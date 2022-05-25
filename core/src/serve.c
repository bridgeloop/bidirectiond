#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <poll.h>
#include <sys/epoll.h>
#include <unistd.h>
#include <pthread.h>
#include <stdatomic.h>
#include <sys/time.h>
#include <stdbool.h>

#include "headers/instance.h"
#include "headers/workers.h"
#include "headers/debug_log.h"
#include "headers/conversations.h"
#include "headers/unlikely.h"
#include "headers/bdd_event.h"
#include "headers/bdd_io.h"
#include "headers/bdd_service.h"
#include "headers/signal.h"

time_t bdd_time(void) {
	time_t ms = 0;
	struct timeval x;
	gettimeofday(&(x), NULL);
	ms += x.tv_sec * 1000;
	ms += x.tv_usec / 1000;
	return ms;
}

static void bdd_conversation_work(struct bdd_instance *instance, struct bdd_conversation **conversation_ref, unsigned short int *next_worker_id) {
	struct bdd_conversation *conversation = *conversation_ref;
	*conversation_ref = NULL;
	struct bdd_worker *worker;
	if (instance->available_workers.ids == NULL) {
		worker = &(instance->workers[*next_worker_id]);
		*next_worker_id = (*next_worker_id + 1) % instance->n_workers;
	} else {
		pthread_mutex_lock(&(instance->available_workers.mutex));
		if (instance->available_workers.idx == instance->n_workers) {
			BDD_DEBUG_LOG("no available worker threads; waiting...\n");
			do {
				pthread_cond_wait(
					&(instance->available_workers.cond),
					&(instance->available_workers.mutex)
				);
			} while (instance->available_workers.idx == instance->n_workers);
		}
		worker = &(instance->workers[instance->available_workers.ids[(instance->available_workers.idx)++]]);
		pthread_mutex_unlock(&(instance->available_workers.mutex));
	}

	BDD_DEBUG_LOG("worker thread %i chosen!\n", (int)worker->id);

	pthread_mutex_lock(&(worker->work_mutex));
	if (worker->conversations == NULL) {
		worker->conversations_appender = &(worker->conversations);
	}
	(*(worker->conversations_appender)) = conversation;
	worker->conversations_appender = &(conversation->next);
	pthread_cond_signal(&(worker->work_cond));
	pthread_mutex_unlock(&(worker->work_mutex));
	return;
}

void *bdd_serve(struct bdd_instance *instance) {
	pthread_sigmask(SIG_BLOCK, &(instance->sigmask), NULL);
	unsigned short int next_worker_id = 0;
	struct bdd_conversation *valid_conversations = NULL;
	struct bdd_conversation *valid_conversations_tail = NULL;

	int epoll_timeout = instance->epoll_timeout;

	struct bdd_conversation **conversations_to_epoll = &(instance->conversations_to_epoll.head);

	epoll:;

	struct bdd_conversation *conversations_to_discard = NULL;

	BDD_DEBUG_LOG("polling\n");

	int n_events;
	do {
		n_events = epoll_wait(instance->epoll_fd, instance->epoll_oevents, instance->n_epoll_oevents, epoll_timeout);
	} while (n_events < 0 && errno == EINTR);
	if (unlikely(n_events < 0)) {
		fprintf(stderr, "bidirectiond epoll error: %i - try increasing your rlimits for open files\n", errno);
		bdd_stop(instance);
		bdd_thread_exit(instance);
	}

	pthread_mutex_lock(&(instance->conversations_to_epoll.mutex));
	{
		char g[8];
		int r = read(instance->serve_eventfd, &(g), 8);
		assert(r == 8 || r < 0);
	}
	while ((*conversations_to_epoll) != NULL) {
		struct bdd_conversation *conversation = *conversations_to_epoll;
		(*conversations_to_epoll) = conversation->next;

		conversation->skip = false;

		bool any_in_epoll = false;

		bool any_connecting = conversation->n_connecting > 0;
		bool any_broken = conversation->core_caused_broken_io;
		conversation->core_caused_broken_io = false;

		bdd_io_id n_io = bdd_conversation_n_max_io(conversation);
		for (bdd_io_id idx = 0; idx < n_io; ++idx) {
			struct bdd_io *io = &(conversation->io_array[idx]);

			io->in_epoll = 0;
			if (!bdd_io_internal_has_epoll_state(conversation, io)) {
				continue;
			}

			int fd = bdd_io_internal_fd(io);

			uint32_t events = 0;

			if (any_connecting) {
				if (io->state == BDD_IO_STATE_SSL_CONNECTING && SSL_want_read(io->io.ssl)) {
					events |= EPOLLIN;
				}
				if (io->state == BDD_IO_STATE_CONNECTING || io->state == BDD_IO_STATE_SSL_CONNECTING) {
					events |= EPOLLOUT;
				}
			} else if (any_broken) {
				unsigned char *revents_list = (void *)&(conversation->io_array[
					n_io
				]);
				if (io->state == BDD_IO_STATE_ESTABLISHED_BROKEN) {
					io->no_epoll = 1;
					revents_list[idx] = BDDEV_ERR;
					struct pollfd pollfd = {
						.fd = fd,
						.events = POLLIN,
					};
					poll(&(pollfd), 1, 0);
					if (pollfd.revents & POLLIN) {
						revents_list[idx] |= BDDEV_IN;
					}
				} else if (io->state == BDD_IO_STATE_BROKEN) {
					io->no_epoll = 1;
					revents_list[idx] = BDDEV_ERR;
				} else {
					revents_list[idx] = 0;
				}
				continue;
			} else {
				if (io->listen_read && !io->eof) {
					events |= EPOLLIN;
				}
				if (io->listen_write && !io->shutdown_called) {
					events |= EPOLLOUT;
				}
			}
			if (io->ssl && io->shutdown_called && !(SSL_get_shutdown(io->io.ssl) & SSL_SENT_SHUTDOWN)) {
				events |= EPOLLOUT;
			}

			struct epoll_event event = {
				.events = events,
				.data = {
					.ptr = conversation,
				},
			};
			if (epoll_ctl(instance->epoll_fd, EPOLL_CTL_ADD, fd, &(event)) != 0) {
				for (bdd_io_id idx2 = 0; idx2 < idx; ++idx2) {
					io = &(conversation->io_array[idx2]);
					if (!io->in_epoll) {
						continue;
					}
					fd = bdd_io_internal_fd(io);

					int r = epoll_ctl(instance->epoll_fd, EPOLL_CTL_DEL, fd, NULL);
					assert(r == 0);
				}
				goto discard_conversation;
			}

			any_in_epoll = true;
			io->in_epoll = 1;
		}

		if (!any_connecting && any_broken) {
			bdd_conversation_work(instance, &(conversation), &(next_worker_id));
			continue;
		}

		if (!any_in_epoll) {
			goto discard_conversation;
		}

		conversation->next = NULL;
		conversation->accessed_at = bdd_time();
		if (valid_conversations == NULL) {
			assert(valid_conversations_tail == NULL);
			conversation->prev = NULL;
			valid_conversations_tail = valid_conversations = conversation;
		} else {
			assert(valid_conversations_tail != NULL);
			(conversation->prev = valid_conversations_tail)->next = conversation;
			valid_conversations_tail = conversation;
		}

		continue;

		discard_conversation:;
		bdd_conversation_deinit(conversation);
		bdd_conversation_release(instance, &(conversation));
	}
	pthread_mutex_unlock(&(instance->conversations_to_epoll.mutex));

	if (unlikely(atomic_load(&(instance->exiting)))) {
		bdd_thread_exit(instance);
	}

	for (int idx = 0; idx < n_events; ++idx) {
		struct epoll_event *event = &(instance->epoll_oevents[idx]);
		struct bdd_conversation *conversation = event->data.ptr;

		if (conversation == NULL) { // eventfd
			continue;
		}
		bool skip = conversation->skip;
		conversation->skip = true;
		if (skip) {
			continue;
		}

		bool any_connecting = conversation->n_connecting > 0;

		struct bdd_conversation *n;
		if ((n = conversation->prev) != NULL) {
			n->next = conversation->next;
		}
		if ((n = conversation->next) != NULL) {
			n->prev = conversation->prev;
		}
		if (valid_conversations_tail == conversation) {
			if ((valid_conversations_tail = conversation->prev) == NULL) {
				valid_conversations = NULL;
			}
		} else if (valid_conversations == conversation) {
			if ((valid_conversations = conversation->next) == NULL) {
				valid_conversations_tail = NULL;
			}
		}
		conversation->next = NULL;

		assert(conversation->io_array != NULL);
		bdd_io_id n_io = bdd_conversation_n_max_io(conversation);
		struct bdd_io *io_array = conversation->io_array;
		unsigned char *revents_list = (void *)&(io_array[n_io]);
		struct pollfd pollfd = {
			.events = POLLIN | POLLOUT | POLLRDHUP,
		};

		bool any_with_events = false;
		for (bdd_io_id io_id = 0; io_id < n_io; ++io_id) {
			struct bdd_io *io = &(io_array[io_id]);
			revents_list[io_id] = 0;

			if (!io->in_epoll) {
				continue;
			}

			int r = epoll_ctl(
				instance->epoll_fd,
				EPOLL_CTL_DEL,
				(pollfd.fd = bdd_io_internal_fd(io)),
				NULL
			);
			assert(r == 0);

			r = poll(&(pollfd), 1, 0);
			if (r < 0) {
				conversation->next = conversations_to_discard;
				conversations_to_discard = conversation;
				goto events_iter;
			}

			short int revents = pollfd.revents;

			if (io->ssl && io->shutdown_called && !(SSL_get_shutdown(io->io.ssl) & SSL_SENT_SHUTDOWN) && (revents & POLLOUT)) {
				switch (bdd_io_internal_shutdown_continue(io)) {
					case (bdd_io_shutdown_err): {
						bdd_io_internal_break_established(conversation, io, true);
						break;
					}
					case (bdd_io_shutdown_success): {
						if (!io->ssl) {
							break;
						}
						if (SSL_get_shutdown(io->io.ssl) == (SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN)) {
							io->no_epoll = 1;
						}
						break;
					}
				}
			}

			if (any_connecting) {
				if (
					(
						(io->state == BDD_IO_STATE_SSL_CONNECTING && SSL_want_read(io->io.ssl)) &&
						(revents & POLLIN)
					) ||
					(
						(
							io->state == BDD_IO_STATE_CONNECTING ||
							(io->state == BDD_IO_STATE_SSL_CONNECTING && SSL_want_write(io->io.ssl))
						) &&
						(revents & POLLOUT)
					)
				) {
					if ((pollfd.revents & POLLERR) || bdd_io_internal_connect_continue(conversation, io) == bdd_io_connect_err) {
						bdd_io_internal_break(conversation, io, true);
					}
				}
				// to-do: does openssl return an error here for us?
				if (io->state == BDD_IO_STATE_SSL_CONNECTING && (revents & (POLLRDHUP | POLLHUP))) {
					bdd_io_internal_break(conversation, io, true);
				}
			}

			if (any_connecting) {
				continue;
			}

			unsigned char bdd_revents = 0;

			if ((revents & POLLIN) && !io->eof) {
				bdd_revents |= BDDEV_IN;
			}

			if (revents & POLLERR) {
				bdd_revents |= BDDEV_ERR;
				io->no_epoll = 1;
			} else if (revents & POLLHUP) {
				io->no_epoll = 1;
			}

			if (!io->shutdown_called && (revents & POLLOUT)) {
				bdd_revents |= BDDEV_OUT;
			}

			if (r == 0 || bdd_revents == 0) {
				continue;
			}

			revents_list[io_id] = bdd_revents;
			any_with_events = true;
		}

		if (any_connecting || !any_with_events) {
			bdd_conversation_link(instance, &(conversation));
			continue;
		}

		BDD_DEBUG_LOG("found working conversation struct\n");

		bdd_conversation_work(instance, &(conversation), &(next_worker_id));
		events_iter:;
	}

	if (epoll_timeout >= 0) {
		for (;;) {
			struct bdd_conversation *conversation = valid_conversations;
			if (conversation == NULL) {
				valid_conversations_tail = NULL;
				break;
			}
			if (bdd_time() - conversation->accessed_at < epoll_timeout) {
				break;
			}
			valid_conversations = conversation->next;
			if (valid_conversations != NULL) {
				valid_conversations->prev = NULL;
			}
			bdd_conversation_deinit(conversation);
			bdd_conversation_release(instance, &(conversation));
		}
	}

	while (conversations_to_discard != NULL) {
		struct bdd_conversation *conversation = conversations_to_discard;
		conversations_to_discard = conversation->next;
		bdd_conversation_deinit(conversation);
		bdd_conversation_release(instance, &(conversation));
	}

	goto epoll;
}
