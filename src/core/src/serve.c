#include <assert.h>
#include <errno.h>
#include <signal.h>
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
#include "headers/bdd_io.h"
#include "headers/bdd_poll.h"
#include "headers/bdd_io_remove.h"
#include "headers/bdd_io_connect.h"
#include "headers/bdd_io_wait.h"
#include "headers/bdd_service.h"
#include "headers/signal.h"
#include "headers/pollrdhup.h"

time_t bdd_time(void) {
	time_t ms = 0;
	struct timeval x;
	gettimeofday(&(x), NULL);
	ms += x.tv_sec * 1000;
	ms += x.tv_usec / 1000;
	return ms;
}

void *bdd_serve(struct bdd_instance *instance) {
	pthread_sigmask(SIG_BLOCK, &(instance->sigmask), NULL);
	unsigned short int next_worker_id = 0;
	struct bdd_conversation *valid_conversations = NULL;
	struct bdd_conversation *valid_conversations_tail = NULL;

	int epoll_timeout = instance->epoll_timeout;

	find_conversations:;

	struct bdd_conversation *conversation_release_list = NULL;

	BDD_DEBUG_LOG("linked_conversations.head is %p\n", instance->linked_conversations.head);
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

	pthread_mutex_lock(&(instance->linked_conversations.mutex));
	{
		char g[8];
		int r = read(instance->serve_eventfd, &(g), 8);
		assert(r == 8 || r < 0);
	}
	for (
		struct bdd_conversation *conversation;
		(conversation = instance->linked_conversations.head) != NULL;
	) {
		struct bdd_conversation *next = conversation->next;
		conversation->skip = 0;

		bool broken = true;

		if (!conversation->release) {
			bool wait = conversation->n_waiting > 0;
			bool found_wait_io = false;
			for (bdd_io_id idx = 0; idx < bdd_conversation_n_max_io(conversation); ++idx) {
				struct bdd_io *io = &(conversation->io[idx]);
				if (!bdd_io_has_epoll_state(io)) {
					io->in_epoll = 0;
					continue;
				}
				int fd;
				if (io->ssl) {
					fd = SSL_get_fd(io->io.ssl);
				} else {
					fd = io->io.fd;
				}

				bool s_ev = false;
				short int ev;
				if (found_wait_io || (wait && bdd_io_wait_state(io) == BDD_IO_WAIT_DONT)) {
					ev = 0; // implicit EPOLLHUP and EPOLLERR
					s_ev = true;
				} else if (wait) {
					assert(!found_wait_io && bdd_io_wait_state(io) != BDD_IO_WAIT_DONT);
					found_wait_io = true;
					if (bdd_io_wait_state(io) == BDD_IO_WAIT_RDHUP) {
						ev = EPOLLRDHUP;
						s_ev = true;
					} else {
						assert(bdd_io_wait_state(io) == BDD_IO_WAIT_ESTABLISHED);
					}
				}
				if (!s_ev) {
					s_ev = true;
					if (
						(io->state == BDD_IO_STATE_CONNECTING && io->substate == BDD_IO_CONNECTING_SUBSTATE_IN_PROGRESS) ||
						(io->state == BDD_IO_STATE_SSL_CONNECTING && io->substate == BDD_IO_SSL_CONNECTING_SUBSTATE_WANTS_WRITE)
					) {
						ev = EPOLLOUT;
					} else {
						assert(
							(io->state == BDD_IO_STATE_SSL_CONNECTING && io->state == BDD_IO_SSL_CONNECTING_SUBSTATE_WANTS_READ) ||
							io->state == BDD_IO_STATE_ESTABLISHED
						);
						ev = EPOLLIN;
					}
				}
				struct epoll_event event = {
					.events = ev,
					.data = {
						.ptr = conversation,
					},
				};
				if (epoll_ctl(instance->epoll_fd, EPOLL_CTL_ADD, fd, &(event)) != 0) {
					for (bdd_io_id idx2 = 0; idx2 < idx; ++idx2) {
						io = &(conversation->io[idx2]);
						if (!bdd_io_has_epoll_state(io)) {
							continue;
						}
						if (io->ssl) {
							fd = SSL_get_fd(io->io.ssl);
						} else {
							fd = io->io.fd;
						}

						int r = epoll_ctl(instance->epoll_fd, EPOLL_CTL_DEL, fd, NULL);
						assert(r == 0);
					}
					broken = true;
					break;
				}
				io->in_epoll = 1;
				broken = false;
			}
		}

		if (broken) {
			bdd_conversation_deinit(conversation);
			bdd_conversation_release(instance, &(conversation));
		} else {
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
		}
		instance->linked_conversations.head = next;
	}
	pthread_mutex_unlock(&(instance->linked_conversations.mutex));

	if (unlikely(atomic_load(&(instance->exiting)))) {
		bdd_thread_exit(instance);
	}

	// to-do: implement io wait
	for (int idx = 0; idx < n_events; ++idx) {
		struct epoll_event *event = &(instance->epoll_oevents[idx]);
		struct bdd_conversation *conversation = event->data.ptr;

		if (conversation == NULL) { // eventfd
			continue;
		}
		if (pthread_mutex_trylock(&(conversation->skip_mutex)) != 0) {
			continue;
		}
		bool skip = conversation->skip;
		conversation->skip = 1;
		pthread_mutex_unlock(&(conversation->skip_mutex));
		if (skip) {
			continue;
		}

		if (conversation->prev != NULL) {
			conversation->prev->next = conversation->next;
		}
		if (conversation->next != NULL) {
			conversation->next->prev = conversation->prev;
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

		process:;
		bool serve = false;
		bool connecting = false;
		for (bdd_io_id io_id = 0; io_id < bdd_conversation_n_max_io(conversation); ++io_id) {
			struct bdd_io *io = &(conversation->io[io_id]);
			if (!bdd_io_has_epoll_state(io)) {
				continue;
			}
			int fd;
			if (io->ssl) {
				fd = SSL_get_fd(io->io.ssl);
			} else {
				fd = io->io.fd;
			}
			int r;
			if (io->in_epoll) {
				r = epoll_ctl(instance->epoll_fd, EPOLL_CTL_DEL, fd, NULL);
				assert(r == 0);
				io->in_epoll = 0;
			}
			if (io->state == BDD_IO_STATE_ESTABLISHED) {
				if (io->wait == BDD_IO_WAIT_ESTABLISHED) {
					bdd_io_wait(conversation, io_id, BDD_IO_WAIT_DONT);
				}
				established:;
				struct bdd_poll_io poll_io = {
					.io_id = io_id,
					.events = POLLIN | POLLRDHUP,
					.revents = 0,
				};
				r = bdd_poll(conversation, &(poll_io), 1, 0);
				assert(!(poll_io.revents & POLLNVAL));
				if (poll_io.revents & POLLRDHUP) {
					if (io->wait == BDD_IO_WAIT_RDHUP) {
						bdd_io_wait(conversation, io_id, BDD_IO_WAIT_DONT);
					}
					#ifndef BIDIRECTIOND_NO_RDHUP_SERVE
					serve = true;
					#endif
				}
				if (poll_io.revents & POLLIN) {
					serve = true;
				} else if (
					r < 0 ||
					(poll_io.revents & (
						POLLERR /* rst sent or received */ |
						POLLHUP /* socket has been shut-down in both directions */
					))
				) {
					remove_io:;
					bdd_io_remove(conversation, io_id);
					if (conversation->service->io_removed != NULL) {
						conversation->service->io_removed(conversation, io_id);
						goto process;
					}
				}
			} else {
				assert(
					(io->state == BDD_IO_STATE_CONNECTING && io->substate == BDD_IO_CONNECTING_SUBSTATE_IN_PROGRESS) ||
					(io->state == BDD_IO_STATE_SSL_CONNECTING)
				);
				struct bdd_poll_io poll_io = {
					.io_id = io_id,
					.events = POLLIN | POLLOUT,
					.revents = 0,
				};
				r = bdd_poll(conversation, &(poll_io), 1, 0);
				assert(!(poll_io.revents & POLLNVAL));
				if (
					r < 0 ||
					(poll_io.revents & (
						POLLERR |
						POLLHUP
					))
				) {
					goto remove_io;
				}
				if (
					(io->state == BDD_IO_STATE_CONNECTING && io->substate == BDD_IO_CONNECTING_SUBSTATE_IN_PROGRESS && (poll_io.revents & POLLOUT)) ||
					(io->state == BDD_IO_STATE_SSL_CONNECTING && io->substate == BDD_IO_SSL_CONNECTING_SUBSTATE_WANTS_READ && (poll_io.revents & POLLIN)) ||
					(io->state == BDD_IO_STATE_SSL_CONNECTING && io->substate == BDD_IO_SSL_CONNECTING_SUBSTATE_WANTS_WRITE && (poll_io.revents & POLLOUT))
				) {
					switch (bdd_io_connect(conversation, io_id, NULL, 0)) {
						case (bdd_io_connect_established): {
							connecting = true;
							if (io->wait == BDD_IO_WAIT_ESTABLISHED) {
								bdd_io_wait(conversation, io_id, BDD_IO_WAIT_DONT);
							}
							if (conversation->service->io_established != NULL) {
								conversation->service->io_established(conversation, io_id);
								goto process;
							}
							goto established;
						}

						case (bdd_io_connect_err): {
							assert(false);
							goto remove_io;
						}

						default: {
							connecting = true;
							break;
						}
					}
				}
			}
		}

		if (conversation->n_waiting > 0 || (!serve && connecting)) {
			bdd_conversation_link(instance, &(conversation));
			continue;
		}
		if (!serve) {
			BDD_DEBUG_LOG("found broken conversation struct\n");
			conversation->next = conversation_release_list;
			conversation_release_list = conversation;
		}

		BDD_DEBUG_LOG("found working conversation struct\n");

		struct bdd_worker *worker;
		if (instance->available_workers.ids == NULL) {
			worker = &(instance->workers[next_worker_id]);
			next_worker_id = (next_worker_id + 1) % instance->n_workers;
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

	while (conversation_release_list != NULL) {
		struct bdd_conversation *next = conversation_release_list->next;
		bdd_conversation_deinit(conversation_release_list);
		bdd_conversation_release(instance, &(conversation_release_list));
		conversation_release_list = next;
	}

	goto find_conversations;
}
