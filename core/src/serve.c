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
#include "headers/coac.h"
#include "headers/conversations.h"
#include "headers/unlikely.h"
#include "headers/bdd_event.h"
#include "headers/bdd_io.h"
#include "headers/bdd_service.h"
#include "headers/signal.h"

static struct bdd_coac
	*timeout_list_head = NULL,
	*timeout_list_tail = NULL;

time_t bdd_time(void) {
	time_t ms = 0;
	struct timeval x;
	gettimeofday(&(x), NULL);
	ms += x.tv_sec * 1000;
	ms += x.tv_usec / 1000;
	return ms;
}

static void bdd_coac_tl_link(struct bdd_coac **coac_ref) {
	struct bdd_coac
		**head = &(timeout_list_head),
		**tail = &(timeout_list_tail);
	struct bdd_coac *coac = *coac_ref;
	*coac_ref = NULL;
	coac->next = NULL;
	coac->accessed_at = bdd_time();
	if (*head == NULL) {
		assert(*tail == NULL);
		coac->prev = NULL;
		*tail = *head = coac;
	} else {
		assert(*tail != NULL);
		coac->prev = *tail;
		(*tail)->next = coac;
		*tail = coac;
	}
	return;
}

static void bdd_coac_tl_unlink(struct bdd_coac *coac) {
	struct bdd_coac
		**head = &(timeout_list_head),
		**tail = &(timeout_list_tail);
	struct bdd_coac *n;
	if ((n = coac->prev) != NULL) {
		n->next = coac->next;
	}
	if ((n = coac->next) != NULL) {
		n->prev = coac->prev;
	}
	if (*tail == coac) {
		if ((*tail = coac->prev) == NULL) {
			*head = NULL;
		}
	} else if (*head == coac) {
		if ((*head = coac->next) == NULL) {
			*tail = NULL;
		}
	}
	coac->next = NULL;
	coac->prev = NULL;
	return;
}

static bool bdd_conversation_epoll(struct bdd_coac *coac) {
	struct bdd_conversation *conversation = &(coac->inner.conversation);
	conversation->seen = false;

	bool any_in_epoll = false;
	bool any_connecting = conversation->n_connecting > 0;

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
		} else {
			if (io->listen_read && !io->eof) {
				events |= EPOLLIN;
			}
			if (io->listen_write && !io->shutdown_called) {
				events |= EPOLLOUT;
			}
		}
		if (
			io->state == BDD_IO_STATE_ESTABLISHED &&
			io->ssl &&
			io->shutdown_called &&
			!(SSL_get_shutdown(io->io.ssl) & SSL_SENT_SHUTDOWN)
		) {
			events |= EPOLLOUT;
		}

		struct epoll_event event = {
			.events = events,
			.data = {
				.ptr = coac,
			},
		};
		if (epoll_ctl(bdd_gv.epoll_fd, EPOLL_CTL_ADD, fd, &(event)) != 0) {
			for (bdd_io_id idx2 = 0; idx2 < idx; ++idx2) {
				io = &(conversation->io_array[idx2]);
				if (!io->in_epoll) {
					continue;
				}
				fd = bdd_io_internal_fd(io);

				int r = epoll_ctl(bdd_gv.epoll_fd, EPOLL_CTL_DEL, fd, NULL);
				assert(r == 0);
			}
			return false;
		}

		any_in_epoll = true;
		io->in_epoll = 1;
	}

	return any_in_epoll;
}

enum bdd_handle_conversation_status {
	bdd_handle_conversation_discard,
	bdd_handle_conversation_link,
	bdd_handle_conversation_work,
};

static enum bdd_handle_conversation_status bdd_handle_conversation(struct bdd_conversation *conversation) {
	assert(conversation->io_array != NULL);
	bdd_io_id n_io = bdd_conversation_n_max_io(conversation);
	struct bdd_io *io_array = conversation->io_array;
	unsigned char *revents_list = (void *)&(io_array[n_io]);
	struct pollfd pollfd = {
		.events = POLLIN | POLLOUT | POLLRDHUP,
	};

	bool any_with_events = false;
	bool any_connecting = conversation->n_connecting > 0;
	for (bdd_io_id io_id = 0; io_id < n_io; ++io_id) {
		struct bdd_io *io = &(io_array[io_id]);
		revents_list[io_id] = 0;

		if (!io->in_epoll) {
			continue;
		}

		int r = epoll_ctl(
			bdd_gv.epoll_fd,
			EPOLL_CTL_DEL,
			(pollfd.fd = bdd_io_internal_fd(io)),
			NULL
		);
		assert(r == 0);

		io->in_epoll = 0;

		r = poll(&(pollfd), 1, 0);
		if (r < 0) {
			return bdd_handle_conversation_discard;
		}

		short int revents = pollfd.revents;

		if (
			io->state == BDD_IO_STATE_ESTABLISHED &&
			io->ssl &&
			io->shutdown_called &&
			!(SSL_get_shutdown(io->io.ssl) & SSL_SENT_SHUTDOWN) &&
			(revents & POLLOUT)
		) {
			if (bdd_io_internal_shutdown_continue(io) == bdd_io_shutdown_err) {
				bdd_io_internal_break_established(conversation, io);
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
					bdd_io_internal_break(conversation, io);
				}
			}
			// to-do: does openssl return an error here for us?
			if (io->state == BDD_IO_STATE_SSL_CONNECTING && (revents & (POLLRDHUP | POLLHUP))) {
				bdd_io_internal_break(conversation, io);
			}
			continue;
		}

		unsigned char bdd_revents = 0;

		if (revents & POLLERR) {
			if (io->state == BDD_IO_STATE_ESTABLISHED) {
				bdd_io_internal_break_established(conversation, io);
			} else if (io->state != BDD_IO_STATE_BROKEN) {
				bdd_io_internal_break(conversation, io);
			}
		} else if (revents & POLLHUP) {
			io->tcp_hup = 1;
		}

		if (
			(io->state == BDD_IO_STATE_ESTABLISHED || io->state == BDD_IO_STATE_ESTABLISHED_BROKEN) &&
			(revents & POLLIN) &&
			!io->eof
		) {
			bdd_revents |= BDDEV_IN;
		}

		if (io->state == BDD_IO_STATE_ESTABLISHED && !io->shutdown_called && (revents & POLLOUT)) {
			bdd_revents |= BDDEV_OUT;
		}

		if (io->state == BDD_IO_STATE_BROKEN || io->state == BDD_IO_STATE_ESTABLISHED_BROKEN) {
			bdd_revents |= BDDEV_ERR;
		}

		if (bdd_revents == 0) {
			continue;
		}

		revents_list[io_id] = bdd_revents;
		any_with_events = true;
	}

	if (any_connecting || !any_with_events) {
		return bdd_handle_conversation_link;
	}
	return bdd_handle_conversation_work;
}

void *bdd_serve(void) {
	pthread_sigmask(SIG_BLOCK, &(bdd_gv.sigmask), NULL);
	unsigned short int next_worker_id = 0;
	struct bdd_coac
		*conversations_to_discard = NULL,
		*conversations_to_epoll2 = NULL;

	epoll:;

	BDD_DEBUG_LOG("polling\n");

	int n_events;
	do {
		n_events = epoll_wait(bdd_gv.epoll_fd, bdd_gv.epoll_oevents, bdd_gv.n_epoll_oevents, bdd_gv.epoll_timeout);
	} while (n_events < 0 && errno == EINTR);
	if (unlikely(n_events < 0)) {
		fprintf(stderr, "bidirectiond epoll error: %i - try increasing your rlimits for open files\n", errno);
		bdd_stop();
		bdd_thread_exit();
	}

	pthread_mutex_lock(&(bdd_gv.conversations_to_epoll.mutex));
	{
		char g[9];
		int r = read(bdd_gv.serve_eventfd, &(g), 9);
		assert(r == 8 || r < 0);
	}
	if (unlikely(atomic_load(&(bdd_gv.exiting)))) {
		bdd_thread_exit();
	}
	while (bdd_gv.conversations_to_epoll.head != NULL) {
		struct bdd_coac *coac = bdd_gv.conversations_to_epoll.head;
		bdd_gv.conversations_to_epoll.head = coac->next;
		if (bdd_conversation_epoll(coac)) {
			bdd_coac_tl_link(&(coac));
		} else {
			bdd_conversation_deinit(&(coac->inner.conversation));
			bdd_coac_release(&(coac));
		}
	}
	pthread_mutex_unlock(&(bdd_gv.conversations_to_epoll.mutex));

	for (int idx = 0; idx < n_events; ++idx) {
		struct epoll_event *event = &(bdd_gv.epoll_oevents[idx]);
		struct bdd_coac *coac = event->data.ptr;

		if (coac == NULL) { // eventfd
			continue;
		}

		switch (coac->inner_type) {
			case (bdd_coac_conversation): {
				struct bdd_conversation *conversation = &(coac->inner.conversation);
				bool *seen = &(conversation->seen);
				if (*seen) {
					break;
				}
				*seen = true;

				bdd_coac_tl_unlink(coac);

				switch (bdd_handle_conversation(conversation)) {
					case (bdd_handle_conversation_link): {
						coac->next = conversations_to_epoll2;
						conversations_to_epoll2 = coac;
						break;
					}
					case (bdd_handle_conversation_discard): {
						coac->next = conversations_to_discard;
						conversations_to_discard = coac;
						break;
					}
					case (bdd_handle_conversation_work): {
						struct bdd_worker *worker;
						if (bdd_gv.available_workers.ids == NULL) {
							worker = &(bdd_gv.workers[next_worker_id]);
							next_worker_id = (next_worker_id + 1) % bdd_gv.n_workers;
						} else {
							pthread_mutex_lock(&(bdd_gv.available_workers.mutex));
							if (bdd_gv.available_workers.idx == bdd_gv.n_workers) {
								BDD_DEBUG_LOG("no available worker threads; waiting...\n");
								do {
									pthread_cond_wait(
										&(bdd_gv.available_workers.cond),
										&(bdd_gv.available_workers.mutex)
									);
								} while (bdd_gv.available_workers.idx == bdd_gv.n_workers);
							}
							worker = &(bdd_gv.workers[bdd_gv.available_workers.ids[(bdd_gv.available_workers.idx)++]]);
							pthread_mutex_unlock(&(bdd_gv.available_workers.mutex));
						}

						BDD_DEBUG_LOG("worker thread %i chosen!\n", (int)worker->id);

						pthread_mutex_lock(&(worker->work_mutex));
						if (worker->conversations == NULL) {
							worker->conversations_appender = &(worker->conversations);
						}
						(*(worker->conversations_appender)) = coac;
						worker->conversations_appender = &(coac->next);
						pthread_cond_signal(&(worker->work_cond));
						pthread_mutex_unlock(&(worker->work_mutex));
						break;
					}
				}

				break;
			}
		}
	}

	if (bdd_gv.epoll_timeout >= 0) {
		for (;;) {
			struct bdd_coac *coac = timeout_list_head;
			if (coac == NULL) {
				timeout_list_tail = NULL;
				break;
			}
			if (bdd_time() - coac->accessed_at < bdd_gv.epoll_timeout) {
				break;
			}
			timeout_list_head = coac->next;
			if (timeout_list_head != NULL) {
				timeout_list_head->prev = NULL;
			}
			bdd_conversation_deinit(&(coac->inner.conversation));
			bdd_coac_release(&(coac));
		}
	}

	while (conversations_to_discard != NULL) {
		struct bdd_coac *coac = conversations_to_discard;
		conversations_to_discard = coac->next;
		bdd_conversation_deinit(&(coac->inner.conversation));
		bdd_coac_release(&(coac));
	}

	while (conversations_to_epoll2 != NULL) {
		struct bdd_coac *coac = conversations_to_epoll2;
		conversations_to_epoll2 = coac->next;
		if (bdd_conversation_epoll(coac)) {
			bdd_coac_tl_link(&(coac));
		} else {
			bdd_conversation_deinit(&(coac->inner.conversation));
			bdd_coac_release(&(coac));
		}
	}

	goto epoll;
}
