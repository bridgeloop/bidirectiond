#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <sys/epoll.h>
#include <unistd.h>
#include <pthread.h>
#include <stdatomic.h>
#include <string.h>
#include <stdbool.h>

#include "headers/instance.h"
#include "headers/accept.h"
#include "headers/timeout_list.h"
#include "headers/debug_log.h"
#include "headers/conversations.h"
#include "headers/unlikely.h"
#include "headers/bdd_event.h"
#include "headers/bdd_io.h"
#include "headers/bidirectiond_n_io.h"
#include "headers/bdd_service.h"
#include "headers/bdd_stop.h"
#include "headers/bdd_event.h"
#include "headers/bdd_shutdown_status.h"

static void process_link(struct bdd_conversation **list, struct bdd_conversation *conversation) {
	if (conversation->n_ev == 1) {
		conversation->next = *list;
		*list = conversation;
	}
	return;
}

void *bdd_serve(struct bdd_worker_data *worker_data) {
	pthread_sigmask(SIG_BLOCK, &(bdd_gv.sigmask), NULL);
	unsigned short int next_worker_id = 0;
	struct bdd_conversation *process_list = NULL;
	struct bdd_tl *timeout_list = &(worker_data->timeout_list);
	int epoll_fd = worker_data->epoll_fd;
	struct epoll_event *events = worker_data->events;
	epoll:;

	BDD_DEBUG_LOG("polling\n");

	int n_events;
	do {
		n_events = epoll_wait(epoll_fd, events, bdd_gv.n_epoll_oevents, bdd_gv.epoll_timeout);
	} while (n_events < 0 && errno == EINTR);
	if (unlikely(n_events < 0)) {
		fprintf(stderr, "bidirectiond epoll error: %i - try increasing your rlimits for open files\n", errno);
		bdd_stop();
		bdd_thread_exit();
	}
	if (unlikely(atomic_load(&(bdd_gv.exiting)))) {
		bdd_thread_exit();
	}

	for (int idx = 0; idx < n_events; ++idx) {
		struct epoll_event *event = &(events[idx]);
		struct bdd_io *io = event->data.ptr;
		if (io == NULL) {
			bdd_accept(worker_data);
			continue;
		}
		struct bdd_conversation *conversation = io->conversation;
		if (!conversation->n_ev) {
			bdd_tl_unlink(
				timeout_list,
				conversation
			);
		}
		switch (conversation->state) {
			case (bdd_conversation_accept): {
				if (bdd_accept_continue(conversation) == bdd_cont_discard) {
					bdd_conversation_discard(conversation);
				}
				break;
			}
			case (bdd_conversation_established): {
				struct bdd_ev *ev = bdd_ev(conversation, conversation->n_ev++);
				ev->io_id = bdd_io_id_of(io);
				ev->events = (
					(event->events & EPOLLIN ? bdd_ev_in : 0) |
					(event->events & EPOLLOUT ? bdd_ev_out : 0) |
					(event->events & EPOLLERR ? 8 : 0)
				);
				#ifndef NDEBUG
				if (event->events & EPOLLERR) {
					assert(event->events & EPOLLIN);
				}
				#endif
				process_link(&(process_list), conversation);
			}
		}
	}

	if (bdd_gv.epoll_timeout >= 0) {
		bdd_tl_process(timeout_list);
	}

	while (process_list != NULL) {
		struct bdd_conversation *conversation = process_list;
		process_list = conversation->next;

		bool any_connecting = conversation->n_connecting > 0;

		for (size_t idx = 0; idx < conversation->n_ev;) {
			struct bdd_ev *ev = bdd_ev(conversation, idx);
			bool wr_err = ev->events & 8;
			ev->events &= ~8;

			struct bdd_io *io = bdd_io(conversation, ev->io_id);

			if (io->state == bdd_io_connecting) {
				switch (bdd_connect_continue(io)) {
					case (bdd_cont_established): {
						bdd_io_state(io, bdd_io_est);
						break;
					}
					case (bdd_cont_discard): {
						ev->events = bdd_ev_removed;
						bdd_io_discard(io);
						break;
					}
				}
			} else if (wr_err) {
				assert(!(ev->events & bdd_ev_out));
				if (bdd_io_hup(io, false)) {
					ev->events = bdd_ev_removed;
					bdd_io_discard(io);
				} else {
					bdd_io_state(io, bdd_io_est);
				}
			} else if (ev->events & bdd_ev_out) {
				if (io->state == bdd_io_est) {
					bdd_io_epoll_mod(io, EPOLLOUT, 0, false);
				} else if (io->state == bdd_io_ssl_shutting) {
					if (bdd_ssl_shutdown_continue(io) == bdd_shutdown_complete) {
						if (bdd_io_hup(io, false)) {
							ev->events = bdd_ev_removed;
							bdd_io_discard(io);
						} else {
							bdd_io_state(io, bdd_io_est);
						}
					}
					ev->events &= ~bdd_ev_out;
				}
			}

			if (io->rdhup) {
				ev->events &= ~bdd_ev_in;
			}
			#ifndef NDEBUG
			if (io->wrhup && (ev->events & bdd_ev_out)) {
				abort();
			}
			#endif
			if (any_connecting) {
				ev->events &= ~(bdd_ev_in | bdd_ev_out);
			}
			if (!ev->events) {
				memmove(ev, &(ev[1]), (--conversation->n_ev - idx) * sizeof(struct bdd_ev));
			} else {
				idx += 1;
			}
		}

		if (conversation->n_ev || conversation->remove) {
			conversation->sosi.service->handle_events(conversation);
		}

		if (conversation->n_in_epoll_with_events == 0) {
			bdd_conversation_discard(conversation);
		}

		conversation->n_ev = 0;
	}

	goto epoll;
}
