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

static inline void process_link(struct bdd_conversation **list, struct bdd_conversation *conversation) {
	if (conversation->n_ev == 1) {
		if (*list != NULL) {
			(*list)->prev = conversation_id(conversation);
		}
		conversation->next = conversation_id(*list);
		conversation->prev = -1;
		(*list) = conversation;
	}
	return;
}
static inline void process_unlink(struct bdd_conversation **list, struct bdd_conversation *conversation) {
	struct bdd_conversation *next = conversation_next(conversation);
	struct bdd_conversation *prev = conversation_prev(conversation);
	if (next != NULL) {
		next->prev = conversation_id(prev);
	}
	if (prev != NULL) {
		prev->next = conversation_id(next);
	} else {
		(*list) = next;
	}
	return;
}

void *bdd_serve(struct bdd_worker_data *worker_data) {
	pthread_sigmask(SIG_BLOCK, &(bdd_gv.sigmask), NULL);
	unsigned short int next_worker_id = 0;
	struct bdd_conversation *process_list = NULL;
	struct bdd_conversation *remove_list = NULL;
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
			assert(event->events == EPOLLIN);
			bdd_accept(worker_data);
			continue;
		}
		struct bdd_conversation *conversation = io_conversation(io);
		if (conversation->remove) {
			continue;
		}
		if (conversation->tl) {
			bdd_tl_unlink(
				timeout_list,
				conversation
			);
		}
		switch (conversation->state) {
			case (bdd_conversation_accept): {
				worker_data->ssl_cb_ctx.conversation = conversation;
				worker_data->ssl_cb_ctx.protocol_name =
					(void *)(worker_data->ssl_cb_ctx.cstr_protocol_name = NULL);
				if (bdd_accept_continue(&(worker_data->ssl_cb_ctx)) == bdd_cont_conversation_discard) {
					if (conversation->n_ev >= 1) {
						process_unlink(&(process_list), conversation);
					}
					conversation->remove = true;
					conversation->next = conversation_id(remove_list);
					remove_list = conversation;
				}
				break;
			}
			case (bdd_conversation_established): {
				struct bdd_ev *ev = bdd_ev(conversation, conversation->n_ev++);
				ev->io_id = bdd_io_id_of(io);
				ev->events = (
					((event->events & EPOLLIN) ? bdd_ev_in : 0) |
					((event->events & EPOLLOUT) ? bdd_ev_out : 0) |
					((event->events & EPOLLERR) ? bdd_ev_err : 0)
				);
				process_link(&(process_list), conversation);
				break;
			}
			default: {
				abort();
			}
		}
	}

	if (bdd_gv.epoll_timeout >= 0) {
		bdd_tl_process(timeout_list);
	}

	while (remove_list != NULL) {
		struct bdd_conversation *conversation = remove_list;
		remove_list = conversation_next(conversation);
		bdd_conversation_discard(conversation);
	}
	while (process_list != NULL) {
		struct bdd_conversation *conversation = process_list;
		process_list = conversation_next(conversation);

		size_t non_removed_idx = 0;
		for (size_t idx = 0; idx < conversation->n_ev;) {
			struct bdd_ev *ev = bdd_ev(conversation, idx);

			struct bdd_io *io = bdd_io(conversation, ev->io_id);

			if (io->state == bdd_io_connecting) {
				switch (bdd_connect_continue(io)) {
					case (bdd_cont_established): {
						if (ev->events & bdd_ev_err) {
							ev->events &= ~bdd_ev_out;
						}
						if (!bdd_io_state(io, bdd_io_est)) {
							goto conversation_discard;
						}
						goto remove_event;
					}
					case (bdd_cont_discard): {
						ev->events = bdd_ev_removed_err;
						if (!bdd_io_discard(io)) {
							goto conversation_discard;
						}
						break;
					}
					case (bdd_cont_inprogress): {
						goto remove_event;
					}
					default: {
						abort();
					}
				}
			} else if (ev->events & bdd_ev_err) {
				ev->events &= ~bdd_ev_out;
				if (bdd_io_hup(io, false)) {
					ev->events = bdd_ev_removed_err;
					if (!bdd_io_discard(io)) {
						goto conversation_discard;
					}
				} else if (io->state > bdd_io_est) {
					if (!bdd_io_state(io, bdd_io_est)) {
						goto conversation_discard;
					}
					goto remove_event;
				}
			} else if (ev->events & bdd_ev_out) {
				if (io->state == bdd_io_out) {
					assert(!io->wrhup);
					if (!bdd_io_state(io, bdd_io_est)) {
						goto conversation_discard;
					}
				} else if (io->state == bdd_io_ssl_shutting) {
					if (bdd_ssl_shutdown_continue(io) == bdd_shutdown_complete) {
						if (bdd_io_hup(io, false)) {
							ev->events = bdd_ev_removed_hup;
							if (!bdd_io_discard(io)) {
								goto conversation_discard;
							}
						} else {
							if (!bdd_io_state(io, bdd_io_est)) {
								goto conversation_discard;
							}
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
			if (conversation->n_blocking > 0) {
				assert(!(ev->events & bdd_ev_in));
			}
			#endif
			if (!ev->events) {
				remove_event:;
				memmove(ev, &(ev[1]), (--conversation->n_ev - idx) * sizeof(struct bdd_ev));
			} else {
				if (ev->events & bdd_ev_removed) {
					if (non_removed_idx != idx) {
						struct bdd_ev this_ev = *ev;
						struct bdd_ev *non_removed_ev = bdd_ev(conversation, non_removed_idx);
						*ev = *non_removed_ev;
						*non_removed_ev = this_ev;
					}
					non_removed_idx += 1;
				}
				idx += 1;
			}
		}

		if (conversation->n_ev != 0) {
			conversation->sosi.service->handle_events(conversation);
		}

		if (conversation->n_in_epoll_with_events == 0 || conversation->remove) {
			conversation_discard:;
			bdd_conversation_discard(conversation);
		} else {
			conversation->n_ev = 0;
		}
	}

	goto epoll;
}
