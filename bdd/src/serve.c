#include <assert.h>
#include <errno.h>
#include <openssl/ssl.h>
#include <signal.h>
#include <stdio.h>
#include <sys/epoll.h>
#include <unistd.h>
#include <pthread.h>
#include <stdatomic.h>
#include <string.h>
#include <stdbool.h>

#include "headers/instance.h"
#include "headers/accept.h"
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

static void run_service(struct bdd_conversation *conversation, struct epoll_event *rearm) {
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
		BDD_CONVERSATION_AGE_MS(conversation, "s");
		conversation->sosi.service->handle_events(conversation);
		BDD_CONVERSATION_AGE_MS(conversation, "e");
	}

	#ifndef NDEBUG
	for (bdd_io_id idx = 0; idx < BIDIRECTIOND_N_IO; ++idx) {
		if (conversation->io_array[idx].state != bdd_io_unused && conversation->io_array[idx].ssl) {
			assert(!SSL_has_pending(conversation->io_array[idx].io.ssl));
		}
	}
	#endif

	if (conversation->n_in_epoll_with_events == 0 || conversation->remove) {
		conversation_discard:;
		bdd_conversation_discard(conversation);
	} else {
		conversation->n_ev = 0;
		if (epoll_ctl(bdd_gv.epoll_fd, EPOLL_CTL_MOD, conversation->epoll_inst, rearm) != 0) {
			abort();
		}
	}

	return;
}

void *bdd_serve(struct bdd_worker_data *worker_data) {
	struct epoll_event *events = worker_data->events;
	epoll:;

	int n_events;
	do {
		n_events = epoll_wait(bdd_gv.epoll_fd, events, bdd_gv.n_epoll_oevents, -1);
	} while (n_events < 0 && errno == EINTR);
	if (unlikely(n_events < 0)) {
		fprintf(stderr, "bidirectiond epoll error: %i - try increasing your rlimits for open files\n", errno);
		bdd_stop();
		return bdd_thread_exit(worker_data);
	}
	if (unlikely(atomic_load(&(bdd_gv.exiting)))) {
		return bdd_thread_exit(worker_data);
	}

	for (int idx = 0; idx < n_events; ++idx) {
		struct epoll_event *conv_event = &(events[idx]);
		struct bdd_conversation *conversation = conv_event->data.ptr;
		assert(conv_event->events == EPOLLIN);
		// can't be the eventfd because this function would have already returned
		if (conversation == NULL) {
			// serve_fd
			bdd_accept(worker_data->ssl_ctx);
			continue;
		}
		//BDD_CONVERSATION_AGE_MS(conversation, "event loop");

		struct epoll_event rearm = bdd_epoll_conv(conversation);

		if (conversation->state == bdd_conversation_accept) {
			worker_data->ssl_cb_ctx.conversation = conversation;
			worker_data->ssl_cb_ctx.protocol_name =
				(void *)(worker_data->ssl_cb_ctx.cstr_protocol_name = NULL);
			if (bdd_accept_continue(worker_data->ssl_ctx, &(worker_data->ssl_cb_ctx)) == bdd_cont_conversation_discard) {
				bdd_conversation_discard(conversation);
			} else {
				if (epoll_ctl(bdd_gv.epoll_fd, EPOLL_CTL_MOD, conversation->epoll_inst, &(rearm)) != 0) {
					abort();
				}
			}
			continue;
		}

		struct epoll_event conv_events[BIDIRECTIOND_N_IO];
		int n_conv_events = epoll_wait(conversation->epoll_inst, conv_events, BIDIRECTIOND_N_IO, 0);
		assert(n_conv_events != 0);
		// if (has_event_for(timer_fd)) ...;
		assert(conversation->state == bdd_conversation_established);
		for (int conv_idx = 0; conv_idx < n_conv_events; ++conv_idx) {
			struct epoll_event *event = &(conv_events[conv_idx]);
			struct bdd_ev *ev = bdd_ev(conversation, conversation->n_ev++);
			ev->io_id = bdd_io_id_of(event->data.ptr);
			ev->events = (
				((event->events & EPOLLIN) ? bdd_ev_in : 0) |
				((event->events & EPOLLOUT) ? bdd_ev_out : 0) |
				((event->events & EPOLLERR) ? bdd_ev_err : 0)
			);
		}
		run_service(conversation, &(rearm));
	}

	goto epoll;
}
