#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <sys/epoll.h>
#include <unistd.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>

#include "headers/instance.h"
#include "headers/accept.h"
#include "headers/timeout_list.h"
#include "headers/debug_log.h"
#include "headers/conversations.h"
#include "headers/unlikely.h"
#include "headers/bdd_event.h"
#include "headers/bdd_io.h"
#include "headers/bdd_service.h"
#include "headers/bdd_stop.h"

enum handle_io_status {
	handle_io_discard,
	handle_io_hup,
	handle_io_lt,
};
static enum handle_io_status handle_io(struct bdd_io *io, uint32_t revents) {
	struct bdd_conversation *conversation = io->conversation;
	unsigned char bdd_revents = 0;

	if (revents & EPOLLERR) {
		io->state = BDD_IO_ERR;
	} else if (io->state == BDD_IO_SSL_SHUTTING) {
		if (bdd_ssl_shutdown_continue(io) == bdd_cont_discard) {
			io->state = BDD_IO_ERR;
		}
	}
	if ((revents & EPOLLIN) && !io->rdhup) {
		bdd_revents |= BDDEV_IN;
	}
	if (revents & EPOLLOUT) {
		if (io->state == bdd_io_est) {
			bdd_revents |= bdd_ev_out;
			bdd_io_epoll_flags(io, EPOLLOUT, 0);
		} else if (io->state == BDD_IO_SSL_SHUTTING) {
			switch (bdd_ssl_shutdown_continue(io)) {
				case (bdd_cont_established): {
					bdd_io_epoll_flags(io, EPOLLOUT, 0);
					break;
				}
				case (bdd_cont_discard): {
					bdd_io_epoll_remove(io);
					break;
				}
			}
		} else {
			abort();
		}
	}
	if (io->state == BDD_IO_ERR) {
		bdd_revents |= BDDEV_NOOUT;
	}

	if (bdd_revents & ~BDDEV_NOOUT) {
		conversation->sosi.service->handle_events(conversation, bdd_io_id(conversation, io), bdd_revents);
	}

	assert(conversation->client.state >= bdd_io_est);

	if (conversation->client.state >= bdd_io_err) {
		// discard conversation
	}

	if (
		((
			conversation->client.rdhup &&
			!(conversation->client.epoll_flags & EPOLLOUT)
		) || !conversation->client.in_epoll) &&
		conversation->n_servers_in_epoll == 0
	) {
		abort();
	}
}

static void discard_link(struct bdd_conversation **list, struct bdd_conversation *conversation) {
	conversation->next = *list;
	*list = conversation;
	return;
}

void *bdd_serve(struct bdd_worker_data *worker_data) {
	pthread_sigmask(SIG_BLOCK, &(bdd_gv.sigmask), NULL);
	unsigned short int next_worker_id = 0;
	struct bdd_conversation *discard_list = NULL;
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
		if (conversation->in_discard_list) {
			continue;
		}
		bdd_tl_unlink(
			timeout_list,
			conversation
		);
		enum bdd_cont (*function)(struct bdd_conversation *, int) = &(bdd_connect_continue);
		switch (conversation->state) {
			case (bdd_conversation_accept): {
				function = &(bdd_accept_continue);
			}
			case (bdd_conversation_connect): {
				switch (function(conversation, epoll_fd)) {
					case (bdd_cont_discard): {
						bdd_conversation_discard(conversation, epoll_fd);
					}
					case (bdd_cont_inprogress): {
						break;
					}
					case (bdd_cont_established): {
						goto established;
					}
				}
				break;
			}
			case (bdd_conversation_established): {
				established:;
				switch (handle_io(io, event->events)) {
					case (handle_io_discard): {
						conversation->in_discard_list = 1;
						discard_link(
							&(discard_list),
							conversation
						);
						break;
					}
					case (handle_io_hup): {
						bdd_io_discard(io, epoll_fd);
						if (bdd_io_opposite(conversation, io)->discarded) {
							bdd_conversation_discard(conversation, epoll_fd);
						}
						break;
					}
					case (handle_io_lt): {
						bdd_tl_link(
							timeout_list,
							conversation
						);
						break;
					}
				}
			}
		}
	}

	if (bdd_gv.epoll_timeout >= 0) {
		bdd_tl_process(timeout_list, epoll_fd);
	}

	while (discard_list != NULL) {
		struct bdd_conversation *conversation = discard_list;
		discard_list = conversation->next;
		bdd_conversation_discard(conversation, epoll_fd);
	}

	goto epoll;
}
