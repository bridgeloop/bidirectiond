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
#include <stdbool.h>

#include "headers/instance.h"
#include "headers/timeout_list.h"
#include "headers/debug_log.h"
#include "headers/conversations.h"
#include "headers/unlikely.h"
#include "headers/bdd_event.h"
#include "headers/bdd_io.h"
#include "headers/bdd_service.h"
#include "headers/signal.h"

enum handle_io_status {
	handle_io_discard,
	handle_io_hup,
	handle_io_lt,
};
static void handle_io(struct bdd_io *io, uint32_t revents) {
	struct bdd_conversation *conversation = io->conversation;
	unsigned char bdd_revents = 0;

	if (revents & EPOLLERR) {
		io->state = BDD_IO_ERR;
	} else if (io->state == BDD_IO_SSL_SHUTTING) {
		if (bdd_ssl_shutdown_continue(io) == bdd_ssl_shutdown_err) {
			io->state = BDD_IO_ERR;
		}
	}
	if ((revents & EPOLLIN) && !io->rdhup) {
		bdd_revents |= BDDEV_IN;
	}
	if ((revents & EPOLLOUT) && io->state == BDD_IO_RW) {
		bdd_revents |= BDDEV_OUT;
	}
	if (io->state == BDD_IO_ERR) {
		bdd_revents |= BDDEV_NOOUT;
	}

	if (bdd_revents & ~BDDEV_NOOUT) {
		conversation->sosi.service->handle_events(conversation, bdd_io_id(conversation, io), bdd_revents);
	}

	if (io->state == BDD_IO_ERR) {
		return handle_io_discard;
	} else if (io->rdhup && io->wrhup) {
		return handle_io_hup;
	} else {
		return handle_io_lt;
	}
}

static void discard_link(struct bdd_conversation **list, struct bdd_conversation *conversation) {
	conversation->next = *list;
	*list = conversation;
	return;
}

void *bdd_serve(void) {
	pthread_sigmask(SIG_BLOCK, &(bdd_gv.sigmask), NULL);
	unsigned short int next_worker_id = 0;
	struct bdd_conversation *discard_list = NULL;
	struct bdd_tl *timeout_list = &(thread_data->bdd_tl);
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
	{
		char g[9];
		int r = read(bdd_gv.serve_eventfd, &(g), 9);
		assert(r == 8 || r < 0);
	}
	if (unlikely(atomic_load(&(bdd_gv.exiting)))) {
		bdd_thread_exit();
	}

	for (int idx = 0; idx < n_events; ++idx) {
		struct epoll_event *event = &(bdd_gv.epoll_oevents[idx]);
		struct bdd_io *io = event->data.ptr;
		struct bdd_conversation *conversation = io->conversation;
		pthread_mutex_lock(&(conversation->mutex));
		pthread_mutex_unlock(&(conversation->mutex));
		if (conversation->in_discard_list) {
			continue;
		}
		bdd_tl_unlink(
			&(timeout_list),
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
							&(timeout_list),
							conversation
						);
						break;
					}
				}
			}
		}
	}

	if (bdd_gv.epoll_timeout >= 0) {
		bdd_tl_process(&(timeout_list), epoll_fd);
	}

	while (discard_list != NULL) {
		struct bdd_conversation *conversation = discard_list;
		discard_list = conversation->next;
		bdd_conversation_discard(conversation);
	}

	goto epoll;
}
