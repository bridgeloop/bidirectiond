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

	struct bdd_to_epoll **to_epoll_head = &(instance->to_epoll.head);

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

	pthread_mutex_lock(&(instance->to_epoll.mutex));
	{
		char g[8];
		int r = read(instance->serve_eventfd, &(g), 8);
		assert(r == 8 || r < 0);
	}
	while ((*to_epoll_head) != NULL) switch ((*to_epoll_head)->struct_type == 0) {
		case (0): {
			struct bdd_conversation *conversation = (void *)(*to_epoll_head);
			(*to_epoll_head) = conversation->next;

			conversation->skip = 0;

			// add the IOs' fds to epoll
			// discard the conversation if no IOs are eligible
			bool any_in_epoll = false;

			for (bdd_io_id idx = 0; idx < bdd_conversation_n_max_io(conversation); ++idx) {
				struct bdd_io *io = &(conversation->io[idx]);
				if (!bdd_io_has_epoll_state(io) || io->no_epoll) {
					io->in_epoll = 0;
					continue;
				}

				int fd = bdd_io_fd(io);

				struct epoll_event event = {
					.events = io->epoll_events,
					.data = {
						.ptr = conversation,
					},
				};
				if (epoll_ctl(instance->epoll_fd, EPOLL_CTL_ADD, fd, &(event)) != 0) {
					for (bdd_io_id idx2 = 0; idx2 < idx; ++idx2) {
						io = &(conversation->io[idx2]);
						if (!io->in_epoll) {
							continue;
						}
						fd = bdd_io_fd(io);

						int r = epoll_ctl(instance->epoll_fd, EPOLL_CTL_DEL, fd, NULL);
						assert(r == 0);
					}
					goto discard_conversation;
				}

				any_in_epoll = true;
				io->in_epoll = 1;
			}

			conversation->next = NULL;
			if (conversation->noatime) {
				conversation->noatime = 0;
			} else {
				conversation->accessed_at = bdd_time();
			}
			if (valid_conversations == NULL) {
				assert(valid_conversations_tail == NULL);
				conversation->prev = NULL;
				valid_conversations_tail = valid_conversations = conversation;
			} else {
				assert(valid_conversations_tail != NULL);
				(conversation->prev = valid_conversations_tail)->next = conversation;
				valid_conversations_tail = conversation;
			}

			break;

			discard_conversation:;
			bdd_conversation_deinit(conversation);
			bdd_conversation_release(instance, &(conversation));

			break;
		}
		default: {
			abort();
		}
	}
	pthread_mutex_unlock(&(instance->to_epoll.mutex));

	if (unlikely(atomic_load(&(instance->exiting)))) {
		bdd_thread_exit(instance);
	}

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

		assert(conversation->io != NULL);
		bdd_io_id n_io = bdd_conversation_n_max_io(conversation);
		struct bdd_io *io = conversation->io;
		short int *revents_list = (void *)&(conversation->io[n_io]);
		struct bdd_poll_io poll_io = {
			.events = POLLIN | POLLOUT | POLLRDHUP,
		};

		#ifndef NDEBUG
		bool any_with_events = false;
		#endif
		for (bdd_io_id idx = 0; idx < n_io; ++idx) {
			bool in_epoll = io[idx].in_epoll;
			io[idx].in_epoll = 0;
			if (!io[idx].in_epoll) {
				no_events:;
				revents_list[idx] = 0;
				continue;
			}
			poll_io.io_id = idx;
			int r = bdd_poll(conversation, &(poll_io), 1, 0);
			if (r < 0) {
				conversation->next = conversations_to_discard;
				conversations_to_discard = conversation;
				goto events_iter;
			}
			if (r == 0) {
				goto no_events;
			}
			short int revents = poll_io.revents;
			revents_list[idx] = revents;
			if (revents & (POLLERR | POLLHUP | POLLRDHUP)) {
				if (revents & POLLHUP) {
					io->hup = 1;
				}
				io->no_epoll = 1;
			}
			#ifndef NDEBUG
			any_with_events = true;
			#endif
		}
		#ifndef NDEBUG
		assert(any_with_events);
		#endif

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
		worker->conversations_appender = (void *)&(conversation->next);
		pthread_cond_signal(&(worker->work_cond));
		pthread_mutex_unlock(&(worker->work_mutex));

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
