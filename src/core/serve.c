#include "internal.h"

#include <errno.h>
#include <signal.h>
#include <sys/epoll.h>
#include <unistd.h>

void *bdd_serve(struct bdd_instance *instance) {
	pthread_sigmask(SIG_BLOCK, &(instance->sigmask), NULL);
	unsigned short int next_worker_id = 0;
	struct bdd_workers *workers = &(instance->workers);
bdd_serve__find_connections:;

	BDD_DEBUG_LOG("linked_connections.head is %p\n", instance->linked_connections.head);
	BDD_DEBUG_LOG("polling\n");

	int n_events;
	do {
		n_events = epoll_wait(instance->epoll_fd, instance->epoll_oevents, instance->n_epoll_oevents, -1);
	} while (n_events < 0 && errno == EINTR);
	if (unlikely(n_events < 0)) {
		fprintf(stderr,
			"bidirectiond epoll error: %i - try increasing your "
			"rlimits for open files\n",
			errno);
		bdd_stop(instance);
		bdd_thread_exit(instance);
	}

	pthread_mutex_lock(&(instance->linked_connections.mutex));
	{
		char g[8];
		int r = read(instance->serve_eventfd, &(g), 8);
		assert(r == 8 || r < 0);
	}
	for (struct bdd_connections **curr = &(instance->linked_connections.head), *connections; (connections = (*curr)) != NULL;) {
		struct bdd_connections **next = &(connections->next);
		connections->working = false;
		bool broken = true;
		if (!connections->broken) {
			for (bdd_io_id idx = 0; idx < bdd_connections_n_max_io(connections); ++idx) {
				int fd = connections->io[idx].fd;
				if (fd < 0) {
					continue;
				}
				struct epoll_event event = {
					.events = EPOLLIN,
					.data = {
						.ptr = connections,
					},
				};
				if (epoll_ctl(instance->epoll_fd, EPOLL_CTL_ADD, fd, &(event)) != 0) {
					for (bdd_io_id idx2 = 0; idx2 < idx; ++idx2) {
						fd = connections->io[idx2].fd;
						if (fd >= 0) {
							int r = epoll_ctl(instance->epoll_fd, EPOLL_CTL_DEL, fd, NULL);
							assert(r == 0);
						}
					}
					broken = true;
					break;
				}
				broken = false;
			}
		}
		if (broken) {
			bdd_connections_deinit(connections);
			bdd_connections_release(instance, curr);
		} else {
			(*curr) = NULL;
		}
		curr = next;
	}
	pthread_mutex_unlock(&(instance->linked_connections.mutex));

	if (unlikely(atomic_load(&(instance->exiting)))) {
		bdd_thread_exit(instance);
	}

	for (int idx = 0; idx < n_events; ++idx) {
		struct epoll_event *event = &(instance->epoll_oevents[idx]);
		struct bdd_connections *connections = event->data.ptr;

		if (connections == NULL) {
			continue;
		}
		if (pthread_mutex_trylock(&(connections->working_mutex)) != 0) {
			continue;
		}
		bool already_working = connections->working;
		connections->working = true;
		pthread_mutex_unlock(&(connections->working_mutex));
		if (already_working) {
			continue;
		}

		bool broken = false;
		for (bdd_io_id io_id = 0; io_id < bdd_connections_n_max_io(connections); ++io_id) {
			if (connections->io[io_id].fd < 0) {
				continue;
			}
			if (!broken) {
				short revents = bdd_poll(connections, io_id);
				if ((revents & (POLLERR | POLLHUP | POLLRDHUP)) && !(revents & POLLIN)) {
					broken = true;
				}
				assert(!(revents & POLLNVAL));
			}
			int r = epoll_ctl(instance->epoll_fd, EPOLL_CTL_DEL, connections->io[io_id].fd, NULL);
			assert(r == 0);
		}

		if (broken) {
			BDD_DEBUG_LOG("found broken connections struct\n");
			bdd_connections_deinit(connections);
			bdd_connections_release(instance, &(connections));
			continue;
		}

		BDD_DEBUG_LOG("found working connections struct\n");

		struct bdd_worker *worker;
		if (workers->available_stack.ids == NULL) {
			worker = &(workers->info[next_worker_id]);
			next_worker_id = (next_worker_id + 1) % workers->n_workers;
		} else {
			pthread_mutex_lock(&(workers->available_stack.mutex));
			if (workers->available_stack.idx == workers->n_workers) {
				BDD_DEBUG_LOG("no available worker threads; waiting...\n");
				do {
					pthread_cond_wait(&(workers->available_stack.cond), &(workers->available_stack.mutex));
				} while (workers->available_stack.idx == workers->n_workers);
			}
			worker = &(workers->info[workers->available_stack.ids[(workers->available_stack.idx)++]]);
			pthread_mutex_unlock(&(workers->available_stack.mutex));
		}

		BDD_DEBUG_LOG("worker thread %i chosen!\n", (int)worker->id);

		pthread_mutex_lock(&(worker->work_mutex));
		if (worker->connections == NULL) {
			worker->connections_appender = &(worker->connections);
		}
		assert(connections->next == NULL);
		(*(worker->connections_appender)) = connections;
		worker->connections_appender = &(connections->next);
		pthread_cond_signal(&(worker->work_cond));
		pthread_mutex_unlock(&(worker->work_mutex));
	}

	goto bdd_serve__find_connections;
}
