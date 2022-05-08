#include "internal.h"

#include <errno.h>
#include <signal.h>
#include <sys/epoll.h>
#include <unistd.h>

void *bdd_serve(struct bdd_instance *instance) {
	pthread_sigmask(SIG_BLOCK, &(instance->sigmask), NULL);
	unsigned short int next_worker_id = 0;
	struct bdd_workers *workers = &(instance->workers);
	struct bdd_connections *connections_list = NULL;
	struct bdd_connections *connections_list_tail = NULL;

bdd_serve__find_connections:;

	struct bdd_connections *connections_release_list = NULL;

	BDD_DEBUG_LOG("linked_connections.head is %p\n", instance->linked_connections.head);
	BDD_DEBUG_LOG("polling\n");

	int n_events;
	do {
		n_events = epoll_wait(instance->epoll_fd, instance->epoll_oevents, instance->n_epoll_oevents, -1 /*instance->epoll_timeout*/);
	} while (n_events < 0 && errno == EINTR);
	if (unlikely(n_events < 0)) {
		fprintf(stderr, "bidirectiond epoll error: %i - try increasing your rlimits for open files\n", errno);
		bdd_stop(instance);
		bdd_thread_exit(instance);
	}

	pthread_mutex_lock(&(instance->linked_connections.mutex));
	{
		char g[8];
		int r = read(instance->serve_eventfd, &(g), 8);
		assert(r == 8 || r < 0);
	}
	for (
		struct bdd_connections *connections;
		(connections = instance->linked_connections.head) != NULL;
	) {
		struct bdd_connections *next = connections->next;
		connections->working = false;
		bool broken = true;
		if (!connections->broken) {
			for (bdd_io_id idx = 0; idx < bdd_connections_n_max_io(connections); ++idx) {
				struct bdd_io *io = &(connections->io[idx]);
				if (io->state != BDD_IO_STATE_CREATED && io->state != BDD_IO_STATE_ESTABLISHED) {
					continue;
				}
				int fd;
				if (io->ssl) {
					fd = SSL_get_fd(io->io.ssl);
				} else {
					fd = io->io.fd;
				}
				short int ev = EPOLLIN;
				if (io->state == BDD_IO_STATE_CREATED && io->connect_state == BDD_IO_CONNECT_STATE_WANTS_CALL_ONCE_WRITABLE) {
					ev = EPOLLOUT;
				}
				struct epoll_event event = {
					.events = ev | EPOLLRDHUP,
					.data = {
						.ptr = connections,
					},
				};
				if (epoll_ctl(instance->epoll_fd, EPOLL_CTL_ADD, fd, &(event)) != 0) {
					for (bdd_io_id idx2 = 0; idx2 < idx; ++idx2) {
						io = &(connections->io[idx2]);
						if (io->ssl) {
							fd = SSL_get_fd(io->io.ssl);
						} else {
							fd = io->io.fd;
						}
						if (io->state != BDD_IO_STATE_CREATED && io->state != BDD_IO_STATE_ESTABLISHED) {
							continue;
						}
						int r = epoll_ctl(instance->epoll_fd, EPOLL_CTL_DEL, fd, NULL);
						assert(r == 0);
					}
					broken = true;
					break;
				}
				broken = false;
			}
		}
		if (broken) {
			connections->next = connections_release_list;
			connections_release_list = connections;
			connections->working = true;
		} else {
			connections->next = NULL;
			if (connections_list == NULL) {
				assert(connections_list_tail == NULL);
				connections->prev = NULL;
				connections_list_tail = connections_list = connections;
			} else {
				assert(connections_list_tail != NULL);
				(connections->prev = connections_list_tail)->next = connections;
				connections_list_tail = connections;
			}
		}
		instance->linked_connections.head = next;
	}
	pthread_mutex_unlock(&(instance->linked_connections.mutex));

	if (unlikely(atomic_load(&(instance->exiting)))) {
		bdd_thread_exit(instance);
	}

	// to-do: mode where it wont serve while there are connecting ios that arent in the connect_state BDD_IO_CONNECT_STATE_WANTS_CALL
	for (int idx = 0; idx < n_events; ++idx) {
		struct epoll_event *event = &(instance->epoll_oevents[idx]);
		struct bdd_connections *connections = event->data.ptr;

		if (connections == NULL) { // eventfd
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

		if (connections->prev != NULL) {
			connections->prev->next = connections->next;
		}
		if (connections->next != NULL) {
			connections->next->prev = connections->prev;
		}
		if (connections_list_tail == connections) {
			if ((connections_list_tail = connections->prev) == NULL) {
				connections_list = NULL;
			}
		} else if (connections_list == connections) {
			if ((connections_list = connections->next) == NULL) {
				connections_list_tail = NULL;
			}
		}
		connections->next = NULL;

		bool established_io = false;
		bool connecting_io = false;
		for (bdd_io_id io_id = 0; io_id < bdd_connections_n_max_io(connections); ++io_id) {
			struct bdd_io *io = &(connections->io[io_id]);
			int fd;
			if (io->ssl) {
				fd = SSL_get_fd(io->io.ssl);
			} else {
				fd = io->io.fd;
			}
			if (io->state == BDD_IO_STATE_CREATED) {
				int r = epoll_ctl(instance->epoll_fd, EPOLL_CTL_DEL, fd, NULL);
				assert(r == 0);
				if (io->connect_state == BDD_IO_CONNECT_STATE_WANTS_CALL) {
					continue;
				}
				struct bdd_poll_io poll_io = {
					.io_id = io_id,
					.events = POLLIN | POLLOUT | POLLRDHUP,
					.revents = 0,
				};
				r = bdd_poll(connections, &(poll_io), 1, 0);
				assert(!(poll_io.revents & POLLNVAL));
				if (r < 0 || (poll_io.revents & (POLLERR | POLLHUP | POLLRDHUP))) {
					goto remove_io;
				}
				if (
					(io->connect_state == BDD_IO_CONNECT_STATE_WANTS_CALL_ONCE_READABLE && (poll_io.revents & POLLIN)) ||
					(io->connect_state == BDD_IO_CONNECT_STATE_WANTS_CALL_ONCE_WRITABLE && (poll_io.revents & POLLOUT))
				) {
					switch (bdd_io_connect(connections, io_id, NULL, 0)) {
						case (bdd_io_connect_err): case (bdd_io_connect_broken): {
							assert(false);
							goto remove_io;
						}
						case (bdd_io_connect_established): {
							connecting_io = true;
							if (connections->service->io_established != NULL) {
								connections->service->io_established(connections, io_id);
							}
							break;
						}
						default: {
							connecting_io = true;
							continue;
						}
					}
				}
			} else if (io->state == BDD_IO_STATE_ESTABLISHED) {
				int r = epoll_ctl(instance->epoll_fd, EPOLL_CTL_DEL, fd, NULL);
				assert(r == 0);
				struct bdd_poll_io poll_io = {
					.io_id = io_id,
					.events = POLLIN | POLLRDHUP,
					.revents = 0,
				};
				r = bdd_poll(connections, &(poll_io), 1, 0);
				assert(!(poll_io.revents & POLLNVAL));
				if (poll_io.revents & (POLLIN | POLLRDHUP)) {
					established_io = true;
				} else if (
					r < 0 ||
					(poll_io.revents & (
						POLLERR /* rst sent or received */ |
						POLLHUP /* socket has been shut-down in both directions */
					))
				) {
					remove_io:;
					bdd_io_remove(connections, io_id);
					if (connections->service->io_removed != NULL) {
						connections->service->io_removed(connections, io_id, poll_io.revents);
					}
				}
			}
		}

		if (!established_io) {
			if (connecting_io) {
				bdd_connections_link(instance, &(connections));
			} else {
				BDD_DEBUG_LOG("found broken connections struct\n");
				connections->next = connections_release_list;
				connections_release_list = connections;
			}
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
					pthread_cond_wait(
						&(workers->available_stack.cond),
						&(workers->available_stack.mutex)
					);
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
		(*(worker->connections_appender)) = connections;
		worker->connections_appender = &(connections->next);
		pthread_cond_signal(&(worker->work_cond));
		pthread_mutex_unlock(&(worker->work_mutex));
	}

	while (connections_release_list != NULL) {
		struct bdd_connections *next = connections_release_list->next;
		bdd_connections_deinit(connections_release_list);
		bdd_connections_release(instance, &(connections_release_list));
		connections_release_list = next;
	}

	goto bdd_serve__find_connections;
}
