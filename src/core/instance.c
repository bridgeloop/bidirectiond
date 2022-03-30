#include "internal.h"

#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <unistd.h>

// fuck this whole file

struct bdd_instance *bdd_instance_alloc(void) {
	struct bdd_instance *instance = malloc(sizeof(struct bdd_instance));
	if (instance == NULL) {
		return NULL;
	}
	// exiting
	atomic_store(&(instance->exiting), false);
	// running threads
	instance->n_running_threads = 0;
	bdd_mutex_preinit(&(instance->n_running_threads_mutex));
	bdd_cond_preinit(&(instance->n_running_threads_cond));
	// epoll
	instance->epoll_fd = -1;
	instance->n_epoll_oevents = 0;
	instance->epoll_oevents = NULL;
	// name_descriptions
	instance->name_descriptions = NULL;
	// client timeout
	instance->client_timeout.tv_sec = 0;
	instance->client_timeout.tv_usec = 0;
	// server socket
	instance->sv_socket = -1;
	// connections
	instance->connections.n_connections = 0;
	instance->connections.connections = NULL;
	instance->connections.connections_idx = 0;
	instance->connections.available = NULL;
	instance->connections.available_idx = 0;
	bdd_mutex_preinit(&(instance->connections.available_mutex));
	bdd_cond_preinit(&(instance->connections.available_cond));
	// linked connections
	bdd_mutex_preinit(&(instance->linked_connections.mutex));
	// accept thread stuff
	instance->accept.eventfd = -1;
	for (uint8_t idx = 0; idx < 2; ++idx) {
		instance->accept.pollfds[idx].fd = -1;
		instance->accept.pollfds[idx].events = 0;
		instance->accept.pollfds[idx].revents = 0;
	}
	instance->accept.ssl_ctx = NULL;
	instance->accept.accept_ctx.service_name_description = NULL;
	instance->accept.accept_ctx.locked_name_descriptions = NULL;
	instance->linked_connections.head = NULL;
	// serve_eventfd
	instance->serve_eventfd = -1;
	// workers
	bdd_mutex_preinit(&(instance->workers.available_stack.mutex));
	bdd_cond_preinit(&(instance->workers.available_stack.cond));
	instance->workers.available_stack.ids = NULL;
	instance->workers.available_stack.idx = 0;
	instance->workers.n_workers = 0;
	instance->workers.info = NULL;
	instance->workers.info_idx = 0;
	instance->workers.buf = NULL;
	instance->workers.buf_sz_per_worker = 0;
	return instance;
}

struct bdd_instance *bdd_go(struct bdd_settings settings) {
	if (settings.sv_socket < 0 || settings.buf_sz == 0 || settings.n_connections < 0 || settings.n_epoll_oevents < 0 || settings.name_descriptions == NULL ||
	    ((settings.n_connections == 0 || settings.n_worker_threads == 0 || settings.n_epoll_oevents == 0) && (settings.n_connections != 0 || settings.n_worker_threads != 0 || settings.n_epoll_oevents != 0)))
	{
		return NULL;
	}
	bool uses_internal_services = settings.n_connections != 0;

	struct bdd_instance *instance = bdd_instance_alloc();
	if (instance == NULL) {
		return NULL;
	}

	if (pthread_mutex_init(&(instance->n_running_threads_mutex), NULL) != 0) {
		free(instance);
		return NULL;
	}
	if (pthread_cond_init(&(instance->n_running_threads_cond), NULL) != 0) {
		pthread_mutex_destroy(&(instance->n_running_threads_mutex));
		free(instance);
		return NULL;
	}

	struct bdd_instance *ret = (struct bdd_instance *)instance;
	{
		while (atomic_flag_test_and_set(&(BDD_GLOBAL_MUTEX)))
			;
		if (BDD_GLOBAL_RC == 0) {
			if ((BDD_GLOBAL_CL_SSL_CTX = SSL_CTX_new(TLS_client_method())) == NULL) {
				atomic_flag_clear(&(BDD_GLOBAL_MUTEX));
				free(instance);
				return NULL;
			}
		}
		if ((BDD_GLOBAL_RC += 1) <= 0) {
			atomic_flag_clear(&(BDD_GLOBAL_MUTEX));
			goto bdd_go__err;
		}
		atomic_flag_clear(&(BDD_GLOBAL_MUTEX));
	}

	// sigmask
	instance->sigmask = settings.sigmask;
	if (uses_internal_services) {
		// epoll
		if ((instance->epoll_fd = epoll_create1(0)) < 0) {
			goto bdd_go__err;
		}
		instance->n_epoll_oevents = settings.n_epoll_oevents;
		if ((instance->epoll_oevents = malloc(sizeof(struct epoll_event) * settings.n_epoll_oevents)) == NULL) {
			goto bdd_go__err;
		}
	}
	// name_descriptions
	instance->name_descriptions = settings.name_descriptions;
	// client timeout
	instance->client_timeout.tv_sec = (settings.client_timeout / 1000);
	instance->client_timeout.tv_usec = (settings.client_timeout % 1000) * 1000;
	// server socket
	instance->sv_socket = settings.sv_socket;
	if (uses_internal_services) {
		// connections
		instance->connections.n_connections = settings.n_connections;
		if ((instance->connections.connections = malloc((settings.n_connections * sizeof(struct bdd_connections)) + (settings.n_connections * sizeof(int)))) == NULL) {
			goto bdd_go__err;
		}
		// available stack
		instance->connections.available = (void *)&(instance->connections.connections[settings.n_connections]);
		instance->connections.available_idx = 0;
		if (pthread_mutex_init(&(instance->connections.available_mutex), NULL) != 0 || pthread_cond_init(&(instance->connections.available_cond), NULL) != 0) {
			goto bdd_go__err;
		}
		// init connections, and the available stack
		for (int *idx = &(instance->connections.connections_idx); (*idx) < settings.n_connections; ++(*idx)) {
			if (pthread_mutex_init(&(instance->connections.connections[(*idx)].working_mutex), NULL) != 0) {
				goto bdd_go__err;
			}
			instance->connections.connections[(*idx)].associated.data = NULL;
			instance->connections.connections[(*idx)].associated.destructor = NULL;
			instance->connections.connections[(*idx)].io = NULL;
			instance->connections.connections[(*idx)].working = false;
			instance->connections.connections[(*idx)].broken = false;
			instance->connections.available[(*idx)] = (*idx);
		}
		// linked connections
		if (pthread_mutex_init(&(instance->linked_connections.mutex), NULL) != 0) {
			goto bdd_go__err;
		}
		instance->linked_connections.head = NULL;
	}
	// accept
	if ((instance->accept.eventfd = eventfd(0, EFD_NONBLOCK)) < 0) {
		goto bdd_go__err;
	}
	instance->accept.pollfds[0].fd = settings.sv_socket;
	instance->accept.pollfds[0].events = POLLIN;
	instance->accept.pollfds[1].fd = instance->accept.eventfd;
	instance->accept.pollfds[1].events = POLLIN;
	if ((instance->accept.ssl_ctx = SSL_CTX_new(TLS_server_method())) == NULL) {
		goto bdd_go__err;
	}
	SSL_CTX_set_ecdh_auto(instance->accept.ssl_ctx, 1);
	if (SSL_CTX_set_cipher_list(instance->accept.ssl_ctx, "HIGH:!aNULL:!MD5") != 1) {
		goto bdd_go__err;
	}
	SSL_CTX_set_max_proto_version(instance->accept.ssl_ctx, TLS1_2_VERSION);
	SSL_CTX_set_options(instance->accept.ssl_ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION);
	SSL_CTX_set_tlsext_servername_callback(instance->accept.ssl_ctx, &(bdd_use_correct_ctx));
	SSL_CTX_set_tlsext_servername_arg(instance->accept.ssl_ctx, &(instance->accept.accept_ctx));
	if (uses_internal_services) {
		// serve
		if ((instance->serve_eventfd = eventfd(0, EFD_NONBLOCK)) < 0) {
			goto bdd_go__err;
		}
		struct epoll_event event = {
		    .events = EPOLLIN,
		    .data =
			{
			    .ptr = NULL,
			},
		};
		if (epoll_ctl(instance->epoll_fd, EPOLL_CTL_ADD, instance->serve_eventfd, &(event)) != 0) {
			goto bdd_go__err;
		}
		// workers
		if (!settings.use_work_queues) {
			if ((instance->workers.available_stack.ids = malloc(settings.n_worker_threads * sizeof(unsigned short int))) == NULL) {
				goto bdd_go__err;
			}
			instance->workers.available_stack.idx = settings.n_worker_threads;
		}
		if ((instance->workers.buf = malloc(settings.buf_sz * settings.n_worker_threads)) == NULL) {
			goto bdd_go__err;
		}
		instance->workers.buf_sz_per_worker = settings.buf_sz;
	}
	{
		pthread_mutex_lock(&(instance->n_running_threads_mutex));
		bool e = false;
		pthread_t pthid;
		if (pthread_create(&(pthid), NULL, (void *(*)(void *))(&(bdd_accept)), instance) != 0) {
			e = true;
		} else {
			instance->n_running_threads += 1;
		}
		if (uses_internal_services) {
			if (!e) {
				if (pthread_create(&(pthid), NULL, (void *(*)(void *))(&(bdd_serve)), instance) != 0) {
					e = true;
				} else {
					instance->n_running_threads += 1;
				}
			}
			struct bdd_worker *workers;
			if (!e && (workers = malloc(sizeof(struct bdd_worker) * settings.n_worker_threads)) == NULL) {
				e = true;
			}
			instance->workers.info = workers;
			for (unsigned short int *idx = &(instance->workers.n_workers); !e && (*idx) < settings.n_worker_threads; ++(*idx)) {
				(*((struct bdd_instance **)&(workers[(*idx)].instance))) = instance;
				if (pthread_mutex_init(&(workers[(*idx)].work_mutex), NULL) != 0) {
					e = true;
				}
				if (pthread_cond_init(&(workers[(*idx)].work_cond), NULL) != 0) {
					pthread_mutex_destroy(&(workers[(*idx)].work_mutex));
					e = true;
				}
				workers[(*idx)].id = (*idx);
				workers[(*idx)].connections = NULL;
				workers[(*idx)].connections_appender = NULL;
				if (pthread_create(&(pthid), NULL, (void *(*)(void *))(&(bdd_worker)), &(workers[(*idx)])) != 0) {
					e = true;
				} else {
					instance->n_running_threads += 1;
				}
			}
			if (e) {
				pthread_mutex_unlock(&(instance->n_running_threads_mutex));
				goto bdd_go__err;
			}
		}
		pthread_mutex_unlock(&(instance->n_running_threads_mutex));
	}

	return ret;

bdd_go__err:;
	bdd_stop(ret);
	bdd_wait(ret);
	bdd_destroy(ret);
	return NULL;
}
void bdd_stop(struct bdd_instance *instance) {
	atomic_store(&(instance->exiting), true);
	if (instance->accept.eventfd != -1) {
		bdd_stop_accept(instance);
	}
	if (instance->serve_eventfd != -1) {
		bdd_signal(instance);
	}
	for (unsigned short int idx = 0; idx < instance->workers.n_workers; ++idx) {
		pthread_mutex_lock(&(instance->workers.info[idx].work_mutex));
		pthread_cond_signal(&(instance->workers.info[idx].work_cond));
		pthread_mutex_unlock(&(instance->workers.info[idx].work_mutex));
	}
	return;
}
bool bdd_running(struct bdd_instance *instance) {
	pthread_mutex_lock(&(instance->n_running_threads_mutex));
	bool running = instance->n_running_threads != 0;
	pthread_mutex_unlock(&(instance->n_running_threads_mutex));
	return running;
}
void bdd_wait(struct bdd_instance *instance) {
	if (pthread_mutex_lock(&(instance->n_running_threads_mutex)) != 0) {
		return;
	}
	while (instance->n_running_threads != 0) {
		pthread_cond_wait(&(instance->n_running_threads_cond), &(instance->n_running_threads_mutex));
	}
	pthread_mutex_unlock(&(instance->n_running_threads_mutex));
	return;
}
void bdd_destroy(struct bdd_instance *instance) {
	pthread_mutex_destroy(&(instance->n_running_threads_mutex));
	pthread_cond_destroy(&(instance->n_running_threads_cond));

	if (instance->epoll_fd >= 0) {
		close(instance->epoll_fd);
	}
	if (instance->epoll_oevents != NULL) {
		free(instance->epoll_oevents);
	}

	pthread_mutex_destroy(&(instance->connections.available_mutex));
	pthread_cond_destroy(&(instance->connections.available_cond));

	for (int idx = 0; idx < instance->connections.n_connections; ++idx) {
		bdd_connections_deinit(&(instance->connections.connections[idx]));
		pthread_mutex_destroy(&(instance->connections.connections[idx].working_mutex));
	}

	if (instance->connections.connections != NULL) {
		free(instance->connections.connections);
	}

	pthread_mutex_destroy(&(instance->linked_connections.mutex));

	if (instance->accept.eventfd >= 0) {
		close(instance->accept.eventfd);
	}
	if (instance->accept.ssl_ctx != NULL) {
		SSL_CTX_free(instance->accept.ssl_ctx);
	}

	if (instance->serve_eventfd >= 0) {
		close(instance->serve_eventfd);
	}

	pthread_mutex_destroy(&(instance->workers.available_stack.mutex));
	pthread_cond_destroy(&(instance->workers.available_stack.cond));
	if (instance->workers.available_stack.ids != NULL) {
		free(instance->workers.available_stack.ids);
	}

	for (unsigned short int idx = 0; idx < instance->workers.n_workers; ++idx) {
		pthread_mutex_destroy(&(instance->workers.info[idx].work_mutex));
		pthread_cond_destroy(&(instance->workers.info[idx].work_cond));
	}

	if (instance->workers.buf != NULL) {
		free(instance->workers.buf);
	}
	if (instance->workers.info != NULL) {
		free(instance->workers.info);
	}

	free(instance);

	while (atomic_flag_test_and_set(&(BDD_GLOBAL_MUTEX)))
		;
	if (--BDD_GLOBAL_RC == 0) {
		SSL_CTX_free(BDD_GLOBAL_CL_SSL_CTX);
	}
	atomic_flag_clear(&(BDD_GLOBAL_MUTEX));

	return;
}