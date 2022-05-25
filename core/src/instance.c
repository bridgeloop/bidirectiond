#include <openssl/ssl.h>
#include <stdatomic.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <unistd.h>
#include <pthread.h>
#include <stdint.h>

#include "headers/instance.h"
#include "headers/conversations.h"
#include "headers/bdd_settings.h"
#include "headers/bdd_pthread_preinit.h"
#include "headers/workers.h"
#include "headers/internal_globals.h"
#include "headers/signal.h"
#include "headers/serve.h"

SSL_CTX *bdd_ssl_ctx_skel(void) {
	SSL_CTX *ssl_ctx = SSL_CTX_new(TLS_server_method());
	if (ssl_ctx == NULL) {
		return NULL;
	}
	if (SSL_CTX_set_ciphersuites(
		ssl_ctx,
		"TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256"
	) != 1) {
		goto err;
	}
	SSL_CTX_set_min_proto_version(ssl_ctx, TLS1_3_VERSION);
	SSL_CTX_set_max_proto_version(ssl_ctx, TLS1_3_VERSION);
	return ssl_ctx;

	err:;
	SSL_CTX_free(ssl_ctx);
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
	for (unsigned short int idx = 0; idx < instance->n_workers; ++idx) {
		pthread_mutex_lock(&(instance->workers[idx].work_mutex));
		pthread_cond_signal(&(instance->workers[idx].work_cond));
		pthread_mutex_unlock(&(instance->workers[idx].work_mutex));
	}
	return;
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

	close(instance->epoll_fd);
	free(instance->epoll_oevents);

	pthread_mutex_destroy(&(instance->available_conversations.mutex));
	pthread_cond_destroy(&(instance->available_conversations.cond));

	for (
		size_t idx = 0;
		idx < instance->conversations_idx;
		++idx
	) {
		bdd_conversation_deinit(&(instance->conversations[idx]));
	}
	free(instance->conversations);

	pthread_mutex_destroy(&(instance->conversations_to_epoll.mutex));

	close(instance->accept.eventfd);
	if (instance->accept.ssl_ctx != NULL) {
		SSL_CTX_free(instance->accept.ssl_ctx);
	}

	close(instance->serve_eventfd);

	pthread_mutex_destroy(&(instance->available_workers.mutex));
	pthread_cond_destroy(&(instance->available_workers.cond));
	free(instance->available_workers.ids);

	for (
		size_t idx = 0;
		idx < instance->n_workers;
		++idx
	) {
		pthread_mutex_destroy(&(instance->workers[idx].work_mutex));
		pthread_cond_destroy(&(instance->workers[idx].work_cond));
	}

	free(instance->workers);
	free(instance);

	while (atomic_flag_test_and_set(&(BDD_GLOBAL_MUTEX)));
	if (--BDD_GLOBAL_RC == 0) {
		if (BDD_GLOBAL_CL_SSL_CTX != NULL) {
			SSL_CTX_free(BDD_GLOBAL_CL_SSL_CTX);
		}
	}
	atomic_flag_clear(&(BDD_GLOBAL_MUTEX));

	return;
}

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
	instance->epoll_timeout = -1;
	// name_descs
	instance->name_descs = NULL;
	// server socket
	instance->sv_socket = -1;
	// conversations
	instance->n_conversations = 0;
	instance->conversations = NULL;
	instance->conversations_idx = 0;
	instance->available_conversations.ids = NULL;
	instance->available_conversations.idx = 0;
	bdd_mutex_preinit(&(instance->available_conversations.mutex));
	bdd_cond_preinit(&(instance->available_conversations.cond));
	// linked conversations
	bdd_mutex_preinit(&(instance->conversations_to_epoll.mutex));
	instance->conversations_to_epoll.head = NULL;
	// accept thread stuff
	instance->accept.eventfd = -1;
	for (uint8_t idx = 0; idx < 2; ++idx) {
		instance->accept.pollfds[idx].fd = -1;
		instance->accept.pollfds[idx].events = 0;
		instance->accept.pollfds[idx].revents = 0;
	}
	instance->accept.ssl_ctx = NULL;
	instance->accept.ctx.service_instance = NULL;
	instance->accept.ctx.protocol_name = NULL;
	instance->accept.ctx.cstr_protocol_name = NULL;
	instance->conversations_to_epoll.head = NULL;
	// serve_eventfd
	instance->serve_eventfd = -1;
	// workers
	bdd_mutex_preinit(&(instance->available_workers.mutex));
	bdd_cond_preinit(&(instance->available_workers.cond));
	instance->available_workers.ids = NULL;
	instance->available_workers.idx = 0;
	instance->n_workers = 0;
	instance->workers = NULL;
	instance->workers_idx = 0;
	return instance;
}

struct bdd_instance *bdd_go(struct bdd_settings settings) {
	if (
		settings.sv_socket < 0 ||
		settings.n_conversations <= 0 ||
		settings.n_epoll_oevents <= 0 ||
		settings.name_descs == NULL ||
		settings.n_worker_threads <= 0
	) {
		return NULL;
	}

	struct bdd_instance *instance = bdd_instance_alloc();
	if (instance == NULL) {
		return NULL;
	}

	struct bdd_instance *ret = (struct bdd_instance *)instance;
	bool e = false;
	while (atomic_flag_test_and_set(&(BDD_GLOBAL_MUTEX)));
	if (BDD_GLOBAL_RC == 0) {
		BDD_GLOBAL_CL_SSL_CTX = SSL_CTX_new(TLS_client_method());
		SSL_CTX_set_min_proto_version(BDD_GLOBAL_CL_SSL_CTX, TLS1_3_VERSION);
		SSL_CTX_set_max_proto_version(BDD_GLOBAL_CL_SSL_CTX, TLS1_3_VERSION);
	}
	BDD_GLOBAL_RC += 1;
	if (BDD_GLOBAL_CL_SSL_CTX == NULL || BDD_GLOBAL_RC <= 0) {
		e = true;
		BDD_GLOBAL_RC -= 1;
	}
	atomic_flag_clear(&(BDD_GLOBAL_MUTEX));
	if (e) {
		free(instance);
		return NULL;
	}

	// sigmask
	instance->sigmask = settings.sigmask;
	// running threads
	if (
		pthread_mutex_init(&(instance->n_running_threads_mutex), NULL) != 0 ||
		pthread_cond_init(&(instance->n_running_threads_cond), NULL) != 0
	) {
		goto err;
	}
	// epoll
	if ((instance->epoll_fd = epoll_create1(0)) < 0) {
		goto err;
	}
	instance->n_epoll_oevents = settings.n_epoll_oevents;
	if ((instance->epoll_oevents = malloc(sizeof(struct epoll_event) * settings.n_epoll_oevents)) == NULL) {
		goto err;
	}
	instance->epoll_timeout = settings.epoll_timeout;
	// name_descs
	instance->name_descs = settings.name_descs;
	// server socket
	instance->sv_socket = settings.sv_socket;
	// conversations
	instance->n_conversations = settings.n_conversations;
	instance->conversations = malloc(
		(settings.n_conversations * sizeof(struct bdd_conversation)) +
		(settings.n_conversations * sizeof(int))
	);
	if (instance->conversations == NULL) {
		goto err;
	}
	// available stack
	instance->available_conversations.ids = (void *)&(instance->conversations[settings.n_conversations]);
	instance->available_conversations.idx = 0;
	if (
		pthread_mutex_init(&(instance->available_conversations.mutex), NULL) != 0 ||
		pthread_cond_init(&(instance->available_conversations.cond), NULL) != 0
	) {
		goto err;
	}
	// init conversations, and the available stack
	for (
		int *idx = &(instance->conversations_idx);
		(*idx) < settings.n_conversations;
		++(*idx)
	) {
		instance->conversations[(*idx)].associated.data = NULL;
		instance->conversations[(*idx)].associated.destructor = NULL;
		instance->conversations[(*idx)].io_array = NULL;
		instance->available_conversations.ids[(*idx)] = (*idx);
	}
	// to epoll
	if (pthread_mutex_init(&(instance->conversations_to_epoll.mutex), NULL) != 0) {
		goto err;
	}
	instance->conversations_to_epoll.head = NULL;
	// accept
	if ((instance->accept.eventfd = eventfd(0, EFD_NONBLOCK)) < 0) {
		goto err;
	}
	instance->accept.pollfds[0].fd = settings.sv_socket;
	instance->accept.pollfds[0].events = POLLIN;
	instance->accept.pollfds[1].fd = instance->accept.eventfd;
	instance->accept.pollfds[1].events = POLLIN;
	if ((instance->accept.ssl_ctx = bdd_ssl_ctx_skel()) == NULL) {
		goto err;
	}
	SSL_CTX_set_alpn_select_cb(instance->accept.ssl_ctx, (void *)bdd_alpn_cb, instance);
	SSL_CTX_set_client_hello_cb(instance->accept.ssl_ctx, (void *)bdd_hello_cb, instance);
	// serve
	if ((instance->serve_eventfd = eventfd(0, EFD_NONBLOCK)) < 0) {
		goto err;
	}
	struct epoll_event event = {
	    .events = EPOLLIN,
	    .data = {
		    .ptr = NULL,
		},
	};
	if (epoll_ctl(instance->epoll_fd, EPOLL_CTL_ADD, instance->serve_eventfd, &(event)) != 0) {
		goto err;
	}

	// workers
	if (!settings.use_work_queues) {
		unsigned short int *ids = malloc(settings.n_worker_threads * sizeof(unsigned short int));
		if (ids == NULL) {
			goto err;
		}
		instance->available_workers.ids = ids;
		instance->available_workers.idx = settings.n_worker_threads;
	}

	pthread_mutex_lock(&(instance->n_running_threads_mutex));
	pthread_t pthid;
	if (pthread_create(&(pthid), NULL, (void *(*)(void *))(&(bdd_accept)), instance) != 0) {
		e = true;
	} else {
		instance->n_running_threads += 1;
	}
	if (!e && pthread_create(&(pthid), NULL, (void *(*)(void *))(&(bdd_serve)), instance) != 0) {
		e = true;
	} else {
		instance->n_running_threads += 1;
	}
	struct bdd_worker *workers = malloc(sizeof(struct bdd_worker) * settings.n_worker_threads);
	if (workers == NULL) {
		e = true;
	}
	instance->workers = workers;
	for (
		unsigned short int *idx = &(instance->n_workers);
		!e && (*idx) < settings.n_worker_threads;
		++(*idx)
	) {
		(*((struct bdd_instance **)&(workers[(*idx)].instance))) = instance;
		bdd_mutex_preinit(&(workers[(*idx)].work_mutex));
		bdd_cond_preinit(&(workers[(*idx)].work_cond));
		if (
			pthread_mutex_init(&(workers[(*idx)].work_mutex), NULL) != 0 ||
			pthread_cond_init(&(workers[(*idx)].work_cond), NULL) != 0
		) {
			e = true;
		}
		workers[(*idx)].id = (*idx);
		workers[(*idx)].conversations = NULL;
		workers[(*idx)].conversations_appender = NULL;
		if (
			!e &&
			pthread_create(
				&(pthid),
				NULL,
				(void *(*)(void *))(&(bdd_worker)),
				&(workers[(*idx)])
			) == 0
		) {
			instance->n_running_threads += 1;
		} else {
			e = true;
		}
	}
	pthread_mutex_unlock(&(instance->n_running_threads_mutex));
	if (e) {
		goto err;
	}

	return ret;

err:;
	bdd_stop(ret);
	bdd_wait(ret);
	bdd_destroy(ret);
	return NULL;
}
