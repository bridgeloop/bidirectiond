#include <openssl/ssl.h>
#include <stdatomic.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <unistd.h>
#include <pthread.h>
#include <stdint.h>
#include <string.h>

#include "headers/instance.h"
#include "headers/conversations.h"
#include "headers/coac.h"
#include "headers/bdd_settings.h"
#include "headers/workers.h"
#include "headers/signal.h"
#include "headers/serve.h"

void bdd_mutex_preinit(pthread_mutex_t *dest) {
	static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
	memcpy(dest, &(mutex), sizeof(pthread_mutex_t));
	return;
}

void bdd_cond_preinit(pthread_cond_t *dest) {
	static pthread_cond_t mutex = PTHREAD_COND_INITIALIZER;
	memcpy(dest, &(mutex), sizeof(pthread_cond_t));
	return;
}


struct bdd_gv bdd_gv = {
	.cl_ssl_ctx = NULL,

	.n_running_threads = 0,
	.n_running_threads_mutex = PTHREAD_MUTEX_INITIALIZER,
	.n_running_threads_cond = PTHREAD_COND_INITIALIZER,

	.epoll_fd = -1,
	.epoll_oevents = NULL,

	.name_descs = NULL,

	.sv_socket = -1,
	.serve_eventfd = -1,

	.available_coac = {
		.mutex = PTHREAD_MUTEX_INITIALIZER,
		.cond = PTHREAD_COND_INITIALIZER,
		.ids = NULL,
	},
	.coac = NULL,
	.coac_idx = 0,

	.conversations_to_epoll = {
		.mutex = PTHREAD_MUTEX_INITIALIZER,
		.head = NULL,
	},

	.accept = {
		.eventfd = -1,
		.ssl_ctx = NULL,
	},

	.available_workers = {
		.mutex = PTHREAD_MUTEX_INITIALIZER,
		.cond = PTHREAD_COND_INITIALIZER,
		.ids = NULL,
	},
	.n_workers = 0,
	.workers = NULL,
};

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

void bdd_stop(void) {
	atomic_store(&(bdd_gv.exiting), true);
	if (bdd_gv.accept.eventfd != -1) {
		bdd_stop_accept();
	}
	if (bdd_gv.serve_eventfd != -1) {
		bdd_signal();
	}
	for (unsigned short int idx = 0; idx < bdd_gv.n_workers; ++idx) {
		pthread_mutex_lock(&(bdd_gv.workers[idx].work_mutex));
		pthread_cond_signal(&(bdd_gv.workers[idx].work_cond));
		pthread_mutex_unlock(&(bdd_gv.workers[idx].work_mutex));
	}
	return;
}
void bdd_wait(void) {
	if (pthread_mutex_lock(&(bdd_gv.n_running_threads_mutex)) != 0) {
		return;
	}
	while (bdd_gv.n_running_threads != 0) {
		pthread_cond_wait(&(bdd_gv.n_running_threads_cond), &(bdd_gv.n_running_threads_mutex));
	}
	pthread_mutex_unlock(&(bdd_gv.n_running_threads_mutex));
	return;
}
void bdd_destroy(void) {
	pthread_mutex_destroy(&(bdd_gv.n_running_threads_mutex));
	pthread_cond_destroy(&(bdd_gv.n_running_threads_cond));

	close(bdd_gv.epoll_fd);
	free(bdd_gv.epoll_oevents);

	pthread_mutex_destroy(&(bdd_gv.available_coac.mutex));
	pthread_cond_destroy(&(bdd_gv.available_coac.cond));

	for (
		size_t idx = 0;
		idx < bdd_gv.coac_idx;
		++idx
	) {
		struct bdd_coac *coac = &(bdd_gv.coac[idx]);
		if (coac->inner_type == bdd_coac_conversation) {
			bdd_conversation_deinit(&(coac->inner.conversation));
		}
	}
	free(bdd_gv.coac);

	pthread_mutex_destroy(&(bdd_gv.conversations_to_epoll.mutex));

	close(bdd_gv.accept.eventfd);
	if (bdd_gv.accept.ssl_ctx != NULL) {
		SSL_CTX_free(bdd_gv.accept.ssl_ctx);
	}

	close(bdd_gv.serve_eventfd);

	pthread_mutex_destroy(&(bdd_gv.available_workers.mutex));
	pthread_cond_destroy(&(bdd_gv.available_workers.cond));
	free(bdd_gv.available_workers.ids);

	for (
		size_t idx = 0;
		idx < bdd_gv.n_workers;
		++idx
	) {
		pthread_mutex_destroy(&(bdd_gv.workers[idx].work_mutex));
		pthread_cond_destroy(&(bdd_gv.workers[idx].work_cond));
	}

	free(bdd_gv.workers);
	SSL_CTX_free(bdd_gv.cl_ssl_ctx);

	return;
}

bool bdd_go(struct bdd_settings settings) {
	if (
		settings.sv_socket < 0 ||
		settings.n_conversations <= 0 ||
		settings.n_epoll_oevents <= 0 ||
		settings.name_descs == NULL ||
		settings.n_worker_threads <= 0
	) {
		return false;
	}

	SSL_CTX *cl_ssl_ctx = SSL_CTX_new(TLS_client_method());
	SSL_CTX_set_min_proto_version(cl_ssl_ctx, TLS1_3_VERSION);
	SSL_CTX_set_max_proto_version(cl_ssl_ctx, TLS1_3_VERSION);
	bdd_gv.cl_ssl_ctx = cl_ssl_ctx;

	// sigmask
	bdd_gv.sigmask = settings.sigmask;
	// running threads
	if (
		pthread_mutex_init(&(bdd_gv.n_running_threads_mutex), NULL) != 0 ||
		pthread_cond_init(&(bdd_gv.n_running_threads_cond), NULL) != 0
	) {
		goto err;
	}
	// epoll
	if ((bdd_gv.epoll_fd = epoll_create1(0)) < 0) {
		goto err;
	}
	bdd_gv.n_epoll_oevents = settings.n_epoll_oevents;
	if ((bdd_gv.epoll_oevents = malloc(sizeof(struct epoll_event) * settings.n_epoll_oevents)) == NULL) {
		goto err;
	}
	bdd_gv.epoll_timeout = settings.epoll_timeout;
	// name_descs
	bdd_gv.name_descs = settings.name_descs;
	// server socket
	bdd_gv.sv_socket = settings.sv_socket;
	// conversations
	bdd_gv.n_coac = settings.n_conversations;
	bdd_gv.coac = malloc(
		(settings.n_conversations * sizeof(struct bdd_coac)) +
		(settings.n_conversations * sizeof(int))
	);
	if (bdd_gv.coac == NULL) {
		goto err;
	}
	// available stack
	bdd_gv.available_coac.ids = (void *)&(bdd_gv.coac[settings.n_conversations]);
	bdd_gv.available_coac.idx = 0;
	if (
		pthread_mutex_init(&(bdd_gv.available_coac.mutex), NULL) != 0 ||
		pthread_cond_init(&(bdd_gv.available_coac.cond), NULL) != 0
	) {
		goto err;
	}
	// init conversations, and the available stack
	for (
		int *idx = &(bdd_gv.coac_idx);
		(*idx) < settings.n_conversations;
		++(*idx)
	) {
		bdd_gv.coac->inner_type = bdd_coac_none;
		bdd_gv.available_coac.ids[(*idx)] = (*idx);
	}
	// to epoll
	if (pthread_mutex_init(&(bdd_gv.conversations_to_epoll.mutex), NULL) != 0) {
		goto err;
	}
	bdd_gv.conversations_to_epoll.head = NULL;
	// accept
	if ((bdd_gv.accept.eventfd = eventfd(0, EFD_NONBLOCK)) < 0) {
		goto err;
	}
	bdd_gv.accept.pollfds[0].fd = settings.sv_socket;
	bdd_gv.accept.pollfds[0].events = POLLIN;
	bdd_gv.accept.pollfds[1].fd = bdd_gv.accept.eventfd;
	bdd_gv.accept.pollfds[1].events = POLLIN;
	if ((bdd_gv.accept.ssl_ctx = bdd_ssl_ctx_skel()) == NULL) {
		goto err;
	}
	SSL_CTX_set_alpn_select_cb(bdd_gv.accept.ssl_ctx, (void *)bdd_alpn_cb, &(bdd_gv.accept.ctx));
	SSL_CTX_set_client_hello_cb(bdd_gv.accept.ssl_ctx, (void *)bdd_hello_cb, &(bdd_gv.accept.ctx));
	// serve
	if ((bdd_gv.serve_eventfd = eventfd(0, EFD_NONBLOCK)) < 0) {
		goto err;
	}
	struct epoll_event event = {
		.events = EPOLLIN,
	    .data = {
		    .ptr = NULL,
		},
	};
	if (epoll_ctl(bdd_gv.epoll_fd, EPOLL_CTL_ADD, bdd_gv.serve_eventfd, &(event)) != 0) {
		goto err;
	}

	// workers
	if (!settings.use_work_queues) {
		unsigned short int *ids = malloc(settings.n_worker_threads * sizeof(unsigned short int));
		if (ids == NULL) {
			goto err;
		}
		bdd_gv.available_workers.ids = ids;
		bdd_gv.available_workers.idx = settings.n_worker_threads;
	}

	pthread_mutex_lock(&(bdd_gv.n_running_threads_mutex));
	pthread_t pthid;
	bool e = false;
	if (pthread_create(&(pthid), NULL, (void *(*)(void *))(&(bdd_accept)), NULL) != 0) {
		e = true;
	} else {
		bdd_gv.n_running_threads += 1;
	}
	if (!e && pthread_create(&(pthid), NULL, (void *(*)(void *))(&(bdd_serve)), NULL) != 0) {
		e = true;
	} else {
		bdd_gv.n_running_threads += 1;
	}
	struct bdd_worker *workers = malloc(sizeof(struct bdd_worker) * settings.n_worker_threads);
	if (workers == NULL) {
		e = true;
	}
	bdd_gv.workers = workers;
	for (
		unsigned short int *idx = &(bdd_gv.n_workers);
		!e && (*idx) < settings.n_worker_threads;
		++(*idx)
	) {
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
			bdd_gv.n_running_threads += 1;
		} else {
			e = true;
		}
	}
	pthread_mutex_unlock(&(bdd_gv.n_running_threads_mutex));
	if (e) {
		goto err;
	}

	return true;

err:;
	bdd_stop();
	bdd_wait();
	bdd_destroy();
	return false;
}
