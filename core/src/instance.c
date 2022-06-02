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
#include "headers/bdd_settings.h"
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

	.exiting = false,

	.n_running_threads = 0,
	.n_running_threads_mutex = PTHREAD_MUTEX_INITIALIZER,
	.n_running_threads_cond = PTHREAD_COND_INITIALIZER,

	.name_descs = NULL,

	.sv_socket = -1,
	.serve_eventfd = -1,

	.conversations = NULL,
	.conversations_idx = 0,
	.available_conversations = {
		.mutex = PTHREAD_MUTEX_INITIALIZER,
		.cond = PTHREAD_COND_INITIALIZER,
		.ids = NULL,
		.idx = 0,
	},

	.accept = {
		.eventfd = -1,
	},

	.workers = NULL,
	.workers_idx = 0,
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

	pthread_mutex_destroy(&(bdd_gv.available_conversations.mutex));
	pthread_cond_destroy(&(bdd_gv.available_conversations.cond));

	for (
		size_t idx = 0;
		idx < bdd_gv.conversations_idx;
		++idx
	) {
		struct bdd_conversation *conversation = &(bdd_gv.conversations[idx]);
		bdd_conversation_discard(conversation, -1);
		pthread_mutex_destroy(&(conversation->mutex));
	}
	free(bdd_gv.conversations);

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

	bool locked = false;

	SSL_CTX *cl_ssl_ctx = SSL_CTX_new(TLS_client_method());
	if (sl_ssl_ctx == NULL) {
		return false;
	}
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
	bdd_gv.n_epoll_oevents = settings.n_epoll_oevents;
	bdd_gv.epoll_timeout = settings.epoll_timeout;
	// name_descs
	bdd_gv.name_descs = settings.name_descs;
	// server socket
	bdd_gv.sv_socket = settings.sv_socket;
	// conversations
	bdd_gv.n_conversations = settings.n_conversations;
	bdd_gv.conversations = malloc(
		(settings.n_conversations * sizeof(struct bdd_conversation)) + // conversations
		(settings.n_conversations * sizeof(int)) + // available_conversations
		((
			sizeof(struct bdd_worker_data) +
			(settings.n_epoll_oevents * sizeof(struct epoll_event))
		) * settings.n_worker_threads) // workers
	);
	if (bdd_gv.conversations == NULL) {
		goto err;
	}
	// available stack
	bdd_gv.available_conversations.ids = (void *)&(bdd_gv.conversations[settings.n_conversations]);
	bdd_gv.available_conversations.idx = 0;
	if (
		pthread_mutex_init(&(bdd_gv.available_conversations.mutex), NULL) != 0 ||
		pthread_cond_init(&(bdd_gv.available_conversations.cond), NULL) != 0
	) {
		goto err;
	}
	// init conversations, and the available stack
	for (
		int *idx = &(bdd_gv.conversations_idx);
		(*idx) < settings.n_conversations;
		++(*idx)
	) {
		if (pthread_mutex_init(&(bdd_gv.conversations[(*idx)]), NULL) != 0) {
			goto err;
		}
		bdd_gv.available_conversations.ids[(*idx)] = (*idx);
	}
	// eventfd
	bdd_gv.eventfd = eventfd(0, EFD_NONBLOCK);
	if (bdd_gv.eventfd < 0) {
		goto err;
	}
	// accept
	bdd_gv.accept.pollfds[0].fd = settings.sv_socket;
	bdd_gv.accept.pollfds[0].events = POLLIN;
	bdd_gv.accept.pollfds[1].fd = bdd_gv.eventfd;
	bdd_gv.accept.pollfds[1].events = POLLIN;

	pthread_mutex_lock(&(bdd_gv.n_running_threads_mutex));
	locked = true;
	pthread_t pthid;
	if (pthread_create(&(pthid), NULL, (void *(*)(void *))(&(bdd_accept)), NULL) != 0) {
		goto err;
	}
	bdd_gv.n_running_threads += 1;

	// serve
	struct bdd_worker_data *worker_data = &(bdd_gv.available_conversations.ids[settings.n_conversations]);
	#define next_worker_data \
		(struct bdd_worker_data *)((char *)worker_data + sizeof(struct bdd_worker_data) + (sizeof(struct epoll_event) * settings.n_epoll_oevents))
	for (bdd_gv.workers_idx = 0; bdd_gv.workers_idx < settings.n_worker_threads; ++bdd_gv.workers_idx) {
		int epoll_fd = epoll_create1(0);
		SSL_CTX *ssl_ctx = bdd_ssl_ctx_skel();
		bool tl_init_success = bdd_tl_init(&(worker_data->timeout_list));
		if (epoll_fd < 0 || ssl_ctx == NULL || !tl_init_success) {
			goto worker_create_err;
		}
		struct epoll_event event = {
			.events = EPOLLIN,
		    .data = {
			    .ptr = NULL,
			},
		};
		if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, bdd_gv.eventfd, &(event)) != 0) {
			goto worker_create_err;
		}
		worker_data->epoll_fd = epoll_create1(0);
		worker_data->ssl_ctx = ssl_ctx;

		if (pthread_create(&(pthid), NULL, (void *(*)(void *))(&(bdd_worker)), worker_data) != 0) {
			goto worker_create_err;
		}

		worker_data = next_worker_data;
		continue;

		worker_create_err:;
		if (epoll_fd >= 0) {
			close(epoll_fd);
		}
		if (ssl_ctx != NULL) {
			SSL_CTX_free(ssl_ctx);
		}
		if (tl_init_success) {
			bdd_tl_destroy(&(worker_data->timeout_list));
		}
		goto err;
	}

	pthread_mutex_unlock(&(bdd_gv.n_running_threads_mutex));
	locked = false;

	return true;

	err:;
	if (locked) {
		pthread_mutex_unlock(&(bdd_gv.n_running_threads_mutex));
	}
	bdd_stop();
	bdd_wait();
	bdd_destroy();
	return false;
}
