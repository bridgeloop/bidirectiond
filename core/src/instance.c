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
#include "headers/serve.h"

struct bdd_gv bdd_gv = {
	.cl_ssl_ctx = NULL,

	.exiting = false,

	.n_running_threads = 0,
	.n_running_threads_mutex = PTHREAD_MUTEX_INITIALIZER,
	.n_running_threads_cond = PTHREAD_COND_INITIALIZER,

	.name_descs = NULL,


	.eventfd = -1,

	.conversations = NULL,
	.conversations_idx = 0,
	.available_conversations = {
		.mutex = PTHREAD_MUTEX_INITIALIZER,
		.ids = NULL,
		.idx = 0,
	},

	.worker = NULL,
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

void bdd_thread_exit(void) {
	pthread_mutex_lock(&(bdd_gv.n_running_threads_mutex));
	if ((bdd_gv.n_running_threads -= 1) == 0) {
		pthread_cond_signal(&(bdd_gv.n_running_threads_cond));
	}
	pthread_mutex_unlock(&(bdd_gv.n_running_threads_mutex));
	pthread_exit(NULL);
	return;
}

void bdd_stop(void) {
	atomic_store(&(bdd_gv.exiting), true);
	if (bdd_gv.eventfd != -1) {
		char buf[8] = { ~0, 0, 0, 0, 0, 0, 0, ~0, };
		write(bdd_gv.eventfd, (void *)buf, 8);
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
	if (bdd_gv.cl_ssl_ctx != NULL) {
		SSL_CTX_free(bdd_gv.cl_ssl_ctx);
	}

	pthread_mutex_destroy(&(bdd_gv.n_running_threads_mutex));
	pthread_cond_destroy(&(bdd_gv.n_running_threads_cond));

	pthread_mutex_destroy(&(bdd_gv.available_conversations.mutex));

	for (
		size_t idx = 0;
		idx < bdd_gv.workers_idx;
		++idx
	) {
		struct bdd_worker_data *worker = bdd_gv_worker(idx);
		close(worker->epoll_fd);
		SSL_CTX_free(worker->ssl_ctx);
	}

	for (
		size_t idx = 0;
		idx < bdd_gv.conversations_idx;
		++idx
	) {
		struct bdd_conversation *conversation = &(bdd_gv.conversations[idx]);
		conversation->epoll_fd = -1;
		bdd_conversation_discard(conversation);
	}

	free(bdd_gv.conversations);
	close(bdd_gv.eventfd);

	return;
}

bool bdd_go(struct bdd_settings settings) {
	if (
		settings.sockfds == NULL ||
		settings.n_conversations <= 0 ||
		settings.n_epoll_oevents <= 0 ||
		settings.name_descs == NULL ||
		settings.n_worker_threads <= 0
	) {
		return false;
	}

	bool locked = false;

	SSL_CTX *cl_ssl_ctx = SSL_CTX_new(TLS_client_method());
	if (cl_ssl_ctx == NULL) {
		return false;
	}
	SSL_CTX_set_min_proto_version(cl_ssl_ctx, TLS1_3_VERSION);
	SSL_CTX_set_max_proto_version(cl_ssl_ctx, TLS1_3_VERSION);
	bdd_gv.cl_ssl_ctx = cl_ssl_ctx;
	if (!SSL_CTX_set_default_verify_paths(cl_ssl_ctx)) {
		goto err;
	}

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
	if (pthread_mutex_init(&(bdd_gv.available_conversations.mutex), NULL) != 0) {
		goto err;
	}
	// init conversations, and the available stack
	for (
		int *idx = &(bdd_gv.conversations_idx);
		(*idx) < settings.n_conversations;
		++(*idx)
	) {
		bdd_gv.conversations[(*idx)].state = bdd_conversation_unused;
		bdd_gv.available_conversations.ids[(*idx)] = (*idx);
	}
	// eventfd
	bdd_gv.eventfd = eventfd(0, EFD_NONBLOCK);
	if (bdd_gv.eventfd < 0) {
		goto err;
	}

	pthread_t pthid;

	// serve
	pthread_mutex_lock(&(bdd_gv.n_running_threads_mutex));
	locked = true;
	struct bdd_worker_data *worker_data = (struct bdd_worker_data *)&(bdd_gv.available_conversations.ids[settings.n_conversations]);
	bdd_gv.worker = worker_data;
	bdd_gv.n_workers = settings.n_worker_threads;
	#define next_worker_data \
		(struct bdd_worker_data *)((char *)worker_data + sizeof(struct bdd_worker_data) + (sizeof(struct epoll_event) * settings.n_epoll_oevents))
	for (bdd_gv.workers_idx = 0; bdd_gv.workers_idx < settings.n_worker_threads; ++bdd_gv.workers_idx) {
		int epoll_fd = epoll_create1(0);
		SSL_CTX *ssl_ctx = bdd_ssl_ctx_skel();
		bdd_tl_init(&(worker_data->timeout_list));
		if (epoll_fd < 0 || ssl_ctx == NULL) {
			goto worker_create_err;
		}
		struct epoll_event event = {
			.events = EPOLLIN,
		    .data = { .ptr = NULL, },
		};
		worker_data->epoll_fd = epoll_fd;
		worker_data->ssl_ctx = ssl_ctx;
		worker_data->serve_fd = settings.sockfds[bdd_gv.workers_idx];
		if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, worker_data->serve_fd, &(event)) != 0) {
			goto worker_create_err;
		}
		if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, bdd_gv.eventfd, &(event)) != 0) {
			goto worker_create_err;
		}

		if (pthread_create(&(pthid), NULL, (void *(*)(void *))(&(bdd_serve)), worker_data) != 0) {
			goto worker_create_err;
		}

		worker_data = next_worker_data;
		bdd_gv.n_running_threads += 1;
		continue;

		worker_create_err:;
		close(epoll_fd);
		if (ssl_ctx != NULL) {
			SSL_CTX_free(ssl_ctx);
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
