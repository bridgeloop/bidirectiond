#include <openssl/ssl.h>
#include <stdatomic.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <unistd.h>
#include <pthread.h>
#include <stdint.h>
#include <string.h>

#include "headers/hashmap.h"
#include "headers/instance.h"
#include "headers/conversations.h"
#include "headers/bdd_settings.h"
#include "headers/serve.h"

#define elsewhere 0
struct bdd_gv bdd_gv = {
	.cl_ssl_ctx = NULL,

	.sigmask = elsewhere,

	.exiting = false,

	.n_running_threads = elsewhere,
	.n_running_threads_mutex = PTHREAD_MUTEX_INITIALIZER,
	.n_running_threads_cond = PTHREAD_COND_INITIALIZER,

	.eventfd = -1,

	.epoll_fd = -1,
	.serve_fd = -1,
	.n_epoll_oevents = elsewhere,
	.timerfd_timeout = elsewhere,

	.name_descs = elsewhere,

	.conversations = NULL,
	.conversations_idx = 0,
	.available_conversations = {
		.mutex = PTHREAD_MUTEX_INITIALIZER,
		.ids = NULL,
		.idx = 0,
	},

	.n_workers = elsewhere,
	.workers = NULL,
	.workers_idx = 0,

	.tcp_nodelay = true,
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

void *bdd_thread_exit(struct bdd_worker_data *worker) {
	hashmap_area_release(bdd_gv.name_descs, worker->ssl_cb_ctx.area);
	pthread_mutex_lock(&(bdd_gv.n_running_threads_mutex));
	if ((bdd_gv.n_running_threads -= 1) == 0) {
		pthread_cond_signal(&(bdd_gv.n_running_threads_cond));
	}
	pthread_mutex_unlock(&(bdd_gv.n_running_threads_mutex));
	return NULL;
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
		SSL_CTX_free(worker->ssl_ctx);
	}


	for (
		size_t idx = 0;
		idx < bdd_gv.conversations_idx;
		++idx
	) {
		struct bdd_conversation *conversation = &(bdd_gv.conversations[idx]);
		close(conversation->epoll_inst);
		conversation->epoll_inst = -1;
		bdd_conversation_discard(conversation);
	}

	free(bdd_gv.conversations);
	close(bdd_gv.eventfd);
	close(bdd_gv.epoll_fd);
	// maybe close serve_fd?

	return;
}

static void *thread_init(struct bdd_worker_data *worker_data) {
	pthread_sigmask(SIG_BLOCK, &(bdd_gv.sigmask), NULL);
	worker_data->ssl_cb_ctx.area = hashmap_area(bdd_gv.name_descs);
	return bdd_serve(worker_data);
}

struct epoll_event bdd_epoll_conv(struct bdd_conversation *conv) {
	return (struct epoll_event){
		.events = EPOLLIN | EPOLLONESHOT,
		.data = { .ptr = conv, },
	};
}

bool bdd_go(struct bdd_settings settings) {
	if (
		settings.serve_fd < 0 ||
		settings.n_conversations <= 0 ||
		settings.n_epoll_oevents <= 0
	) {
		return false;
	}

	bdd_gv.tcp_nodelay = settings.tcp_nodelay;
	bdd_gv.n_workers = sysconf(_SC_NPROCESSORS_ONLN);

	#ifndef NDEBUG
	bdd_gv.n_workers = 1;
	#endif

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
	bdd_gv.n_running_threads = 0;

	// eventfd
	bdd_gv.eventfd = eventfd(0, EFD_NONBLOCK);
	if (bdd_gv.eventfd < 0) {
		goto err;
	}
	// epoll
	if ((bdd_gv.epoll_fd = epoll_create1(0)) < 0) {
		goto err;
	}
	bdd_gv.serve_fd = settings.serve_fd;
	struct epoll_event ev = bdd_epoll_conv(NULL);
	if (epoll_ctl(bdd_gv.epoll_fd, EPOLL_CTL_ADD, bdd_gv.serve_fd, &(ev)) != 0) {
		goto err;
	}
	ev.events &= ~EPOLLONESHOT;
	if (epoll_ctl(bdd_gv.epoll_fd, EPOLL_CTL_ADD, bdd_gv.eventfd, &(ev)) != 0) {
		goto err;
	}
	bdd_gv.n_epoll_oevents = settings.n_epoll_oevents;
	bdd_gv.timerfd_timeout = settings.timerfd_timeout;
	// conversations

	bdd_gv.n_conversations = settings.n_conversations;
	bdd_gv.conversations = malloc(
		(settings.n_conversations * sizeof(struct bdd_conversation)) + // conversations
		(settings.n_conversations * sizeof(int)) + // available_conversations
		((
			sizeof(struct bdd_worker_data) +
			(settings.n_epoll_oevents * sizeof(struct epoll_event))
		) * bdd_gv.n_workers) // workers
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
	ev = (struct epoll_event){
		.events = 0,
		.data = { .ptr = NULL, }
	};
	for (
		int *idx = &(bdd_gv.conversations_idx);
		*idx < settings.n_conversations;
		++(*idx)
	) {
		bdd_gv.conversations[*idx].state = bdd_conversation_unused;
		int fd = epoll_create1(0);
		if (fd < 0) {
			goto err;
		}
		bdd_gv.conversations[*idx].epoll_inst = fd;
		if (epoll_ctl(bdd_gv.epoll_fd, EPOLL_CTL_ADD, fd, &(ev)) != 0) {
			close(fd);
			goto err;
		}
		bdd_gv.available_conversations.ids[*idx] = *idx;
	}

	// serve
	pthread_t pthid;

	pthread_mutex_lock(&(bdd_gv.n_running_threads_mutex));
	locked = true;

	bdd_gv.workers = (struct bdd_worker_data *)&(bdd_gv.available_conversations.ids[settings.n_conversations]);
	for (bdd_gv.workers_idx = 0; bdd_gv.workers_idx < bdd_gv.n_workers; ++bdd_gv.workers_idx) {
		struct bdd_worker_data *worker_data = bdd_gv_worker(bdd_gv.workers_idx);

		SSL_CTX *ssl_ctx = bdd_ssl_ctx_skel();

		SSL_CTX_set_client_hello_cb(ssl_ctx, (void *)bdd_hello_cb, &(worker_data->ssl_cb_ctx));
		SSL_CTX_set_alpn_select_cb(ssl_ctx, (void *)bdd_alpn_cb, &(worker_data->ssl_cb_ctx));
		worker_data->ssl_ctx = ssl_ctx;

		if (pthread_create(&(pthid), NULL, (void *(*)(void *))(&(thread_init)), worker_data) != 0) {
			goto worker_create_err;
		}

		bdd_gv.n_running_threads += 1;
		continue;

		worker_create_err:;
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
