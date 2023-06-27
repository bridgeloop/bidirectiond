#ifndef bidirectiond__instance__h
#define bidirectiond__instance__h

#include <signal.h>
#include <stdatomic.h>
#include <pthread.h>
#include <time.h>
#include <poll.h>
#include <openssl/ssl.h>
#include <stddef.h>

#include "accept.h"
#include "serve.h"

void *bdd_thread_exit(struct bdd_worker_data *worker);

struct bdd_gv {
	SSL_CTX *cl_ssl_ctx;

	sigset_t sigmask;

	atomic_bool exiting;

	int n_running_threads;
	pthread_mutex_t n_running_threads_mutex;
	pthread_cond_t n_running_threads_cond;

	int n_epoll_oevents;
	int epoll_timeout;

	void *name_descs;

	int eventfd;

	int n_conversations;
	struct bdd_conversation *conversations;
	int conversations_idx;
	struct {
		pthread_mutex_t mutex;
		int *ids;
		int idx;
	} available_conversations;

	unsigned short int n_workers;
	struct bdd_worker_data *workers;
	unsigned short int workers_idx;

	bool tcp_nodelay;
};
#define bdd_gv_worker(idx) (struct bdd_worker_data *)((char *)bdd_gv.workers + ((sizeof(struct bdd_worker_data) + (sizeof(struct epoll_event) * bdd_gv.n_epoll_oevents)) * idx))
extern struct bdd_gv bdd_gv;

#endif
