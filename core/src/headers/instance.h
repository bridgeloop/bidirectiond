#ifndef bidirectiond_core__instance__h
#define bidirectiond_core__instance__h

#include <signal.h>
#include <stdatomic.h>
#include <pthread.h>
#include <time.h>
struct bdd_coac;
#include <poll.h>
#include <openssl/ssl.h>
#include "accept.h"
struct bdd_worker;
#include <stddef.h>

struct bdd_gv {
	SSL_CTX *cl_ssl_ctx;
	sigset_t sigmask;

	atomic_bool exiting;

	int n_running_threads;
	pthread_mutex_t n_running_threads_mutex;
	pthread_cond_t n_running_threads_cond;

	int epoll_fd;
	int n_epoll_oevents;
	struct epoll_event *epoll_oevents;
	int epoll_timeout;

	void *name_descs;

	int sv_socket;
	int serve_eventfd;

	struct {
		pthread_mutex_t mutex;
		pthread_cond_t cond;
		int *ids;
		int idx;
	} available_coac;
	int n_coac;
	struct bdd_coac *coac;
	int coac_idx;

	struct {
		pthread_mutex_t mutex;
		struct bdd_coac *head;
	} conversations_to_epoll;

	struct {
		int eventfd;
		struct pollfd pollfds[2];
		SSL_CTX *ssl_ctx;
		struct bdd_accept_ctx ctx;
	} accept;

	struct {
		pthread_mutex_t mutex;
		pthread_cond_t cond;
		unsigned short int *ids;
		unsigned short int idx;
	} available_workers;
	unsigned short int n_workers;
	struct bdd_worker *workers;
	unsigned short int workers_idx;
};
extern struct bdd_gv bdd_gv;

#endif
