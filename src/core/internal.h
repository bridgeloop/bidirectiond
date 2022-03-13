#ifndef bidirectiond_core__internal__h
#define bidirectiond_core__internal__h

#include "api.h"

extern atomic_flag BDD_GLOBAL_MUTEX;
extern size_t BDD_GLOBAL_RC;
extern SSL_CTX *BDD_GLOBAL_CL_SSL_CTX;

void bdd_mutex_preinit(pthread_mutex_t *dest);
void bdd_cond_preinit(pthread_cond_t *dest);

// my justification for the following shit is: bdd's memory usage is already kinda pushing it, so i'd like to save some heap space in exchange for a few extra instructions
#define bdd_connections_n_max_io(c) (c->service->n_max_io)
#define bdd_connections_id(instance, c) (((char *)c - (char *)(instance->connections.connections)) / sizeof(struct bdd_connections))

struct bdd_worker {
	struct bdd_instance *const instance;
	unsigned short int id;
	pthread_mutex_t work_mutex;
	pthread_cond_t work_cond;
	struct bdd_connections *connections;
	struct bdd_connections **connections_appender;
};
struct bdd_workers {
	struct {
		pthread_mutex_t mutex;
		pthread_cond_t cond;
		unsigned short int *ids;
		unsigned short int idx;
	} available_stack;
	unsigned short int n_workers;
	struct bdd_worker *info;
	unsigned short int info_idx;
	void *buf;
	size_t buf_sz_per_worker;
};

struct bdd_accept_ctx {
	struct bdd_name_description *service_name_description;
	struct locked_hashmap *locked_name_descriptions;
};

struct bdd_instance {
	sigset_t sigmask;

	atomic_bool exiting;

	int n_running_threads;
	pthread_mutex_t n_running_threads_mutex;
	pthread_cond_t n_running_threads_cond;

	int epoll_fd;
	int n_epoll_oevents;
	struct epoll_event *epoll_oevents;

	void *name_descriptions;

	struct timeval client_timeout;

	int sv_socket;

	struct {
		int n_connections;

		struct bdd_connections *connections;
		int connections_idx;

		// stack
		int *available;
		int available_idx;
		pthread_mutex_t available_mutex;
		pthread_cond_t available_cond;
	} connections;
	struct {
		pthread_mutex_t mutex;
		struct bdd_connections *head;
	} linked_connections;

	struct {
		int eventfd;
		struct pollfd pollfds[2];
		SSL_CTX *ssl_ctx;
		struct bdd_accept_ctx accept_ctx;
	} accept;

	int serve_eventfd;

	struct bdd_workers workers;
};

#ifdef NDEBUG
#define BDD_DEBUG_LOG(x...) (0)
#else
#include <stdio.h>
#ifdef BIDIRECTIOND_VERBOSE_DEBUG_LOG
int bdd_vdl_SSL_write(void *x, char *data, size_t len);
int bdd_vdl_send(int a, char *b, size_t c, int _);
#define SSL_write bdd_vdl_SSL_write
#define send bdd_vdl_send
int bdd_vdl_pthread_mutex_lock(void *_, char *name, int ln);
int bdd_vdl_pthread_mutex_unlock(void *_, char *name, int ln);
int bdd_vdl_pthread_cond_wait(void *_, void *__, char *name, int ln);
int bdd_vdl_pthread_mutex_trylock(void *_, char *name, int ln);
#define pthread_mutex_lock(x) bdd_vdl_pthread_mutex_lock(x, #x, __LINE__)
#define pthread_mutex_unlock(x) bdd_vdl_pthread_mutex_unlock(x, #x, __LINE__)
#define pthread_cond_wait(_, __) bdd_vdl_pthread_cond_wait(_, __, #__, __LINE__)
#define pthread_mutex_trylock(x) bdd_vdl_pthread_mutex_trylock(x, #x, __LINE__)
#endif
#define BDD_DEBUG_LOG(string, args...) (printf("[DEBUG (%p)] " string, (void *)pthread_self(), ##args), fflush(stdout))
#endif

enum bdd_connections_init_status { bdd_connections_init_success,
								   bdd_connections_init_failed_wants_deinit,
								   bdd_connections_init_failed,
} __attribute__((packed));
enum bdd_connections_init_status bdd_connections_init(struct bdd_connections *connections, SSL **client_ssl, struct sockaddr client_sockaddr, const struct bdd_internal_service *service, void *service_info);
struct bdd_connections *bdd_connections_obtain(struct bdd_instance *instance);
void bdd_connections_release(struct bdd_instance *instance, struct bdd_connections **connections);
void bdd_connections_deinit(struct bdd_connections *connections);
void bdd_connections_link(struct bdd_instance *instance, struct bdd_connections **connections);
void bdd_signal(struct bdd_instance *instance);

int bdd_use_correct_ctx(SSL *client_ssl, int *_, struct bdd_accept_ctx *ctx);

void *bdd_serve(struct bdd_instance *instance);
void *bdd_accept(struct bdd_instance *instance);
void *bdd_worker(struct bdd_worker *worker);

void bdd_stop_accept(struct bdd_instance *instance);

void bdd_thread_exit(struct bdd_instance *instance);

#ifndef unlikely
#define unlikely(x) __builtin_expect((x), 0)
#endif

#endif
