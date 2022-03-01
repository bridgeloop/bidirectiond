#ifndef bidirectiond_core__api__h
#define bidirectiond_core__api__h

#include <assert.h>
#include <hashmap/hashmap.h>
#include <openssl/ssl.h>
#include <poll.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/time.h>

#ifndef POLLRDHUP
#define POLLRDHUP 0x400
#endif

enum bdd_name_description_service_type { bdd_name_description_service_type_none,
										 bdd_name_description_service_type_internal,
} __attribute__((packed));
typedef unsigned short int bdd_io_id;

struct bdd_instance;
struct bdd_io {
	int fd;
	SSL *ssl;
};

struct bdd_connections_associated {
	void *data;
	void (*destructor)(void *data);
};

struct bdd_connections {
	struct bdd_connections *next;

	bool working : 1, broken : 1;
	pthread_mutex_t working_mutex;

	const struct bdd_internal_service *service;

	struct bdd_io *io;

	struct bdd_connections_associated associated;
};

struct bdd_internal_service {
	char *name;

	bool (*serve)(struct bdd_connections *connections, void *buf, size_t buf_size);

	bool (*connections_init)(struct bdd_connections *connections, void *service_info, bdd_io_id client_id, struct sockaddr client_sockaddr);

	void (*service_info_destructor)(void *service_info);
	bool (*service_init)(struct locked_hashmap *name_descriptions, struct bdd_internal_service *service, size_t n_arguments, char **arguments);
	char **supported_arguments;
	char *arguments_help;

	bdd_io_id n_max_io;
};

struct bdd_settings {
	int sv_socket;

	struct hashmap *name_descriptions;

	uint32_t client_timeout;

	uint32_t buf_sz;
	bool use_stack_buf : 1, use_work_queues : 1;

	int n_connections;
	int n_epoll_oevents;
	unsigned short int n_worker_threads;

	sigset_t sigmask;
};

enum bdd_service_type { bdd_service_type_none,
						bdd_service_type_internal,
} __attribute__((packed));
struct bdd_name_description {
	SSL_CTX *ssl_ctx;

	enum bdd_service_type service_type;
	union {
		struct {
			struct bdd_internal_service *service;
			void *service_info;
		} internal;
	} service;
};

__attribute__((warn_unused_result)) int bdd_poll(struct bdd_connections *connections, bdd_io_id io_id);
__attribute__((warn_unused_result)) ssize_t bdd_read(struct bdd_connections *connections, bdd_io_id io_id, void *buf, ssize_t sz);
__attribute__((warn_unused_result)) ssize_t bdd_read_whole(struct bdd_connections *connections, bdd_io_id io_id, void *buf, ssize_t sz);
__attribute__((warn_unused_result)) ssize_t bdd_write(struct bdd_connections *connections, bdd_io_id io_id, void *buf, ssize_t sz);
__attribute__((warn_unused_result)) ssize_t bdd_write_whole(struct bdd_connections *connections, bdd_io_id io_id, void *buf, ssize_t sz);

bool bdd_create_io(struct bdd_connections *connections, bdd_io_id *io_id, int *fd, char *ssl_name);
void bdd_remove_io(struct bdd_connections *connections, bdd_io_id io_id);
void bdd_set_associated(struct bdd_connections *connections, void *data, void (*destructor)(void *));
void bdd_name_description_destroy(struct bdd_name_description *name_description);
#define bdd_get_associated(connections) (connections->associated.data)

struct bdd_instance *bdd_go(struct bdd_settings settings);
bool bdd_running(struct bdd_instance *instance);
void bdd_wait(struct bdd_instance *instance);
void bdd_stop(struct bdd_instance *instance);
void bdd_destroy(struct bdd_instance *instance);

bool bdd_name_descriptions_set_internal_service(struct locked_hashmap *name_descriptions, char *name, size_t name_len, struct bdd_internal_service *service, void *service_info);
bool bdd_name_descriptions_set_ssl_ctx(struct locked_hashmap *name_descriptions, char *name, size_t name_len, SSL_CTX *ssl_ctx);

#endif
