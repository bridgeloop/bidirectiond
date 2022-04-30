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

enum bdd_name_description_service_type {
	bdd_name_description_service_type_none,
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

	bool working: 1, broken: 1;
	pthread_mutex_t working_mutex;

	const struct bdd_service *service;

	struct bdd_io *io;

	struct bdd_connections_associated associated;
};

struct bdd_service {
	bool (*serve)(struct bdd_connections *connections, void *buf, size_t buf_size);

	bool (*connections_init
	)(struct bdd_connections *connections,
	  const char *protocol_name,
	  void *instance_info,
	  bdd_io_id client_id,
	  struct sockaddr client_sockaddr);

	void (*instance_info_destructor)(void *instance_info);
	bool (*instantiate
	)(struct locked_hashmap *name_descriptions,
	  const struct bdd_service *service,
	  size_t n_arguments,
	  const char **arguments);
	const char **supported_protocols;
	const char **supported_arguments;
	const char *arguments_help;

	bdd_io_id n_max_io;
};

struct bdd_settings {
	int sv_socket;

	struct hashmap *name_descriptions;

	uint32_t client_timeout;

	uint32_t buf_sz;
	bool use_stack_buf: 1, use_work_queues: 1;

	int n_connections;
	int n_epoll_oevents;
	unsigned short int n_worker_threads;

	sigset_t sigmask;
};

__attribute__((warn_unused_result)) int bdd_poll(struct bdd_connections *connections, bdd_io_id io_id);
__attribute__((warn_unused_result)) ssize_t
bdd_read(struct bdd_connections *connections, bdd_io_id io_id, void *buf, ssize_t sz);
__attribute__((warn_unused_result)) ssize_t
bdd_read_whole(struct bdd_connections *connections, bdd_io_id io_id, void *buf, ssize_t sz);
__attribute__((warn_unused_result)) ssize_t
bdd_write(struct bdd_connections *connections, bdd_io_id io_id, void *buf, ssize_t sz);
__attribute__((warn_unused_result)) ssize_t
bdd_write_whole(struct bdd_connections *connections, bdd_io_id io_id, void *buf, ssize_t sz);

bool bdd_create_io(struct bdd_connections *connections, bdd_io_id *io_id, int *fd, const char *ssl_name);
void bdd_remove_io(struct bdd_connections *connections, bdd_io_id io_id);
void bdd_set_associated(struct bdd_connections *connections, void *data, void (*destructor)(void *));
#define bdd_get_associated(connections) (connections->associated.data)

struct bdd_instance *bdd_go(struct bdd_settings settings);
bool bdd_running(struct bdd_instance *instance);
void bdd_wait(struct bdd_instance *instance);
void bdd_stop(struct bdd_instance *instance);
void bdd_destroy(struct bdd_instance *instance);

bool bdd_name_descriptions_add_service_instance(
	struct locked_hashmap *name_descriptions,
	const char *scope,
	size_t scope_sz,
	const struct bdd_service *service,
	void **instance_info
);
bool bdd_name_descriptions_create_ssl_ctx(
	struct locked_hashmap *name_descriptions,
	X509 **x509_ref,
	EVP_PKEY **pkey_ref
);
struct hashmap *bdd_name_descriptions_create(void);

#endif
