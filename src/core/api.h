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

#define BDD_IO_STATE_UNUSED 0
#define BDD_IO_STATE_CREATED 1
#define BDD_IO_STATE_ESTABLISHED 2
#define BDD_IO_STATE_BROKEN 3

#define BDD_IO_CONNECT_STATE_WANTS_CALL 0
#define BDD_IO_CONNECT_STATE_WANTS_CALL_ONCE_WRITABLE 1
#define BDD_IO_CONNECT_STATE_WANTS_CALL_ONCE_READABLE 2
#define BDD_IO_CONNECT_STATE_DO_NOT_CALL 3

struct bdd_poll_io {
	bdd_io_id io_id;
	short int events;
	short int revents;
};

struct bdd_instance;
struct bdd_io {
	uint8_t
		state : 2,
		shutdown : 1,
		connect_stage : 1, // internal
		connect_state : 2,
		ssl : 1,
		tcp : 1;
	union {
		int fd;
		SSL *ssl;
	} io;
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

	void (*io_removed)(struct bdd_connections *connections, bdd_io_id io_id, short int revents);
	void (*io_established)(struct bdd_connections *connections, bdd_io_id io_id);

	bool (*connections_init)(
		struct bdd_connections *connections,
		const char *protocol_name,
		void *instance_info,
		bdd_io_id client_id,
		struct sockaddr client_sockaddr
	);

	void (*instance_info_destructor)(void *instance_info);
	bool (*instantiate)(
		struct locked_hashmap *name_descriptions,
		const struct bdd_service *service,
		size_t n_arguments,
		const char **arguments
	);
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

int bdd_poll(
	struct bdd_connections *connections,
	struct bdd_poll_io *io_ids,
	bdd_io_id n_io_ids,
	int timeout
);
__attribute__((warn_unused_result)) ssize_t bdd_read(
	struct bdd_connections *connections,
	bdd_io_id io_id,
	void *buf,
	ssize_t sz
);
__attribute__((warn_unused_result)) ssize_t bdd_write(
	struct bdd_connections *connections,
	bdd_io_id io_id,
	void *buf,
	ssize_t sz
);

bool bdd_io_create(
	struct bdd_connections *connections,
	bdd_io_id *io_id,
	int domain,
	int type,
	int protocol
);
bool bdd_io_prep_ssl(struct bdd_connections *connections, bdd_io_id io_id, char *ssl_name);
void bdd_io_remove(struct bdd_connections *connections, bdd_io_id io_id);
enum bdd_io_connect_status {
	bdd_io_connect_err,
	bdd_io_connect_broken,
	bdd_io_connect_connecting,
	bdd_io_connect_established,
};
enum bdd_io_connect_status bdd_io_connect(struct bdd_connections *connections, bdd_io_id io_io, struct sockaddr *addr, socklen_t addrlen);
void bdd_set_associated(
	struct bdd_connections *connections,
	void *data,
	void (*destructor)(void *)
);
#define bdd_get_associated(connections) (connections->associated.data)

struct bdd_instance *bdd_go(struct bdd_settings settings);
bool bdd_running(struct bdd_instance *instance);
void bdd_wait(struct bdd_instance *instance);
void bdd_stop(struct bdd_instance *instance);
void bdd_destroy(struct bdd_instance *instance);
void bdd_io_shutdown(struct bdd_connections *connections, bdd_io_id io_id);

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
