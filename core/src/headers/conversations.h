#ifndef bidirectiond_core__conversations__h
#define bidirectiond_core__conversations__h

#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <time.h>
#include <sys/socket.h>

#include "bdd_io.h"

struct bdd_service;
struct bdd_io;

struct bdd_associated {
	void *data;
	void (*destructor)(void *data);
};

enum bdd_conversation_state {
	bdd_conversation_unused,
	bdd_conversation_obtained,
	bdd_conversation_accept,
	bdd_conversation_ssl,
	bdd_conversation_connect,
	bdd_conversation_ssl_connect,
	bdd_conversation_established,
};

struct bdd_conversation {
	enum bdd_conversation_state state;

	struct bdd_conversation *next;
	struct bdd_conversation *prev;
	time_t accessed_at;

	pthread_mutex_t mutex;

	union {
		const struct bdd_service *service;
		struct bdd_service_instance *service_instance;
	} sosi;

	struct bdd_io client;
	union {
		struct bdd_io server;
		struct {
			const unsigned char *protocol_name;
			const char *cstr_protocol_name;
		} ac;
	} soac;

	struct bdd_associated associated;

	bool in_discard_list; // bdd_serve
};

enum bdd_conversation_init_status {
	bdd_conversation_init_success,
	bdd_conversation_init_failed_wants_deinit,
	bdd_conversation_init_failed,
} __attribute__((packed));
enum bdd_conversation_init_status bdd_conversation_init(
	struct bdd_conversation *conversation,
	SSL **client_ssl,
	struct sockaddr client_sockaddr,
	const struct bdd_service *service,
	const char *protocol_name,
	const void *instance_info
);

int bdd_io_internal_fd(struct bdd_io *io);
struct bdd_conversation *bdd_conversation_obtain(void);
void bdd_conversation_discard(struct bdd_conversation *conversation, int epoll_fd);
void bdd_io_init(struct bdd_conversation *conversation, struct bdd_io *io);
void bdd_io_discard(struct bdd_io *io, int epoll_fd);

uint8_t bdd_io_id(struct bdd_conversation *conversation, struct bdd_io *io);
struct bdd_io *bdd_io(struct bdd_conversation *conversation, uint8_t io_id);
struct bdd_io *bdd_io_opposite(struct bdd_conversation *conversation, struct bdd_io *io);

void bdd_io_apply_ssl(struct bdd_io *io, SSL *ssl);

#endif
