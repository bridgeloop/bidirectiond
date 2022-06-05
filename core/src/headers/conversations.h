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
	bdd_conversation_established,
};

struct bdd_conversation {
	enum bdd_conversation_state state;
	int epoll_fd;

	struct bdd_conversation *next;
	struct bdd_conversation *prev;
	time_t accessed_at;

	union {
		const struct bdd_service *service;
		struct bdd_service_instance *service_instance;
	} sosi;

	struct bdd_io *io_array;

	typeof(BIDIRECTIOND_N_IO) n_connecting;
	typeof(BIDIRECTIOND_N_IO) n_in_epoll_with_events;

	typeof(BIDIRECTIOND_N_IO) n_ev;

	union {
		struct bdd_associated associated;
		struct {
			const unsigned char *protocol_name;
			const char *cstr_protocol_name;
		} pn;
	} aopn;
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

int bdd_io_fd(struct bdd_io *io);
struct bdd_conversation *bdd_conversation_obtain(int epoll_fd);
void bdd_conversation_discard(struct bdd_conversation *conversation);
typeof(BIDIRECTIOND_N_IO) bdd_io_obtain(struct bdd_conversation *conversation);
void bdd_io_discard(struct bdd_io *io);

uint8_t bdd_io_id(struct bdd_io *io);
struct bdd_io *bdd_io(struct bdd_conversation *conversation, uint8_t io_id);

void bdd_io_apply_ssl(struct bdd_io *io, SSL *ssl);

#endif
