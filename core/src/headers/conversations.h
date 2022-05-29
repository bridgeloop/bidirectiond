#ifndef bidirectiond_core__conversations__h
#define bidirectiond_core__conversations__h

#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <time.h>
#include <sys/socket.h>

#include "bdd_io_id.h"
#include "bdd_io_connect.h"
#include "bdd_io_shutdown.h"
#include "bdd_conversation_n_max_io.h"

struct bdd_coac;
struct bdd_instance;
struct bdd_service;
struct bdd_io;

struct bdd_associated {
	void *data;
	void (*destructor)(void *data);
};

struct bdd_conversation {
	// set by bdd_conversation_init
	const struct bdd_service *service;

	// set by bdd_conversation_init, destroyed by bdd_conversation_deinit
	struct bdd_io *io_array;
	// technically set by a service, destroyed by a service or bdd_conversation_deinit
	struct bdd_associated associated;

	bool seen; // bdd_serve
	bdd_io_id n_connecting; // amount of connecting IOs - set by bdd_io_connect, and bdd_serve
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

void bdd_conversation_deinit(struct bdd_instance *instance, struct bdd_conversation *conversation);

void bdd_io_internal_set_state(struct bdd_conversation *conversation, struct bdd_io *io, uint8_t state);
int bdd_io_internal_fd(struct bdd_io *io);
bool bdd_io_internal_has_epoll_state(struct bdd_conversation *conversation, struct bdd_io *io);
void bdd_io_internal_break(struct bdd_conversation *conversation, struct bdd_io *io);
void bdd_io_internal_break_established(struct bdd_conversation *conversation, struct bdd_io *io);
enum bdd_io_connect_status bdd_io_internal_connect_continue(struct bdd_conversation *conversation, struct bdd_io *io);
enum bdd_io_shutdown_status bdd_io_internal_shutdown_continue(struct bdd_io *io);

#endif
