#ifndef bidirectiond_core__conversations__h
#define bidirectiond_core__conversations__h

#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <time.h>
#include <sys/socket.h>

#include "bdd_io_id.h"
#include "bdd_conversation_n_max_io.h"

struct bdd_instance;
struct bdd_service;
struct bdd_io;

int bdd_conversation_id(struct bdd_instance *instance, struct bdd_conversation *conversation);

struct bdd_associated {
	void *data;
	void (*destructor)(void *data);
};

// bdd_conversations are passed around four differently-purposed
// linked lists.

// to_epoll is a list of conversations to be processed
// by a loop in serve.c which will either discard a conversation,
// or add it to an epoll instance, and then move it into
// valid_conversations.
// to_epoll does not use the `prev` pointer.

// valid_conversations is a linked list of conversations that are
// in the epoll instance. conversations in valid_conversations that
// have been inactive for a long time will be discarded. otherwise,
// if an io associated with a conversation in valid_conversions
// receives an event, it will be processed in serve.c, and it will
// either be moved into conversations_to_discard, or it will be
// moved into a worker's conversation list.
// valid_conversations' entries must have a valid `prev` pointer
// (NULL is a valid value for the `prev` pointer).

// conversations_to_discard is a linked list of conversations to
// be discared as soon as possible.
// conversations_to_discard does not use the `prev` pointer.

// a worker's conversation list is a list of conversations that
// should be passed to a service's serve function.
// a worker's conversation list does not use the `prev` pointer.
struct bdd_conversation {
	const uint8_t struct_type; // constant - set by bdd_go
	uint8_t
		skip : 2, // moved out of the valid_conversations linked list - set by bdd_serve
		noatime : 2; // do not update accessed_at - set by bdd_conversation_init and bdd_serve

	// created by bdd_go, destroyed by bdd_destroy
	pthread_mutex_t skip_mutex;

	// valid_conversations
	// set by the to_epoll processor when the conversation is moved into valid_conversations
	time_t accessed_at;
	struct bdd_conversation *prev;
	// all linked lists of bdd_conversations
	// set when a conversation is moved into a linked list
	void *next;

	// set by bdd_conversation_init
	const struct bdd_service *service;

	// set by bdd_conversation_init, destroyed by bdd_conversation_deinit
	struct bdd_io *io;
	// technically set by a service, destroyed by a service or bdd_conversation_deinit
	struct bdd_associated associated;
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
struct bdd_conversation *bdd_conversation_obtain(struct bdd_instance *instance);
void bdd_conversation_release(struct bdd_instance *instance, struct bdd_conversation **conversation);
void bdd_conversation_deinit(struct bdd_conversation *conversation);
void bdd_conversation_link(struct bdd_instance *instance, struct bdd_conversation **conversation);

uint8_t bdd_io_state(struct bdd_io *io);
uint8_t bdd_io_substate(struct bdd_io *io);
void bdd_io_set_state(struct bdd_io *io, uint8_t state);
void bdd_io_set_state_substate(struct bdd_io *io, uint8_t state, uint8_t substate);
int bdd_io_fd(struct bdd_io *io);
bool bdd_io_has_epoll_state(struct bdd_io *io);
uint8_t bdd_io_wait_state(struct bdd_io *io);

#endif
