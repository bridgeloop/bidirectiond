#ifndef bidirectiond__conversations__h
#define bidirectiond__conversations__h

#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <time.h>
#include <sys/socket.h>

#include "bdd_event.h"
#include "bdd_io.h"
#include "bdd_shutdown_status.h"
#include "bidirectiond_n_io.h"

struct bdd_service;
struct bdd_io;

#define io_conversation(io) (&(bdd_gv.conversations[io->conversation_id]))
#define _conversation_next(conversation) (&(bdd_gv.conversations[conversation->next]))
#define _conversation_prev(conversation) (&(bdd_gv.conversations[conversation->prev]))
#define conversation_next(conversation) ((conversation)->next != -1 ? _conversation_next(conversation) : NULL)
#define conversation_prev(conversation) ((conversation)->prev != -1 ? _conversation_prev(conversation) : NULL)
#define conversation_id(conversation) ((conversation) == NULL ? -1 : (int)(((char *)(conversation) - (char *)bdd_gv.conversations) / sizeof(struct bdd_conversation)))

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
	#ifndef NDEBUG
	time_t spawn;
	#endif

	enum bdd_conversation_state state;
	int epoll_fd;

	int next;
	int prev;
	time_t accessed_at;

	bool tl : 1, remove : 1;

	union {
		const struct bdd_service *service;
		struct bdd_service_instance *service_instance;
	} sosi;

	struct bdd_io io_array[BIDIRECTIOND_N_IO];

	bdd_io_id n_blocking;
	bdd_io_id n_in_epoll_with_events;

	bdd_io_id n_ev;
	struct bdd_ev ev[BIDIRECTIOND_N_IO];

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

int bdd_io_fd(struct bdd_io *io);
struct bdd_conversation *bdd_conversation_obtain(int epoll_fd);
void bdd_conversation_discard(struct bdd_conversation *conversation);
bool bdd_io_discard(struct bdd_io *io);

bdd_io_id bdd_io_id_of(struct bdd_io *io);
struct bdd_io *bdd_io(struct bdd_conversation *conversation, bdd_io_id io_id);

enum bdd_shutdown_status bdd_ssl_shutdown_continue(struct bdd_io *io);

bool bdd_io_hup(struct bdd_io *io, bool rdhup);
bool bdd_io_state(struct bdd_io *io, enum bdd_io_state new_state);
void bdd_io_clean(struct bdd_io *io, enum bdd_io_state prev_state);
void bdd_io_epoll_remove(struct bdd_io *io);

#endif
