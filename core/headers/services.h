#ifndef bidirectiond_core__services__h
#define bidirectiond_core__services__h

#include <stdbool.h>
#include <stddef.h>
#include <sys/socket.h>
#include <sys/epoll.h>

#include "../src/headers/bdd_io_id.h"
#include "../src/headers/bdd_service.h"
#include "../src/headers/bdd_io_remove.h"
#include "../src/headers/bdd_name_descs.h"
#include "../src/headers/bdd_io_connect.h"
#include "../src/headers/bdd_conversation_n_max_io.h"
#include "../src/headers/bdd_poll.h"
#include "../src/headers/bdd_io_shutdown.h"

struct bdd_conversation;

__attribute__((warn_unused_result)) ssize_t bdd_read(
	struct bdd_conversation *conversation,
	bdd_io_id io_id,
	void *buf,
	ssize_t sz
);
__attribute__((warn_unused_result)) ssize_t bdd_write(
	struct bdd_conversation *conversation,
	bdd_io_id io_id,
	void *buf,
	ssize_t sz
);

bool bdd_io_create(
	struct bdd_conversation *conversation,
	bdd_io_id *io_id,
	int domain,
	int type,
	int protocol
);
bool bdd_io_prep_ssl(
	struct bdd_conversation *conversation,
	bdd_io_id io_id,
	char *ssl_name
);
void bdd_set_associated(
	struct bdd_conversation *conversation,
	void *data,
	void (*destructor)(void *)
);
void *bdd_get_associated(struct bdd_conversation *conversation);
bool bdd_name_descs_add_service_instance(
	struct bdd_name_descs *name_descs,
	const char *scope,
	size_t scope_sz,
	const struct bdd_service *service,
	const void **instance_info
);
bool bdd_io_set_epoll_events(
	struct bdd_conversation *conversation,
	bdd_io_id io_id,
	uint32_t epoll_events
);
bool bdd_io_set_blocking(
	struct bdd_conversation *conversation,
	bdd_io_id io_id,
	bool block
);
uint32_t bdd_io_epoll_events(struct bdd_conversation *conversation, bdd_io_id io_id);
bool bdd_io_blocking(struct bdd_conversation *conversation, bdd_io_id io_id);

#endif
