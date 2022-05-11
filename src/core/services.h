#ifndef bidirectiond_core__services__h
#define bidirectiond_core__services__h

#include <stdbool.h>
#include <stddef.h>
#include <sys/socket.h>
#include "src/headers/pollrdhup.h"
#include "src/headers/bdd_io_id.h"
#include "src/headers/bdd_service.h"
#include "src/headers/bdd_io_remove.h"
#include "src/headers/bdd_io_connect.h"
#include "src/headers/bdd_poll.h"
#include "src/headers/bdd_io_shutdown.h"
#include "src/headers/bdd_io_wait.h"

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
bool bdd_io_prep_ssl(struct bdd_conversation *conversation, bdd_io_id io_id, char *ssl_name);
void bdd_set_associated(
	struct bdd_conversation *conversation,
	void *data,
	void (*destructor)(void *)
);
void *bdd_get_associated(struct bdd_conversation *conversation);
bool bdd_name_descriptions_add_service_instance(
	struct locked_hashmap *name_descriptions,
	const char *scope,
	size_t scope_sz,
	const struct bdd_service *service,
	void **instance_info
);

#endif
