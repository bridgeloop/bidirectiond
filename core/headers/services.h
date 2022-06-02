#ifndef bidirectiond_core__services__h
#define bidirectiond_core__services__h

#include <stdbool.h>
#include <stddef.h>
#include <sys/socket.h>
#include <sys/epoll.h>

#include "../src/headers/bdd_event.h"
#include "../src/headers/bdd_service.h"
#include "../src/headers/bdd_name_descs.h"

struct bdd_conversation;

__attribute__((warn_unused_result)) ssize_t bdd_io_read(
	struct bdd_conversation *conversation,
	uint8_t io_id,
	void *buf,
	ssize_t sz
);
__attribute__((warn_unused_result)) ssize_t bdd_io_write(
	struct bdd_conversation *conversation,
	uint8_t io_id,
	void *buf,
	ssize_t sz
);

bool bdd_connect(struct bdd_conversation *conversation, int address_family, struct sockaddr *addr, socklen_t addrlen);
bool bdd_prep_ssl(
	struct bdd_conversation *conversation,
	char *ssl_name,
	char *alp
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

bool bdd_io_shutdown(struct bdd_conversation *conversation, uint8_t io_id);

#endif
