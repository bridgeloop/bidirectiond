#ifndef bidirectiond_core__bdd_io_connect__h
#define bidirectiond_core__bdd_io_connect__h

#include "bdd_io_id.h"
#include <sys/socket.h>
struct bdd_conversation;
enum bdd_io_connect_status {
	bdd_io_connect_err,
	bdd_io_connect_again,
	bdd_io_connect_inprogress,
	bdd_io_connect_established,
};
__attribute__((warn_unused_result)) enum bdd_io_connect_status bdd_io_connect(struct bdd_conversation *conversation, bdd_io_id io_io, struct sockaddr *addr, socklen_t addrlen);

#endif
