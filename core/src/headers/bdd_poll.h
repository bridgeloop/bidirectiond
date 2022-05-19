#ifndef bidirectiond_core__bdd_io_poll__h
#define bidirectiond_core__bdd_io_poll__h

#include <poll.h>

#include "bdd_io_id.h"
#include "bdd_poll_io.h"

struct bdd_conversation;
int bdd_poll(
	struct bdd_conversation *conversation,
	struct bdd_poll_io *io_ids,
	bdd_io_id n_io_ids,
	int timeout
);

#endif
