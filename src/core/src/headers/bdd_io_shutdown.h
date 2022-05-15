#ifndef bidirectiond_core__bdd_io_shutdown__h
#define bidirectiond_core__bdd_io_shutdown__h

#include "bdd_io_id.h"
struct bdd_conversation;

enum bdd_io_shutdown_state {
	bdd_io_shutdown_err,
	bdd_io_shutdown_again,
	bdd_io_shutdown_wants_write,
	bdd_io_shutdown_wants_read,
	bdd_io_shutdown_success,
};
enum bdd_io_shutdown_state bdd_io_shutdown(struct bdd_conversation *conversation, bdd_io_id io_id);

#endif
