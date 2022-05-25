#ifndef bidirectiond_core__bdd_io_shutdown__h
#define bidirectiond_core__bdd_io_shutdown__h

#include "bdd_io_id.h"
struct bdd_conversation;

enum bdd_io_shutdown_status {
	bdd_io_shutdown_err,
	bdd_io_shutdown_inprogress,
	bdd_io_shutdown_success,
};
__attribute__((warn_unused_result)) enum bdd_io_shutdown_status bdd_io_shutdown(struct bdd_conversation *conversation, bdd_io_id io_id);

#endif
