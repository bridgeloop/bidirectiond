#ifndef bidirectiond_core__bdd_io_wait__h
#define bidirectiond_core__bdd_io_wait__h

#include <stdint.h>

#include "bdd_io_id.h"

struct bdd_conversation;
#define BDD_IO_WAIT_DONT 0
#define BDD_IO_WAIT_ESTABLISHED 1
#define BDD_IO_WAIT_RDHUP 2
bool bdd_io_wait(struct bdd_conversation *conversation, bdd_io_id io_id, uint8_t wait_state);

#endif
