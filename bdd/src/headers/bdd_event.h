#ifndef bidirectiond__bdd_event__h
#define bidirectiond__bdd_event__h

#include "bidirectiond_n_io.h"

#define bdd_ev_in 1
#define bdd_ev_out 2
#define bdd_ev_err 4
#define bdd_ev_removed (bdd_ev_removed_err | bdd_ev_removed_hup)
#define bdd_ev_removed_err 8
#define bdd_ev_removed_hup 16

struct bdd_ev {
	uint8_t events;
	bdd_io_id io_id;
};

struct bdd_conversation;
struct bdd_ev *bdd_ev(struct bdd_conversation *conversation, bdd_io_id idx);
bdd_io_id bdd_n_ev(struct bdd_conversation *conversation);

#endif
