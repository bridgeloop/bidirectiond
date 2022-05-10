#ifndef bidirectiond_core__bdd_poll_io__h
#define bidirectiond_core__bdd_poll_io__h

#include "bdd_io_id.h"

struct bdd_poll_io {
	bdd_io_id io_id;
	short int events;
	short int revents;
};

#endif
