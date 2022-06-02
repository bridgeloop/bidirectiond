#ifndef bidirectiond_core__bdd_settings__h
#define bidirectiond_core__bdd_settings__h

#include <stdint.h>
#include <signal.h>

struct bdd_settings {
	struct bdd_name_descs *name_descs;

	int epoll_timeout;

	int n_conversations;
	int n_epoll_oevents;
	unsigned short int n_worker_threads;

	sigset_t sigmask;

	int *sockfds;
};

#endif
