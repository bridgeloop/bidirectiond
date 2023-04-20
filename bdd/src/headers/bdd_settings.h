#ifndef bidirectiond__bdd_settings__h
#define bidirectiond__bdd_settings__h

#include <stdint.h>
#include <signal.h>

struct bdd_settings {
	int epoll_timeout;

	int n_conversations;
	int n_epoll_oevents;

	sigset_t sigmask;

	int *sockfds;
};

#endif
