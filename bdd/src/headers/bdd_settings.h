#ifndef bidirectiond__bdd_settings__h
#define bidirectiond__bdd_settings__h

#include <stdint.h>
#include <signal.h>
#include <stdbool.h>

struct bdd_settings {
	int timerfd_timeout;

	int n_conversations;
	int n_epoll_oevents;

	sigset_t sigmask;

	int serve_fd;
	
	bool tcp_nodelay;
};

#endif
