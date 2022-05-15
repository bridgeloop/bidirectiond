#ifndef bidirectiond_core__bdd_settings__h
#define bidirectiond_core__bdd_settings__h

#include <stdint.h>
#include <signal.h>

struct bdd_settings {
	int sv_socket;

	struct hashmap *name_descriptions;

	uint32_t client_timeout;
	int epoll_timeout;

	bool use_work_queues;

	int n_conversations;
	int n_epoll_oevents;
	unsigned short int n_worker_threads;

	sigset_t sigmask;
};

#endif
