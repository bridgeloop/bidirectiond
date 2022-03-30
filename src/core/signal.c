#include "internal.h"

#include <unistd.h>

void bdd_signal(struct bdd_instance *instance) {
	char buf[8] = {
	    ~0,
	    0,
	    0,
	    0,
	    0,
	    0,
	    0,
	    ~0,
	};
	int r = write(instance->serve_eventfd, (void *)buf, 8);
	assert(r == 8 || r < 0);
	return;
}

void bdd_stop_accept(struct bdd_instance *instance) {
	char buf[8] = {
	    ~0,
	    0,
	    0,
	    0,
	    0,
	    0,
	    0,
	    ~0,
	};
	int r = write(instance->accept.eventfd, (void *)buf, 8);
	assert(r == 8 || r < 0);
	return;
}

void bdd_thread_exit(struct bdd_instance *instance) {
	pthread_mutex_lock(&(instance->n_running_threads_mutex));
	if ((instance->n_running_threads -= 1) == 0) {
		pthread_cond_signal(&(instance->n_running_threads_cond));
	}
	pthread_mutex_unlock(&(instance->n_running_threads_mutex));
	pthread_exit(NULL);
}
