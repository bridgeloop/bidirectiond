#include <unistd.h>
#include <pthread.h>
#include <assert.h>

#include "headers/instance.h"

void bdd_signal(void) {
	char buf[8] = { ~0, 0, 0, 0, 0, 0, 0, ~0, };
	int r = write(bdd_gv.serve_eventfd, (void *)buf, 8);
	assert(r == 8 || r < 0);
	return;
}

void bdd_stop_accept(void) {
	char buf[8] = { ~0, 0, 0, 0, 0, 0, 0, ~0, };
	int r = write(bdd_gv.accept.eventfd, (void *)buf, 8);
	assert(r == 8 || r < 0);
	return;
}

void bdd_thread_exit(void) {
	pthread_mutex_lock(&(bdd_gv.n_running_threads_mutex));
	if ((bdd_gv.n_running_threads -= 1) == 0) {
		pthread_cond_signal(&(bdd_gv.n_running_threads_cond));
	}
	pthread_mutex_unlock(&(bdd_gv.n_running_threads_mutex));
	pthread_exit(NULL);
	return;
}
