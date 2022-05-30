#include <pthread.h>
#include <assert.h>

#include "headers/instance.h"
#include "headers/serve.h"
#include "headers/coac.h"
#include "headers/signal.h"

// coac id //

int bdd_coac_id(struct bdd_coac *coac) {
	return (((char *)coac - (char *)(bdd_gv.coac)) / sizeof(struct bdd_coac));
}

// put a conversation coac into conversations_to_epoll //

void bdd_coac_link(struct bdd_coac **coac_ref) {
	assert(coac_ref != NULL);
	struct bdd_coac *coac = (*coac_ref);
	assert(coac != NULL);
	(*coac_ref) = NULL;
	pthread_mutex_lock(&(bdd_gv.conversations_to_epoll.mutex));
	coac->next = bdd_gv.conversations_to_epoll.head;
	bdd_gv.conversations_to_epoll.head = coac;
	bdd_signal();
	pthread_mutex_unlock(&(bdd_gv.conversations_to_epoll.mutex));
	return;
}

// safely obtain and release coac //

struct bdd_coac *bdd_coac_obtain(void) {
	struct bdd_coac *coac = NULL;
	pthread_mutex_lock(&(bdd_gv.available_coac.mutex));
	while (!atomic_load(&(bdd_gv.exiting)) && bdd_gv.available_coac.idx == bdd_gv.n_coac) {
		pthread_cond_wait(&(bdd_gv.available_coac.cond), &(bdd_gv.available_coac.mutex));
	}
	if (!atomic_load(&(bdd_gv.exiting))) {
		int id = bdd_gv.available_coac.ids[bdd_gv.available_coac.idx++];
		coac = &(bdd_gv.coac[id]);
	}
	pthread_mutex_unlock(&(bdd_gv.available_coac.mutex));
	return coac;
}
void bdd_coac_release(struct bdd_coac **coac_ref) {
	assert(coac_ref != NULL);

	struct bdd_coac *coac = *coac_ref;
	assert(coac != NULL);
	(*coac_ref) = NULL;

	coac->inner_type = bdd_coac_none;

	pthread_mutex_lock(&(bdd_gv.available_coac.mutex));

	assert(bdd_gv.available_coac.idx != 0);

	int id = bdd_coac_id(coac);

	assert(id >= 0 && id < bdd_gv.n_coac);

	bdd_gv.available_coac.ids[--(bdd_gv.available_coac.idx)] = id;

	pthread_cond_signal(&(bdd_gv.available_coac.cond));
	pthread_mutex_unlock(&(bdd_gv.available_coac.mutex));

	return;
}
