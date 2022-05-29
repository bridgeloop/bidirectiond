#include <pthread.h>
#include <assert.h>

#include "headers/instance.h"
#include "headers/coac.h"
#include "headers/signal.h"

// coac id //

int bdd_coac_id(struct bdd_instance *instance, struct bdd_coac *coac) {
	return (((char *)coac - (char *)(instance->coac)) / sizeof(struct bdd_coac));
}

// put a conversation coac into conversations_to_epoll //

void bdd_coac_link(struct bdd_instance *instance, struct bdd_coac **coac_ref) {
	assert(coac_ref != NULL);
	struct bdd_coac *coac = (*coac_ref);
	assert(coac != NULL);
	(*coac_ref) = NULL;
	pthread_mutex_lock(&(instance->conversations_to_epoll.mutex));
	coac->next = instance->conversations_to_epoll.head;
	instance->conversations_to_epoll.head = coac;
	bdd_signal(instance);
	pthread_mutex_unlock(&(instance->conversations_to_epoll.mutex));
	return;
}

// safely obtain and release coac //

struct bdd_coac *bdd_coac_obtain(struct bdd_instance *instance) {
	struct bdd_coac *coac = NULL;
	pthread_mutex_lock(&(instance->available_coac.mutex));
	while (!atomic_load(&(instance->exiting)) && instance->available_coac.idx == instance->n_coac) {
		pthread_cond_wait(&(instance->available_coac.cond), &(instance->available_coac.mutex));
	}
	if (!atomic_load(&(instance->exiting))) {
		int id = instance->available_coac.ids[instance->available_coac.idx++];
		coac = &(instance->coac[id]);
	}
	pthread_mutex_unlock(&(instance->available_coac.mutex));
	return coac;
}
void bdd_coac_release(struct bdd_instance *instance, struct bdd_coac **coac_ref) {
	assert(coac_ref != NULL);

	struct bdd_coac *coac = *coac_ref;
	assert(coac != NULL);
	(*coac_ref) = NULL;

	coac->inner_type = bdd_coac_none;

	pthread_mutex_lock(&(instance->available_coac.mutex));

	assert(instance->available_coac.idx != 0);

	int id = bdd_coac_id(instance, coac);

	assert(id >= 0 && id < instance->n_coac);

	instance->available_coac.ids[--(instance->available_coac.idx)] = id;

	pthread_cond_signal(&(instance->available_coac.cond));
	pthread_mutex_unlock(&(instance->available_coac.mutex));

	return;
}
