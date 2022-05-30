#include <pthread.h>
#include <alloca.h>
#include <assert.h>
#include <stdatomic.h>

#include "headers/workers.h"
#include "headers/bdd_io.h"
#include "headers/instance.h"
#include "headers/coac.h"
#include "headers/debug_log.h"
#include "headers/unlikely.h"
#include "headers/signal.h"
#include "headers/bdd_service.h"
#include "headers/conversations.h"

void *bdd_worker(struct bdd_worker *worker) {
	pthread_sigmask(SIG_BLOCK, &(bdd_gv.sigmask), NULL);

	work:;
	if (bdd_gv.available_workers.ids != NULL) {
		pthread_mutex_lock(&(bdd_gv.available_workers.mutex));
		bdd_gv.available_workers.ids[--(bdd_gv.available_workers.idx)] = worker->id;
		pthread_cond_signal(&(bdd_gv.available_workers.cond));
		pthread_mutex_unlock(&(bdd_gv.available_workers.mutex));
	}
	BDD_DEBUG_LOG("thread accepting work\n");

	// await work
	pthread_mutex_lock(&(worker->work_mutex));
	while (worker->conversations == NULL && !atomic_load(&(bdd_gv.exiting))) {
		pthread_cond_wait(&(worker->work_cond), &(worker->work_mutex));
	}
	BDD_DEBUG_LOG("thread received work!\n");

	if (unlikely(atomic_load(&(bdd_gv.exiting)))) {
		pthread_mutex_unlock(&(worker->work_mutex));
		bdd_thread_exit();
	}

	struct bdd_coac *coac = worker->conversations;
	worker->conversations = coac->next;

	pthread_mutex_unlock(&(worker->work_mutex));

	struct bdd_conversation *conversation = &(coac->inner.conversation);

	assert(conversation->service->handle_events != NULL);
	conversation->service->handle_events(
		conversation
	);

	bdd_coac_link(&(coac));

	goto work;
}
