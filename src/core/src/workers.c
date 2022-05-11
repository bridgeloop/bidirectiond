#include <pthread.h>
#include <alloca.h>
#include <assert.h>
#include <stdatomic.h>

#include "headers/workers.h"
#include "headers/instance.h"
#include "headers/debug_log.h"
#include "headers/unlikely.h"
#include "headers/signal.h"
#include "headers/bdd_service.h"
#include "headers/conversations.h"

void *bdd_worker(struct bdd_worker *worker) {
	struct bdd_instance *instance = worker->instance;

	pthread_sigmask(SIG_BLOCK, &(instance->sigmask), NULL);

	unsigned char *buf = instance->workers_buf;
	size_t buf_sz = instance->buf_sz_per_worker;

	work:;
	if (instance->available_workers.ids != NULL) {
		pthread_mutex_lock(&(instance->available_workers.mutex));
		instance->available_workers.ids[--(instance->available_workers.idx)] = worker->id;
		pthread_cond_signal(&(instance->available_workers.cond));
		pthread_mutex_unlock(&(instance->available_workers.mutex));
	}
	BDD_DEBUG_LOG("thread accepting work\n");

	// await work
	pthread_mutex_lock(&(worker->work_mutex));
	while (worker->conversations == NULL && !atomic_load(&(instance->exiting))) {
		pthread_cond_wait(&(worker->work_cond), &(worker->work_mutex));
	}
	BDD_DEBUG_LOG("thread received work!\n");

	if (unlikely(atomic_load(&(instance->exiting)))) {
		pthread_mutex_unlock(&(worker->work_mutex));
		bdd_thread_exit(instance);
	}

	struct bdd_conversation *conversation = worker->conversations;
	worker->conversations = conversation->next;

	pthread_mutex_unlock(&(worker->work_mutex));

	assert(conversation->service->serve != NULL);
	if (!conversation->service->serve(conversation, buf, buf_sz)) {
		conversation->release = 1;
	}

	bdd_conversation_link(instance, &(conversation));

	goto work;
}
