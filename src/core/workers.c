#include "internal.h"
#include <signal.h>

void *bdd_worker(struct bdd_worker *worker) {
	struct bdd_instance *instance = worker->instance;
	struct bdd_workers *workers = &(instance->workers);
	
	pthread_sigmask(SIG_BLOCK, &(instance->sigmask), NULL);
	
	unsigned char *buf;
	size_t buf_sz = workers->buf_sz_per_worker;
	if (workers->buf == NULL) {
		buf = alloca(buf_sz);
	} else {
		buf = workers->buf + (worker->id * buf_sz);
	}
	
	bdd_worker__work:;
	if (workers->available_stack.ids != NULL) {
		pthread_mutex_lock(&(workers->available_stack.mutex));
		workers->available_stack.ids[--(workers->available_stack.idx)] = worker->id;
		pthread_cond_signal(&(workers->available_stack.cond));
		pthread_mutex_unlock(&(workers->available_stack.mutex));
	}
	BDD_DEBUG_LOG("thread accepting work\n");
	
	// await work
	pthread_mutex_lock(&(worker->work_mutex));
	while (worker->connections == NULL && !atomic_load(&(instance->exiting))) {
		pthread_cond_wait(&(worker->work_cond), &(worker->work_mutex));
	}
	BDD_DEBUG_LOG("thread received work!\n");
	
	if (unlikely(atomic_load(&(instance->exiting)))) {
		pthread_mutex_unlock(&(worker->work_mutex));
		bdd_thread_exit(instance);
	}
	
	struct bdd_connections *connections = worker->connections;
	worker->connections = connections->next;
	
	pthread_mutex_unlock(&(worker->work_mutex));
	
	assert(connections->service->serve != NULL);
	if (!connections->service->serve(connections, buf, buf_sz)) {
		connections->broken = true;
	}
	
	bdd_connections_link(instance, &(connections));
	
	goto bdd_worker__work;
}
