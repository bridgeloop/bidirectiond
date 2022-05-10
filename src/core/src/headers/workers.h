#ifndef bidirectiond_core__workers__h
#define bidirectiond_core__workers__h

#include <pthread.h>

struct bdd_instance;
struct bdd_conversation;
struct bdd_worker {
	struct bdd_instance *const instance;
	unsigned short int id;
	pthread_mutex_t work_mutex;
	pthread_cond_t work_cond;
	struct bdd_conversation *conversations;
	struct bdd_conversation **conversations_appender;
};

void *bdd_worker(struct bdd_worker *worker);

#endif
