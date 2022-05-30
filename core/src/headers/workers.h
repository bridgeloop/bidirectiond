#ifndef bidirectiond_core__workers__h
#define bidirectiond_core__workers__h

#include <pthread.h>

struct bdd_conversation;
struct bdd_worker {
	unsigned short int id;
	pthread_mutex_t work_mutex;
	pthread_cond_t work_cond;
	struct bdd_coac *conversations;
	struct bdd_coac **conversations_appender;
};

void *bdd_worker(struct bdd_worker *worker);

#endif
