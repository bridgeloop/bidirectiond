#ifndef bidirectiond_core__bdd_pthread_init__h
#define bidirectiond_core__bdd_pthread_init__h

#include <pthread.h>

void bdd_mutex_preinit(pthread_mutex_t *dest);
void bdd_cond_preinit(pthread_cond_t *dest);

#endif
