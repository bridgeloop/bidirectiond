#ifndef bidirectiond__debug_log__h
#define bidirectiond__debug_log__h

#ifdef NDEBUG

#define BDD_DEBUG_LOG(x...) (0)
#define BDD_CONVERSATION_AGE_MS(x...) (0)

#else

#include <stdio.h>
#include "conversations.h"
#include "timeout_list.h"
#define BDD_DEBUG_LOG(string, args...) (printf("[DEBUG] " string, ##args), fflush(stdout))
#define BDD_CONVERSATION_AGE_MS(conversation, string, args...) (printf("[DEBUG conversation %p age %zums] " string "\n", conversation, bdd_time() - conversation->spawn, ##args), fflush(stdout))
#ifdef BIDIRECTIOND_VERBOSE_DEBUG_LOG
ssize_t bdd_vdl_SSL_write(void *x, char *data, size_t len);
ssize_t bdd_vdl_send(int a, char *b, size_t c, int _);
#define SSL_write bdd_vdl_SSL_write
#define send bdd_vdl_send
int bdd_vdl_pthread_mutex_lock(void *_, char *name, int ln);
int bdd_vdl_pthread_mutex_unlock(void *_, char *name, int ln);
int bdd_vdl_pthread_cond_wait(void *_, void *__, char *name, int ln);
int bdd_vdl_pthread_mutex_trylock(void *_, char *name, int ln);
#define pthread_mutex_lock(x) bdd_vdl_pthread_mutex_lock(x, #x, __LINE__)
#define pthread_mutex_unlock(x) bdd_vdl_pthread_mutex_unlock(x, #x, __LINE__)
#define pthread_cond_wait(_, __) bdd_vdl_pthread_cond_wait(_, __, #__, __LINE__)
#define pthread_mutex_trylock(x) bdd_vdl_pthread_mutex_trylock(x, #x, __LINE__)
#endif

#endif

#endif
