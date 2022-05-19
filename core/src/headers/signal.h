#ifndef bidirectiond_core__signal__h
#define bidirectiond_core__signal__h

#include "bdd_stop.h"

struct bdd_instance;

void bdd_signal(struct bdd_instance *instance);
void bdd_stop_accept(struct bdd_instance *instance);
void bdd_thread_exit(struct bdd_instance *instance);

#endif
