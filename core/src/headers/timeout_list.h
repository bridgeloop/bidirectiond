#ifndef bidirectiond_core__timeout_list__h
#define bidirectiond_core__timeout_list__h

#include <pthread.h>
#include "conversations.h"

struct bdd_tl {
	struct bdd_conversation *head;
	struct bdd_conversation *tail;
};

void bdd_tl_unlink(struct bdd_tl *timeout_list, struct bdd_conversation *conversation);
void bdd_tl_link(struct bdd_tl *timeout_list, struct bdd_conversation *conversation);
void bdd_tl_process(struct bdd_tl *timeout_list, int epoll_fd);

void bdd_tl_init(struct bdd_tl *timeout_list);

#endif
