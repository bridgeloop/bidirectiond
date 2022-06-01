#ifndef bidirectiond_core__serve__h
#define bidirectiond_core__serve__h

#include "timeout_list.h"

struct bdd_worker_data {
	int epoll_fd;
	SSL_CTX *ssl_ctx;
	struct bdd_tl *timeout_list;
};
void *bdd_serve(struct bdd_worker_data *worker_data);

#endif
