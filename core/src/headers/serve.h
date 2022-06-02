#ifndef bidirectiond_core__serve__h
#define bidirectiond_core__serve__h

#include <sys/epoll.h>

#include "timeout_list.h"

struct bdd_worker_data {
	int epoll_fd;
	int serve_fd;
	SSL_CTX *ssl_ctx;
	struct bdd_tl timeout_list;
	struct epoll_event events[];
};
void *bdd_serve(struct bdd_worker_data *worker_data);

#endif
