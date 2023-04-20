#ifndef bidirectiond__serve__h
#define bidirectiond__serve__h

#include <sys/epoll.h>

#include "timeout_list.h"

struct hashmap_area;
struct bdd_conversation;
struct bdd_ssl_cb_ctx {
	struct hashmap_area *area;
	struct bdd_conversation *conversation;
	const unsigned char *protocol_name;
	const char *cstr_protocol_name;
};
struct bdd_worker_data {
	int epoll_fd;
	int serve_fd;
	SSL_CTX *ssl_ctx;
	struct bdd_ssl_cb_ctx ssl_cb_ctx;
	struct bdd_tl timeout_list;
	struct epoll_event events[];
};
void *bdd_serve(struct bdd_worker_data *worker_data);

#endif
