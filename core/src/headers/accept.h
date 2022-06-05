#ifndef bidirectiond_core__accept__h
#define bidirectiond_core__accept__h

#include <hashmap/hashmap.h>
#include "bdd_cont.h"

struct bdd_conversation;
struct bdd_io;

int bdd_alpn_cb(
	SSL *client_ssl,
	const unsigned char **out,
	unsigned char *outlen,
	const unsigned char *_,
	unsigned int __,
	struct bdd_conversation *conversation
);
int bdd_hello_cb(SSL *client_ssl, int *alert, struct bdd_conversation *conversation);
struct bdd_worker_data;
void bdd_accept(struct bdd_worker_data *worker_data);
enum bdd_cont bdd_connect_continue(struct bdd_io *io);
enum bdd_cont bdd_accept_continue(struct bdd_conversation *conversation);

#endif
