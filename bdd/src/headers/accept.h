#ifndef bidirectiond__accept__h
#define bidirectiond__accept__h

#include "bdd_cont.h"

struct bdd_conversation;
struct bdd_io;

struct bdd_ssl_cb_ctx;
int bdd_alpn_cb(
	SSL *client_ssl,
	const unsigned char **out,
	unsigned char *outlen,
	const unsigned char *_,
	unsigned int __,
	void *___
);
struct bdd_worker_data;
int bdd_hello_cb(SSL *client_ssl, int *alert, void *_);
void bdd_accept(SSL_CTX *ssl_ctx);
enum bdd_cont bdd_connect_continue(struct bdd_io *io);
enum bdd_cont bdd_accept_continue(SSL_CTX *ssl_ctx);

#endif
