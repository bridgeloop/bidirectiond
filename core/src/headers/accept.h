#ifndef bidirectiond_core__accept__h
#define bidirectiond_core__accept__h

#include <hashmap/hashmap.h>

enum bdd_cont {
	bdd_cont_discard,
	bdd_cont_inprogress,
	bdd_cont_established,
};

int bdd_alpn_cb(
	SSL *client_ssl,
	const unsigned char **out,
	unsigned char *outlen,
	const unsigned char *_,
	unsigned int __,
	struct bdd_conversation *conversation
);
int bdd_hello_cb(SSL *client_ssl, int *alert, struct bdd_conversation *conversation);
void *bdd_accept(void);

#endif
