#ifndef bidirectiond_core__accept__h
#define bidirectiond_core__accept__h

#include <hashmap/hashmap.h>

struct bdd_instance;
struct bdd_service_instance;
struct bdd_accept_ctx {
	struct bdd_service_instance *service_instance;
	const unsigned char *protocol_name;
	const char *cstr_protocol_name;
	struct locked_hashmap *locked_name_descriptions;
};

int bdd_hello_cb(SSL *client_ssl, int *alert, struct bdd_accept_ctx *ctx);
void *bdd_accept(struct bdd_instance *instance);

#endif
