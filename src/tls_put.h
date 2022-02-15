#ifndef bidirectiond__tls_put__h
#define bidirectiond__tls_put__h

#include <stdbool.h>
#include <openssl/ssl.h>
#include <hashmap/hashmap.h>

bool tls_put(struct locked_hashmap *ns, SSL_CTX **ctx);

#endif
