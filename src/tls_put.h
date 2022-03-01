#ifndef bidirectiond__tls_put__h
#define bidirectiond__tls_put__h

#include <hashmap/hashmap.h>
#include <openssl/ssl.h>
#include <stdbool.h>

bool tls_put(struct locked_hashmap *ns, SSL_CTX **ctx);

#endif
