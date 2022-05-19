#ifndef bidirectiond_core__internal_globals__h
#define bidirectiond_core__internal_globals__h

#include <stddef.h>
#include <stdatomic.h>
#include <openssl/ssl.h>

extern atomic_flag BDD_GLOBAL_MUTEX;
extern size_t BDD_GLOBAL_RC;
extern SSL_CTX *BDD_GLOBAL_CL_SSL_CTX;

#endif
