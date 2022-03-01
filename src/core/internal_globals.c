#include <openssl/ssl.h>
#include <stdatomic.h>
#include <stddef.h>
atomic_flag BDD_GLOBAL_MUTEX = ATOMIC_FLAG_INIT;
size_t BDD_GLOBAL_RC = 0;
SSL_CTX *BDD_GLOBAL_CL_SSL_CTX = NULL;
