#include <openssl/ssl.h>
#include <stdatomic.h>
#include <stddef.h>
#include <string.h>

void bdd_mutex_preinit(pthread_mutex_t *dest) {
	static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
	memcpy(dest, &(mutex), sizeof(pthread_mutex_t));
}

void bdd_cond_preinit(pthread_cond_t *dest) {
	static pthread_cond_t mutex = PTHREAD_COND_INITIALIZER;
	memcpy(dest, &(mutex), sizeof(pthread_cond_t));
}
