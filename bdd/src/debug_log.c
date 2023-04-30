#if !defined(NDEBUG) && defined(BIDIRECTIOND_VERBOSE_DEBUG_LOG)
#include <openssl/ssl.h>
#include <pthread.h>
#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>

ssize_t bdd_vdl_SSL_write(void *x, char *data, size_t len) {
	printf("[send %zi] ----------\n", len);
	for (size_t idx = 0; idx < len; ++idx) {
		if (data[idx] >= 0x20 && data[idx] <= 0x7e && data[idx] != '\\') {
			putc(data[idx], stdout);
		} else {
			printf("\\x%02x", data[idx]);
		}
	}
	ssize_t v = SSL_write(x, data, len);
	printf("\n---------- [sent %zi]\n", v);
	return v;
}
ssize_t bdd_vdl_send(int a, char *b, size_t c, int _) {
	printf("[send %zu] ----------\n", c);
	for (size_t idx = 0; idx < c; ++idx) {
		if (b[idx] >= 0x20 && b[idx] <= 0x7e) {
			putc(b[idx], stdout);
		} else {
			printf("\\x%02x", b[idx]);
		}
	}
	ssize_t v = send(a, b, c, _);
	printf("\n---------- [sent %zi]\n", v);
	return v;
}
int bdd_vdl_pthread_mutex_lock(void *_, char *name, int ln) {
	printf("%p (%s) lock attempt @ %i!\n", _, name, ln);
	int x = pthread_mutex_lock(_);
	printf("%p (%s) lock @ %i!\n", _, name, ln);
	return x;
}
int bdd_vdl_pthread_mutex_trylock(void *_, char *name, int ln) {
	printf("%p (%s) lock attempt @ %i!\n", _, name, ln);
	int x = pthread_mutex_trylock(_);
	if (x == 0) {
		printf("%p (%s) lock @ %i!\n", _, name, ln);
	} else {
		printf("%p (%s) trylock failed @ %i!\n", _, name, ln);
	}
	return x;
}
int bdd_vdl_pthread_mutex_unlock(void *_, char *name, int ln) {
	int x = pthread_mutex_unlock(_);
	printf("%p (%s) unlock @ %i!\n", _, name, ln);
	return x;
}
int bdd_vdl_pthread_cond_wait(void *_, void *__, char *name, int ln) {
	printf("%p (%s) unlock @ %i!\n", _, name, ln);
	int x = pthread_cond_wait(_, __);
	printf("%p (%s) lock @ %i!\n", _, name, ln);
	return x;
}
#endif
