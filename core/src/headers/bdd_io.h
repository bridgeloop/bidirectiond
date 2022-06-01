#ifndef bidirectiond_core__bdd_io__h
#define bidirectiond_core__bdd_io__h

#include <openssl/ssl.h>
#include <stdint.h>

#define BDD_IO_RW 0
#define BDD_IO_SSL_SHUTTING 1
#define BDD_IO_RO 2
#define BDD_IO_ERR 3

struct bdd_io {
	struct bdd_conversation *conversation;

	uint8_t
		state : 2,

		rdhup : 1,
		wrhup : 1,

		ssl : 1,
		ssl_alpn : 1,

		discarded : 1,
		in_epoll : 1;

	union {
		int fd;
		SSL *ssl;
	} io;
};

#endif
