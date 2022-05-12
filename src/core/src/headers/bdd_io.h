#ifndef bidirectiond_core__bdd_io__h
#define bidirectiond_core__bdd_io__h

#include <openssl/ssl.h>
#include <stdint.h>

#define BDD_IO_STATE_UNUSED 0
#define BDD_IO_STATE_CREATED 1
#define BDD_IO_STATE_CONNECTING 2
#define BDD_IO_STATE_SSL_CONNECTING 3
#define BDD_IO_STATE_ESTABLISHED 4
#define BDD_IO_STATE_BROKEN 5

#define BDD_IO_CONNECTING_SUBSTATE_AGAIN 0
#define BDD_IO_CONNECTING_SUBSTATE_IN_PROGRESS 1

#define BDD_IO_SSL_CONNECTING_SUBSTATE_WANTS_READ 0
#define BDD_IO_SSL_CONNECTING_SUBSTATE_WANTS_WRITE 1

struct bdd_io {
	uint16_t
		state : 3,
		substate : 1,

		tcp : 1,
		shut_wr : 1,
		ssl : 1,
		ssl_shut : 1,

		wait : 2,

		in_epoll : 1;
	union {
		int fd;
		SSL *ssl;
	} io;
};

#endif
