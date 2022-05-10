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

#define BDD_IO_SSL_CONNECT_STATE_WANTS_CALL_ONCE_WRITABLE 1
#define BDD_IO_SSL_CONNECT_STATE_WANTS_CALL_ONCE_READABLE 2

#define BDD_IO_WAIT_DONT 0
#define BDD_IO_WAIT_FOR_ESTABLISHMENT 1
#define BDD_IO_WAIT_FOR_RDHUP 2

struct bdd_io {
	uint16_t
		state : 3,
		ssl_connecting_state : 1,

		ssl : 1,
		tcp : 1,
		shutdown : 1,

		wait : 2;
	union {
		int fd;
		SSL *ssl;
	} io;
};

#endif
