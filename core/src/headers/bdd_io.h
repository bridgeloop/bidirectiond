#ifndef bidirectiond_core__bdd_io__h
#define bidirectiond_core__bdd_io__h

#include <openssl/ssl.h>
#include <stdint.h>

#define BDD_IO_STATE_UNUSED 0
#define BDD_IO_STATE_CREATED 1
#define BDD_IO_STATE_CONNECT 2
#define BDD_IO_STATE_CONNECTING 3
#define BDD_IO_STATE_SSL_CONNECTING 4
#define BDD_IO_STATE_ESTABLISHED 5
#define BDD_IO_STATE_BROKEN 6

struct bdd_io {
	short int epoll_events;

	uint16_t
		state : 3,

		tcp : 1,
		shut_wr : 1,
		ssl : 1,
		ssl_shut : 2,

		in_epoll : 1,
		no_epoll : 1,
		hup : 1,
		rdhup : 1;

	union {
		int fd;
		SSL *ssl;
	} io;
};

#endif
