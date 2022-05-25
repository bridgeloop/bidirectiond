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
#define BDD_IO_STATE_ESTABLISHED_BROKEN 7

struct bdd_io {
	uint16_t
		state : 3,
		shutdown_called : 1,

		tcp : 1,
		shutdown_complete : 1,
		ssl : 1,
		ssl_alpn : 1,
		ssl_shutdown_fully : 1,

		in_epoll : 1,

		eof : 1,
		no_epoll : 1, // no futher events

		listen_read : 1, // EPOLLIN|EPOLLRDHUP
		listen_write : 1; // EPOLLOUT

	union {
		int fd;
		SSL *ssl;
	} io;
};

#endif
