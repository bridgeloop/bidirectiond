#ifndef bidirectiond_core__bdd_io__h
#define bidirectiond_core__bdd_io__h

#include <openssl/ssl.h>
#include <stdint.h>

enum bdd_io_state {
	bdd_io_unused,

	bdd_io_obtained,
	bdd_io_prepd_ssl,
	bdd_io_connecting, // will block the entire conversation

	// established //
	bdd_io_est,
	bdd_io_out, // est but with epollout rather than epollin
	bdd_io_ssl_shutting, // ssl shutdown in progress
};

struct bdd_io {
	struct bdd_conversation *conversation;

	enum bdd_io_state state;

	uint8_t
		rdhup : 1,
		wrhup : 1,

		ssl : 1,
		ssl_alpn : 1,

		in_epoll : 1;

	uint32_t epoll_events;

	union {
		int fd;
		SSL *ssl;
	} io;
};

#endif
