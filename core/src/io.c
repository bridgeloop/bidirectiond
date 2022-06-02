#include <poll.h>
#include <sys/epoll.h>
#include <stdio.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <assert.h>
#include <unistd.h>
#include <fcntl.h>
#include <alloca.h>
#include <errno.h>

#include "headers/instance.h"
#include "headers/accept.h"
#include "headers/conversations.h"
#include "headers/bdd_service.h"
#include "headers/bdd_io.h"

uint8_t bdd_io_id(struct bdd_conversation *conversation, struct bdd_io *io) {
	if (io == &(conversation->client)) {
		return 0;
	}
	assert(conversation->state == bdd_conversation_established && io == &(conversation->soac.server));
	return 1;
}

struct bdd_io *bdd_io(struct bdd_conversation *conversation, uint8_t io_id) {
	if (conversation == NULL) {
		return NULL;
	}
	switch (io_id) {
		case (0): {
			return &(conversation->client);
		}
		case (1): {
			assert(conversation->state == bdd_conversation_established);
			return &(conversation->soac.server);
		}
	}
	abort();
	return NULL;
}
struct bdd_io *bdd_io_opposite(struct bdd_conversation *conversation, struct bdd_io *io) {
	uint8_t io_id = bdd_io_id(conversation, io);
	return bdd_io(conversation, io_id ^ 1);
}

// returns the number of bytes read, returns -2 on rdhup, returns -1 on err
__attribute__((warn_unused_result)) ssize_t bdd_io_read(
	struct bdd_conversation *conversation,
	uint8_t io_id,
	void *buf,
	ssize_t sz
) {
	struct bdd_io *io = bdd_io(conversation, io_id);
	if (io == NULL || buf == NULL || sz <= 0) {
		fputs("programming error: bdd_read called with invalid arguments\n", stderr);
		abort();
		return -1;
	}

	ssize_t r;
	recv:;
	if (io->ssl) {
		r = SSL_read(io->io.ssl, buf, sz);
		if (r <= 0) {
			int err = SSL_get_error(io->io.ssl, r);
			if (err == SSL_ERROR_SYSCALL) {
				if (errno == EINTR) {
					goto recv;
				}
				if (errno == 0) {
					return 0;
				}
			} else if (err == SSL_ERROR_WANT_WRITE) {
				abort(); // fuck re-negotiation
			} else if (err == SSL_ERROR_ZERO_RETURN /* received close_notify */) {
				io->rdhup = 1;
				return -2;
			} else if (
				(
					err == SSL_ERROR_WANT_READ /* read all of the bytes and no close_notify received */ ||
					err == SSL_ERROR_NONE
				)
			) {
				return 0;
			}
			io->state = BDD_IO_ERR;
			return -1;
		}
	} else {
		r = recv(io->io.fd, buf, sz, 0);
		if (r < 0) {
			if (errno == EINTR) {
				goto recv;
			}
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				return 0;
			}
			io->state = BDD_IO_ERR;
			return -1;
		}
		if (r == 0) {
			io->rdhup = 1;
			return -2;
		}
	}
	return r;
}

// returns the number of bytes written, returns -1 if shut_wr (ssl or not), returns -1 on err
__attribute__((warn_unused_result)) ssize_t bdd_io_write(
	struct bdd_conversation *conversation,
	uint8_t io_id,
	void *buf,
	ssize_t sz
) {
	struct bdd_io *io = bdd_io(conversation, io_id);
	if (io == NULL || buf == NULL || sz <= 0) {
		fputs("programming error: bdd_write called with invalid arguments\n", stderr);
		abort();
		return -1;
	}
	if (io->state != BDD_IO_RW) {
		fputs("programming error: bdd_write called with an io_id which is in a state not equal to BDD_IO_RW\n", stderr);
		abort();
		return -1;
	}

	ssize_t r;
	send:;
	if (io->ssl) {
		r = SSL_write(io->io.ssl, buf, sz);
		if (r <= 0) {
			int err = SSL_get_error(io->io.ssl, r);
			if (err == SSL_ERROR_SYSCALL) {
				if (errno == EINTR) {
					goto send;
				}
				if (errno == 0) {
					return 0;
				}
			} else if (err == SSL_ERROR_WANT_READ) {
				abort(); // fuck re-negotiation
			} else if (
				err == SSL_ERROR_WANT_WRITE ||
				err == SSL_ERROR_NONE
			) {
				return 0;
			}
			io->state = BDD_IO_RO;
			return -1;
		}
	} else {
		r = send(io->io.fd, buf, sz, 0);
		if (r < 0) {
			if (errno == EINTR) {
				goto send;
			}
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				return 0;
			}
			io->state = BDD_IO_RO;
			return -1;
		}
	}
	return r;
}

bool bdd_io_shutdown(struct bdd_conversation *conversation, uint8_t io_id) {
	struct bdd_io *io = bdd_io(conversation, io_id);
	if (io == NULL) {
		fputs("programming error: bdd_io_shutdown called with invalid arguments\n", stderr);
		abort();
		return false;
	}
	if (io->state != BDD_IO_RW) {
		fputs("programming error: bdd_io_shutdown called with an io_id which is in a state not equal to BDD_IO_RW\n", stderr);
		abort();
		return false;
	}
	io->state = BDD_IO_RO;

	if (io->ssl) {
		switch (bdd_ssl_shutdown_continue(io)) {
			case (bdd_cont_discard): {
				io->state = BDD_IO_ERR;
				return false;
			}
			case (bdd_cont_inprogress): {
				io->state = BDD_IO_SSL_SHUTTING;
				return true;
			}
			case (bdd_cont_established): {
				return true;
			}
		}
	} else {
		if (shutdown(bdd_io_internal_fd(io), SHUT_WR) == 0) {
			io->wrhup = 1;
			return true;
		}
		return false;
	}
}

void bdd_io_discard(struct bdd_io *io, int epoll_fd) {
	if (!io->discarded) {
		if (epoll_fd < 0) {
			goto ssl;
		}
		int fd = bdd_io_internal_fd(io);
		if (fd < 0) {
			io->discarded = 1;
			return;
		}
		if (io->in_epoll) {
			epoll_ctl(epoll_fd, EPOLL_CTL_DEL, fd, NULL);
		}
		if (
			io->ssl &&
			io->rdhup &&
			io->wrhup
		) {
			SSL_shutdown(io->io.ssl);
			shutdown(fd, SHUT_WR);
		}
		close(fd);
		ssl:;
		if (io->ssl) {
			SSL_free(io->io.ssl);
		}
		io->discarded = 1;
	}
	return;
}
void bdd_io_init(struct bdd_conversation *conversation, struct bdd_io *io) {
	io->conversation = conversation;

	io->state = BDD_IO_RW;

	io->rdhup = 0;
	io->wrhup = 0;

	io->ssl = 0;
	io->ssl_alpn = 0;

	io->discarded = 0;
	io->in_epoll = 0;


	io->io.fd = -1;


	return;
}
void bdd_io_apply(struct bdd_io *io, int fd) {
	io->io.fd = fd;
	return;
}
void bdd_io_apply_ssl(struct bdd_io *io, SSL *ssl) {
	io->ssl = 1;
	io->io.ssl = ssl;
	return;
}

bool bdd_prep_ssl(struct bdd_conversation *conversation, char *ssl_name, char *alp) {
	if (conversation->state != bdd_conversation_accept) {
		abort();
		return false;
	}
	struct bdd_io *io = &(conversation->soac.server);
	SSL *ssl = SSL_new(bdd_gv.cl_ssl_ctx);
	if (ssl == NULL) {
		return false;
	}

	// sni
	// SSL_set_tlsext_host_name *does* strdup: https://github.com/openssl/openssl/blob/cac250755efd0c40cc6127a0e4baceb8d226c7e3/ssl/s3_lib.c#L3502
	if (!SSL_set_tlsext_host_name(ssl, ssl_name)) {
		goto err;
	}
	// hostname vertification
	SSL_set_hostflags(ssl, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
	// does strdup: https://github.com/openssl/openssl/blob/1c0eede9827b0962f1d752fa4ab5d436fa039da4/crypto/x509/x509_vpm.c#L59
	if (!SSL_set1_host(ssl, ssl_name)) {
		goto err;
	}

	if (alp != NULL) {
		unsigned char *buf = alloca(256);
		buf[0] = 0;
		unsigned int buf_len = 1;
		while (*alp) {
			if (buf_len == 256) {
				abort();
			}
			buf[0] += 1;
			buf[buf_len++] = *(alp++);
		}
		if (SSL_set_alpn_protos(ssl, buf, buf_len) != 0) {
			goto err;
		}
		io->ssl_alpn = 1;
	}
	#ifndef BIDIRECTIOND_UNSAFE_TLS
	SSL_set_verify(ssl, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
	#endif

	conversation->state = bdd_conversation_ssl;
	bdd_io_apply_ssl(io, ssl);

	return true;

	err:;
	SSL_free(ssl);
	return false;
}

bool bdd_connect(struct bdd_conversation *conversation, int address_family, struct sockaddr *sockaddr, socklen_t addrlen) {
	if (conversation->state != bdd_conversation_accept && conversation->state != bdd_conversation_ssl) {
		abort();
		return false;
	}
	struct bdd_io *io = &(conversation->soac.server);
	int fd = socket(address_family, SOCK_STREAM | SOCK_NONBLOCK, 0);
	conversation->state = bdd_conversation_connect;
	connect:;
	if (connect(fd, sockaddr, addrlen) == 0) {
		goto success;
	}
	if (errno == EINTR) {
		goto connect;
	}
	if (errno != EINPROGRESS) {
		goto err;
	}

	success:;
	if (io->ssl) {
		if (SSL_set_fd(io->io.ssl, fd) != 1) {
			goto err;
		}
	} else {
		bdd_io_apply(io, fd);
	}
	return true;

	err:;
	if (io->ssl) {
		SSL_free(io->io.ssl);
	}
	if (fd >= 0) {
		close(fd);
	}
	bdd_io_init(conversation, io);
	conversation->state = bdd_conversation_accept;
	return false;
}
