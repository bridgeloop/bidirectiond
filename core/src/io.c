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
			return &(conversation->soac.service);
		}
	}
	abort();
	return NULL;
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
		assert(false);
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
			bdd_io_internal_break(conversation, io);
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
			bdd_io_internal_break(conversation, io);
			return -1;
		}
		if (r == 0) {
			io->eof = 1;
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
	struct bdd_io *io = &(conversation->io_array[io_id]);
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
			bdd_io_internal_break_established(conversation, io);
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
			bdd_io_internal_break_established(conversation, io);
			return -1;
		}
	}
	return r;
}

enum bdd_cont bdd_ssl_shutdown_continue(struct bdd_io *io) {
	int fd = bdd_io_internal_fd(io);
	int r = SSL_shutdown(io->io.ssl);
	if (r < 0) {
		r = SSL_get_error(io->io.ssl, r);
		if (r == SSL_ERROR_WANT_WRITE) {
			return bdd_cont_inprogress;
		}
		if (r == SSL_ERROR_WANT_READ) {
			// hopefully impossible?
			// https://git.tcp.direct/aiden/bidirectiond/issues/33#issuecomment-363
			abort();
		}
		return bdd_cont_discard;
	}
	io->wrhup = 1;
	return bdd_cont_established;
}

bool bdd_io_shutdown(struct bdd_conversation *conversation, bdd_io_id io_id) {
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
		switch (bdd_io_internal_shutdown_continue(io)) {
			case (bdd_shutdown_err): {
				io->state = BDD_IO_ERR;
				return false;
			}
			case (bdd_shutdown_inprogress): {
				io->state = BDD_IO_SSL_SHUTTING;
				return true;
			}
			case (bdd_shutdown_success): {
				io->state = BDD_IO_RO;
				return true;
			}
		}
	} else {
		if (shutdown(bdd_internal_io_fd(io), SHUT_WR) == 0) {
			io->wrhup = 1;
			return true;
		}
		return false;
	}
}

void bdd_io_destroy(struct bdd_io *io, int epoll_fd) {
	if (!io->discarded) {
		if (epoll_fd < 0) {
			goto ssl;
		}
		int fd = bdd_io_fd(io);
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
void bdd_io_init(struct bdd_io *io) {
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
	SSL *ssl = SSL_new(bdd_gv.sv_ssl_ctx);
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

bool bdd_connect(struct bdd_conversation *conversation, struct sockaddr *sockaddr, socklen_t *addrlen) {
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
		bdd_io_apply_fd(io, fd);
	}
	return true;

	err:;
	if (io->ssl) {
		SSL_free(io->io.ssl);
	}
	if (fd >= 0) {
		close(fd);
	}
	bdd_io_init(io);
	conversation->state = bdd_conversation_accept;
	return false;
}
