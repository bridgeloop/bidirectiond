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

typeof(BIDIRECTIOND_N_IO) bdd_io_id(struct bdd_io *io) {
	struct bdd_conversation *conversation = io->conversation;
	return (((char *)io - (char *)conversation->io_array) / sizeof(struct bdd_io));
}

struct bdd_io *bdd_io(struct bdd_conversation *conversation, typeof(BIDIRECTIOND_N_IO) io_id) {
	if (conversation == NULL || io_id >= BIDIRECTIOND_N_IO) {
		return NULL;
	}
	return &(conversation->io_array[io_id]);
}

int bdd_io_fd(struct bdd_io *io) {
	assert(io->state >= bdd_io_connecting);
	if (io->ssl) {
		return SSL_get_fd(io->io.ssl);
	} else {
		return io->io.fd;
	}
}

void bdd_io_epoll_mod(struct bdd_io *io, uint32_t remove_flags, uint32_t add_flags, bool edge_trigger) {
	uint32_t old_events = io->epoll_events;
	io->epoll_events &= ~remove_flags;
	if (io->rdhup) {
		add_flags &= ~EPOLLIN;
	}
	io->epoll_events |= add_events;
	if (io->edge_trigger) {
		io->epoll_events |= EPOLLET;
	} else {
		io->epoll_events &= ~EPOLLET;
	}
	#ifndef NDEBUG
	if (io->rdhup) {
		assert(!(io->epoll_events & EPOLLIN));
	}
	#endif
	if (io->in_epoll) {
		if (((old_events & ~EPOLLET) == 0) {
			if ((io->epoll_events & ~EPOLLET) != 0) {
				io->conversation->n_in_epoll_with_events += 1;
			}
		} else if ((io->epoll_events & ~EPOLLET) == 0) {
			io->conversation->n_in_epoll_with_events -= 1;
		}
		struct epoll_event ev = {
			.events = io->epoll_events,
			.data = { .ptr = io, },
		};
		epoll_ctl(io->conversation->epoll_fd, EPOLL_CTL_MOD, bdd_io_fd(io), NULL);
	}
	return;
}

void bdd_io_epoll_add(struct bdd_io *io) {
	if (io->in_epoll) {
		return;
	}
	io->in_epoll = 1;
	struct epoll_event ev = {
		.events = io->epoll_events,
		.data = { .ptr = io, },
	};
	epoll_ctl(io->conversation->epoll_fd, EPOLL_CTL_ADD, bdd_io_fd(io), NULL);
	if ((io->epoll_events & ~EPOLLET) != 0) {
		io->conversation->n_in_epoll_with_events += 1;
	}
	return;
}

void bdd_io_epoll_remove(struct bdd_io *io) {
	if (!io->in_epoll) {
		return;
	}
	io->in_epoll = 0;
	epoll_ctl(io->conversation->epoll_fd, EPOLL_CTL_DEL, bdd_io_fd(io), NULL);
	io->conversation->n_in_epoll_with_events -= 1;
	return;
}

bool bdd_io_hup(struct bdd_io *io, bool rdhup) {
	assert(io->state == bdd_io_est || io->state == bdd_io_ssl_shutting);
	if (rdhup) {
		io->rdhup = 1;
	} else {
		io->wrhup = 1;
	}
	return (io->rdhup && io->wrhup);
}

void bdd_io_state(struct bdd_io *io, enum bdd_io_state new_state) {
	struct bdd_conversation *conversation = io->conversation;
	enum bdd_io_state state = io->state;

	assert(state != new_state);

	if (state == bdd_io_connecting) {
		if (conversation->n_connecting) {
			for (typeof(BIDIRECTIOND_N_IO) idx = 0; idx <= conversation->n_servers; ++idx) {
				struct bdd_io *idx_io = bdd_io(idx);
				if (idx_io == io || (idx_io->state != bdd_io_est && idx_io->state != bdd_io_ssl_shutting)) {
					continue;
				}
				if (!io->rdhup) {
					bdd_io_epoll_mod(idx_io, 0, EPOLLIN, false);
				}
				if (io->state == bdd_io_est) {
					bdd_io_epoll_add(idx_io);
				}
			}
		}
		conversation->n_connecting -= 1;
	}

	io->state = new_state;

	if (new_state == bdd_io_connecting) {
		if (conversation->n_connecting == 0) {
			for (typeof(BIDIRECTIOND_N_IO) idx = 0; idx <= conversation->n_servers; ++idx) {
				struct bdd_io *idx_io = bdd_io(idx);
				if (idx_io == io || idx_io->state == bdd_io_connecting) {
					continue;
				}
				if (idx_io->state == bdd_io_ssl_shutting) {
					bdd_io_epoll_mod(idx_io, EPOLLIN, 0, false);
				} else {
					bdd_io_epoll_remove(idx_io);
				}
			}
		}
		conversation->n_connecting += 1;
		bdd_io_epoll_mod(idx_io, 0, EPOLLIN | EPOLLOUT, true);
		bdd_io_epoll_add(idx_io);
	} else if (new_state == bdd_io_est) {
		uint32_t epollin = EPOLLIN;
		if (io->rdhup) {
			epollin = 0;
		}
		bdd_io_epoll_mod(idx_io, EPOLLOUT, epollin, false);
		if (conversation->n_connecting == 0) {
			bdd_io_epoll_add(idx_io);
		} else {
			bdd_io_epoll_remove(idx_io);
		}
	} else if (new_state == bdd_io_ssl_shutting) {
		bdd_io_epoll_mod(idx_io, 0, EPOLLOUT, false);
		bdd_io_epoll_add(idx_io);
	} else {
		bdd_io_epoll_remove(idx_io);
	}

	return;
}

// returns the number of bytes read (where 0 is a possible value), returns -3 on rdhup, returns -2 if IO discarded, returns -1 on err,
__attribute__((warn_unused_result)) ssize_t bdd_io_read(
	struct bdd_conversation *conversation,
	typeof(BIDIRECTIOND_N_IO) io_id,
	void *buf,
	ssize_t sz
) {
	struct bdd_io *io = bdd_io(conversation, io_id);
	if (io == NULL || buf == NULL || sz <= 0 || conversation->n_connecting > 0) {
		fputs("programming error: bdd_io_read called with invalid arguments\n", stderr);
		abort();
		return -1;
	}
	if (io->state < bdd_io_est || io->rdhup) {
		fputs("programming error: bdd_io_read called with an io_id which is in an invalid state\n", stderr);
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
				if (bdd_io_set_hup(io, true)) {
					bdd_io_discard(io);
					return -2;
				}
				return -3;
			} else if (
				(
					err == SSL_ERROR_WANT_READ /* read all of the bytes and no close_notify received */ ||
					err == SSL_ERROR_NONE
				)
			) {
				return 0;
			}
			bdd_io_discard(io);
			return -2;
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
			bdd_io_discard(io);
			return -2;
		}
		if (r == 0) {
			if (bdd_io_set_hup(io, true)) {
				bdd_io_discard(io);
				return -2;
			}
			return -3;
		}
	}
	return r;
}

// returns the number of bytes written, returns -2 if IO discarded, returns -1 on err
__attribute__((warn_unused_result)) ssize_t bdd_io_write(
	struct bdd_conversation *conversation,
	typeof(BIDIRECTIOND_N_IO) io_id,
	void *buf,
	ssize_t sz
) {
	struct bdd_io *io = bdd_io(conversation, io_id);
	if (io == NULL || buf == NULL || sz <= 0 || conversation->n_connecting > 0) {
		fputs("programming error: bdd_io_write called with invalid arguments\n", stderr);
		abort();
		return -1;
	}
	if (io->state != bdd_io_est || io->wrhup) {
		fputs("programming error: bdd_io_write called with an io_id which is in an invalid state\n", stderr);
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
			} else if (err == SSL_ERROR_WANT_READ) {
				abort(); // fuck re-negotiation
			} else if (err == SSL_ERROR_WANT_WRITE) {
				bdd_io_epoll_mod(io, 0, EPOLLOUT, false);
				return 0;
			}
			if (bdd_io_set_hup(io, false)) {
				return -2;
			}
			return -1;
		}
	} else {
		r = send(io->io.fd, buf, sz, 0);
		if (r < 0) {
			if (errno == EINTR) {
				goto send;
			}
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				bdd_io_epoll_mod(io, 0, EPOLLOUT, false);
				return 0;
			}
			if (bdd_io_set_hup(io, false)) {
				return -2;
			}
			return -1;
		}
		if (r != sz) {
			bdd_io_epoll_mod(io, 0, EPOLLOUT, false);
		}
	}
	return r;
}

enum bdd_shutdown_status bdd_ssl_shutdown_continue(struct bdd_io *io) {
	int r = SSL_shutdown(io->io.ssl);
	if (r < 0) {
		r = SSL_get_error(io->io.ssl, r);
		if (r == SSL_ERROR_WANT_WRITE) {
			return bdd_shutdown_inprogress;
		}
		if (r == SSL_ERROR_WANT_READ) {
			// hopefully impossible?
			// https://git.tcp.direct/aiden/bidirectiond/issues/33#issuecomment-363
			abort();
		}
		// ungraceful shutdown
	}
	return bdd_shutdown_complete;
}

enum bdd_shutdown_status bdd_io_shutdown(struct bdd_conversation *conversation, typeof(BIDIRECTIOND_N_IO) io_id) {
	struct bdd_io *io = bdd_io(conversation, io_id);
	if (io == NULL) {
		fputs("programming error: bdd_io_shutdown called with invalid arguments\n", stderr);
		abort();
	}
	if (io->state != bdd_io_est || io->wrhup) {
		fputs("programming error: bdd_io_shutdown called with an io_id which is in an invalid state\n", stderr);
		abort();
	}

	if (io->ssl) {
		bdd_io_state(io, bdd_io_ssl_shutdown);
		if (bdd_io_shutdown_continue(io)): {
			case (bdd_shutdown_inprogress): {
				return bdd_shutdown_inprogress;
			}
		}
	} else {
		shutdown(bdd_io_fd(io), SHUT_WR);
	}
	if (bdd_io_hup(io, false)) {
		bdd_io_discard(io);
		return bdd_shutdown_discard;
	}
	if (io->ssl) {
		bdd_io_state(io, bdd_io_est);
	}
	return bdd_shutdown_complete;
}

void bdd_io_discard(struct bdd_io *io) {
	enum bdd_io_state state = io->state;
	if (state == bdd_io_unused) {
		return;
	}
	bdd_io_state(io, bdd_io_unused);
	if (state >= bdd_io_connecting) {
		int fd = bdd_io_fd(io);
		if (
			io->ssl &&
			io->rdhup &&
			io->wrhup &&
			(SSL_get_shutdown(io->io.ssl) & SSL_SENT_SHUT)
		) {
			SSL_shutdown(io->io.ssl);
			shutdown(fd, SHUT_WR);
		}
		close(fd);
	}
	if (io->ssl) {
		SSL_free(io->io.ssl);
	}
	return;
}

bool bdd_io_prep_ssl(struct bdd_conversation *conversation, typeof(BIDIRECTIOND_N_IO) io_id, char *ssl_name, char *alp) {
	struct bdd_io *io = bdd_io(conversation, io);
	if (io == NULL || io->state != bdd_io_obtained) {
		fputs("programming error: bdd_io_prep_ssl called with an io_id which is in an invalid state\n", stderr);
		abort();
	}
	SSL *ssl = SSL_new(bdd_gv.cl_ssl_ctx);
	if (ssl == NULL) {
		goto err;
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

	// configure the IO
	// **do not goto err after this point**
	io->ssl = 1;
	io->io.ssl = ssl;
	bdd_io_state(io, bdd_io_prepd_ssl);
	return true;

	err:;
	if (ssl != NULL) {
		SSL_free(ssl);
	}
	bdd_io_discard(io);
	return false;
}

enum bdd_cont bdd_io_connect(
	struct bdd_conversation *conversation,
	typeof(BIDIRECTIOND_N_IO) io_id,
	struct sockaddr *sockaddr,
	socklen_t addrlen
) {
	struct bdd_io *io = bdd_io(conversation, io);
	if (io == NULL || (io->state != bdd_io_obtained && io->state != bdd_io_prepd_ssl)) {
		fputs("programming error: bdd_io_connect called with an io_id which is in an invalid state\n", stderr);
		abort();
	}
	int fd = socket(sockaddr->sa_family, SOCK_STREAM | SOCK_NONBLOCK, 0);
	if (fd < 0) {
		goto err;
	}
	if (io->ssl) {
		if (SSL_set_fd(io->io.ssl, fd) != 1) {
			close(fd);
			goto err;
		}
	} else {
		io->io.fd = fd;
	}
	bdd_io_state(io, bdd_io_connecting);
	do {
		if (connect(fd, sockaddr, addrlen) == 0) {
			switch (bdd_connect_continue(io)) {
				case (bdd_cont_discard): {
					goto err;
				}
				case (bdd_cont_inprogress): {
					return bdd_cont_inprogress;
				}
				case (bdd_cont_established): {
					bdd_io_state(io, bdd_io_est);
					return bdd_cont_established;
				}
			}
		}
		if (errno == EINPROGRESS) {
			return bdd_cont_inprogress;
		}
	} while (errno == EINTR);

	err:;
	bdd_io_discard(io);
	return false;
}
