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
#include "headers/bdd_poll_io.h"
#include "headers/bdd_io.h"
#include "headers/bdd_io_connect.h"
#include "headers/bdd_io_shutdown.h"
#include "headers/internal_globals.h"

uint8_t bdd_io_state(struct bdd_io *io) {
	return io->state;
}
void bdd_io_set_state(struct bdd_io *io, uint8_t state) {
	assert(
		state == BDD_IO_STATE_UNUSED ||
		state == BDD_IO_STATE_CREATED ||
		state == BDD_IO_STATE_CONNECT ||
		state == BDD_IO_STATE_CONNECTING ||
		state == BDD_IO_STATE_SSL_CONNECTING ||
		state == BDD_IO_STATE_ESTABLISHED ||
		(state == BDD_IO_STATE_BROKEN && (
			io->state == BDD_IO_STATE_CREATED ||
			io->state == BDD_IO_STATE_CONNECT||
			io->state == BDD_IO_STATE_CONNECTING ||
			io->state == BDD_IO_STATE_SSL_CONNECTING ||
			io->state == BDD_IO_STATE_ESTABLISHED
		))
	);
	#ifndef NDEBUG
	if (io->state == BDD_IO_STATE_BROKEN) {
		assert(state == BDD_IO_STATE_UNUSED);
	}
	#endif
	io->state = state;
	return;
}
int bdd_io_fd(struct bdd_io *io) {
	assert(
		io->state == BDD_IO_STATE_CREATED ||
		io->state == BDD_IO_STATE_CONNECT ||
		io->state == BDD_IO_STATE_CONNECTING ||
		io->state == BDD_IO_STATE_SSL_CONNECTING ||
		io->state == BDD_IO_STATE_ESTABLISHED ||
		io->state == BDD_IO_STATE_BROKEN
	);
	if (io->ssl) {
		return SSL_get_fd(io->io.ssl);
	} else {
		return io->io.fd;
	}
}
bool bdd_io_has_epoll_state(struct bdd_io *io) {
	return (
		bdd_io_state(io) == BDD_IO_STATE_CONNECTING ||
		bdd_io_state(io) == BDD_IO_STATE_SSL_CONNECTING ||
		bdd_io_state(io) == BDD_IO_STATE_ESTABLISHED
	);
}

int bdd_poll(struct bdd_conversation *conversation, struct bdd_poll_io *poll_io, bdd_io_id n_poll_io, int timeout) {
	if (conversation == NULL || poll_io == NULL || n_poll_io == 0) {
		fputs("programming error: bdd_poll called with invalid arguments\n", stderr);
		assert(false);
		return -1;
	}
	struct pollfd *pollfds;
	bool heap;
	if (n_poll_io <= 0x7f) {
		pollfds = alloca(n_poll_io * sizeof(struct pollfd));
		heap = false;
	} else {
		pollfds = malloc(n_poll_io * sizeof(struct pollfd));
		if (pollfds == NULL) {
			fputs("bdd_poll malloc failed\n", stderr);
			return -1;
		}
		heap = true;
	}
	int n_revents = -1;
	for (
		bdd_io_id idx = 0;
		idx < n_poll_io;
		++idx
	) {
		bdd_io_id io_id = poll_io[idx].io_id;
		if (io_id == BDD_IO_ID_NVAL) {
			pollfds[idx].fd = -1;
			pollfds[idx].events = 0;
			continue;
		}
		if (io_id < 0 || io_id >= bdd_conversation_n_max_io(conversation)) {
			fputs("programming error: bdd_poll called with an out-of-bounds io_id\n", stderr);
			assert(false);
			goto out;
		}
		struct bdd_io *io = &(conversation->io_array[io_id]);
		switch (bdd_io_state(io)) {
			case (BDD_IO_STATE_CONNECTING):
			case (BDD_IO_STATE_SSL_CONNECTING):
			case (BDD_IO_STATE_ESTABLISHED): {
				break;
			}

			default: {
				fputs("programming error: bdd_poll called with an io_id which is in an invalid state\n", stderr);
				assert(false);
				goto out;
			}
		}
		pollfds[idx].fd = bdd_io_fd(io);
		if (io->ssl) {
			if (SSL_has_pending(io->io.ssl)) {
				timeout = 0;
			}
		}
		pollfds[idx].events = poll_io[idx].events;
		pollfds[idx].revents = 0;
	}
	n_revents = poll(pollfds, n_poll_io, timeout);
	if (n_revents < 0) {
		goto out;
	}
	for (
		bdd_io_id idx = 0;
		idx < n_poll_io;
		++idx
	) {
		bdd_io_id io_id = poll_io[idx].io_id;
		if (io_id == BDD_IO_ID_NVAL) {
			continue;
		}
		struct bdd_io *io = &(conversation->io_array[io_id]);
		if (io->ssl && (poll_io[idx].events & POLLIN)) {
			if (SSL_has_pending(io->io.ssl)) {
				if (pollfds[idx].revents == 0) {
					n_revents += 1;
				}
				pollfds[idx].revents |= POLLIN;
			}
		}
		poll_io[idx].revents = pollfds[idx].revents;

	}
	out:;
	if (heap) {
		free(pollfds);
	}
	return n_revents;
}

// returns the number of bytes read, returns 0 on rdhup, returns -1 on err
__attribute__((warn_unused_result)) ssize_t bdd_read(
	struct bdd_conversation *conversation,
	bdd_io_id io_id,
	void *buf,
	ssize_t sz
) {
	if (conversation == NULL || io_id < 0 || io_id >= bdd_conversation_n_max_io(conversation) || buf == NULL) {
		fputs("programming error: bdd_read called with invalid arguments\n", stderr);
		assert(false);
		return -1;
	}
	struct bdd_io *io = &(conversation->io_array[io_id]);
	if (bdd_io_state(io) != BDD_IO_STATE_ESTABLISHED) {
		fputs("programming error: bdd_read called with an io_id which is in a state not equal to BDD_IO_STATE_ESTABLISHED\n", stderr);
		assert(false);
		return -1;
	}
	if (sz <= 0) {
		return 0;
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
			} else if (
				(
					err == SSL_ERROR_WANT_READ /* read all of the bytes and no rdhup */ ||
					err == SSL_ERROR_NONE ||
					err == SSL_ERROR_ZERO_RETURN /* received close_notify */
				)
			) {
				return 0;
			}
			bdd_io_set_state(io, BDD_IO_STATE_BROKEN);
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
			bdd_io_set_state(io, BDD_IO_STATE_BROKEN);
			return -1;
		}
	}
	return r;
}

// returns the number of bytes written, returns -1 if shut_wr (ssl or not), returns -1 on err
__attribute__((warn_unused_result)) ssize_t bdd_write(
	struct bdd_conversation *conversation,
	bdd_io_id io_id,
	void *buf,
	ssize_t sz
) {
	if (conversation == NULL || io_id < 0 || io_id >= bdd_conversation_n_max_io(conversation) || buf == NULL) {
		fputs("programming error: bdd_write called with invalid arguments\n", stderr);
		assert(false);
		return -1;
	}
	struct bdd_io *io = &(conversation->io_array[io_id]);
	if (bdd_io_state(io) != BDD_IO_STATE_ESTABLISHED) {
		fputs("programming error: bdd_write called with an io_id which is in a state not equal to BDD_IO_STATE_ESTABLISHED\n", stderr);
		assert(false);
		return -1;
	}
	if (sz <= 0) {
		return 0;
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
			bdd_io_set_state(io, BDD_IO_STATE_BROKEN);
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
			bdd_io_set_state(io, BDD_IO_STATE_BROKEN);
			return -1;
		}
	}
	return r;
}

// thread-unsafe
bool bdd_io_create(
	struct bdd_conversation *conversation,
	bdd_io_id *io_id,
	int domain,
	int type,
	int protocol
) {
	if (conversation == NULL || io_id == NULL) {
		fputs("programming error: bdd_io_create called with invalid arguments\n", stderr);
		assert(false);
		return false;
	}
	struct bdd_io *io = NULL;
	bdd_io_id idx = 0;
	for (; idx < bdd_conversation_n_max_io(conversation); ++idx) {
		io = &(conversation->io_array[idx]);
		if (io->state == BDD_IO_STATE_UNUSED) {
			goto found;
		}
	}
	fputs("programming error: bdd_io_create could not find an unused bdd_io\n", stderr);
	assert(false);
	return false;

	found:;

	int fd = socket(domain, type, protocol);
	if (fd < 0) {
		return false;
	}
	io->epoll_events = EPOLLIN | EPOLLRDHUP;
	bdd_io_set_state(io, BDD_IO_STATE_CREATED);
	io->tcp = (type & ~(SOCK_NONBLOCK | SOCK_CLOEXEC)) == SOCK_STREAM ? 1 : 0;
	io->shut_wr = 0;
	io->ssl = 0;
	io->ssl_alpn = 0;
	io->ssl_shut = 0;
	io->in_epoll = 0;
	io->no_epoll = 0;
	io->hup = 0;
	io->rdhup = 0;
	io->io.fd = fd;
	(*io_id) = idx;
	return true;
}

bool bdd_io_prep_ssl(struct bdd_conversation *conversation, bdd_io_id io_id, char *ssl_name, char *alp) {
	SSL *ssl = NULL;
	const char *err = NULL;
	if (conversation == NULL || io_id < 0 || io_id >= bdd_conversation_n_max_io(conversation) || ssl_name == NULL) {
		err = "programming error: bdd_io_prep_ssl called with invalid arguments\n";
		goto err;
	}
	struct bdd_io *io = &(conversation->io_array[io_id]);
	if (bdd_io_state(io) != BDD_IO_STATE_CREATED) {
		err = "programming error: bdd_io_prep_ssl called with an io_id which is in a state not equal to BDD_IO_STATE_CREATED\n";
		goto err;
	}
	if (!io->tcp) {
		err = "programming error: bdd_io_prep_ssl called with an io_id which does not use tcp\n";
		goto err;
	}
	if (io->ssl) {
		err = "programming error: bdd_io_prep_ssl called with an io_id which already has ssl prepared\n";
		goto err;
	}

	ssl = SSL_new(BDD_GLOBAL_CL_SSL_CTX);
	if (ssl == NULL) {
		goto err;
	}
	SSL_set_fd(ssl, io->io.fd);
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
		unsigned char *buf = alloca(255);
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
	SSL_set_verify(ssl, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);

	io->ssl = 1;
	io->io.ssl = ssl;

	return true;

	err:;
	if (ssl != NULL) {
		SSL_free(ssl);
	}
	if (err != NULL) {
		fputs(err, stderr);
	}
	assert(false);
	return false;
}

enum bdd_io_connect_status bdd_io_connect(struct bdd_conversation *conversation, bdd_io_id io_id, struct sockaddr *addr, socklen_t addrlen) {
	const char *err = NULL;
	if (conversation == NULL || io_id < 0 || io_id >= bdd_conversation_n_max_io(conversation)) {
		err = "programming error: bdd_io_connect called with invalid arguments\n";
		goto err;
	}
	struct bdd_io *io = &(conversation->io_array[io_id]);

	switch (bdd_io_state(io)) {
		case (BDD_IO_STATE_CREATED): case (BDD_IO_STATE_CONNECT): {
			if (addr == NULL || addrlen == 0) {
				err = "programming error: bdd_io_connect called with invalid arguments\n";
				goto err;
			}
			while (connect(bdd_io_fd(io), addr, addrlen) != 0) {
				if (errno == EAGAIN) {
					bdd_io_set_state(io, BDD_IO_STATE_CONNECT);
					return bdd_io_connect_again;
				} else if (errno == EINPROGRESS) {
					bdd_io_set_state(io, BDD_IO_STATE_CONNECTING);
					return bdd_io_connect_wants_write;
				} else if (errno != EINTR) {
					// failed to connect
					bdd_io_set_state(io, BDD_IO_STATE_BROKEN);
					goto err;
				}
			}
			goto connected;
		}

		case (BDD_IO_STATE_CONNECTING): {
			struct pollfd pollfd = {
				.fd = bdd_io_fd(io),
				.events = POLLOUT,
				.revents = 0,
			};
			poll(&(pollfd), 1, 0);
			if (!(pollfd.revents & POLLOUT)) {
				if (pollfd.revents & POLLERR) {
					bdd_io_set_state(io, BDD_IO_STATE_BROKEN);
					goto err;
				}
				return bdd_io_connect_wants_write;
			}

			connected:;

			if (!io->ssl) {
				bdd_io_set_state(io, BDD_IO_STATE_ESTABLISHED);
				return bdd_io_connect_established;
			}

			bdd_io_set_state(io, BDD_IO_STATE_SSL_CONNECTING);
		}

		case (BDD_IO_STATE_SSL_CONNECTING): {
			int r = SSL_connect(io->io.ssl);
			if (r == -1) {
				int err = SSL_get_error(io->io.ssl, r);
				if (err == SSL_ERROR_WANT_WRITE) {
					return bdd_io_connect_wants_write;
				}
				if (err == SSL_ERROR_WANT_READ) {
					return bdd_io_connect_wants_read;
				}
				r = 0;
			}
			if (r == 0) {
				bdd_io_set_state(io, BDD_IO_STATE_BROKEN);
				goto err;
			}

			const unsigned char *alpn;
			unsigned int alpn_sz = 0;
			if (io->ssl_alpn) {
				SSL_get0_alpn_selected(io->io.ssl, &(alpn), &(alpn_sz));
				if (alpn == NULL) {
					bdd_io_set_state(io, BDD_IO_STATE_BROKEN);
					goto err;
				}
			}

			bdd_io_set_state(io, BDD_IO_STATE_ESTABLISHED);
			return bdd_io_connect_established;
		}

		default: {
			err = "programming error: bdd_io_connect called with an io_id which is in an invalid state\n";
		}
	}

	err:;
	if (err != NULL) {
		fputs(err, stderr);
		assert(false);
	}
	return bdd_io_connect_err;
}

enum bdd_io_shutdown_state bdd_io_shutdown(struct bdd_conversation *conversation, bdd_io_id io_id) {
	const char *err = NULL;
	if (conversation == NULL || io_id < 0 || io_id >= bdd_conversation_n_max_io(conversation)) {
		err = "programming error: bdd_io_shutdown called with invalid arguments\n";
		goto err;
	}
	struct bdd_io *io = &(conversation->io_array[io_id]);
	if (bdd_io_state(io) != BDD_IO_STATE_SSL_CONNECTING && bdd_io_state(io) != BDD_IO_STATE_ESTABLISHED || !io->tcp) {
		err = "programming error: bdd_io_shutdown called with an io_id which is in an invalid state\n";
		goto err;
	}
	if (
		(io->ssl && io->ssl_shut == 2) ||
		(!io->ssl && io->shut_wr)
	) {
		err = "programming error: bdd_io_shutdown called with an io_id which has already been shut-down\n";
		goto err;
	}
	int fd = bdd_io_fd(io);
	if (io->ssl && bdd_io_state(io) == BDD_IO_STATE_ESTABLISHED) {
		int r = SSL_shutdown(io->io.ssl);
		if (!io->shut_wr) {
			shutdown(fd, SHUT_WR);
			io->shut_wr = 1;
		}
		if (r == 0) {
			io->ssl_shut = 1;
			return bdd_io_shutdown_again;
		} else if (r < 0) {
			r = SSL_get_error(io->io.ssl, r);
			if (r == SSL_ERROR_WANT_WRITE) {
				return bdd_io_shutdown_wants_write;
			}
			if (r == SSL_ERROR_WANT_READ) {
				return bdd_io_shutdown_wants_read;
			}
			goto err;
		} else {
			io->ssl_shut = 2;
		}
	} else {
		shutdown(fd, SHUT_WR);
		io->shut_wr = 1;
	}
	return bdd_io_shutdown_success;

	err:;
	if (err != NULL) {
		fputs(err, stderr);
		assert(false);
	}
	return bdd_io_shutdown_err;
}
void bdd_io_remove(struct bdd_conversation *conversation, bdd_io_id io_id) {
	if (conversation == NULL || io_id < 0 || io_id >= bdd_conversation_n_max_io(conversation)) {
		fputs("programming error: bdd_io_remove called with invalid arguments\n", stderr);
		assert(false);
		return;
	}
	struct bdd_io *io = &(conversation->io_array[io_id]);
	if (bdd_io_state(io) == BDD_IO_STATE_UNUSED) {
		fputs("programming error: bdd_io_remove called with an io_id which is in a state equal to BDD_IO_STATE_UNUSED\n", stderr);
		assert(false);
		return;
	}

	int fd = bdd_io_fd(io);
	if (io->ssl) {
		if (bdd_io_state(io) == BDD_IO_STATE_ESTABLISHED && io->ssl_shut == 1 && io->hup) {
			// to-do: is this safe is the socket is blocking?
			// there may be a bug in openssl
			SSL_shutdown(io->io.ssl);
		}
		SSL_free(io->io.ssl);
	}
	shutdown(fd, SHUT_RDWR);
	close(fd);
	bdd_io_set_state(io, BDD_IO_STATE_UNUSED);
	return;
}
bool bdd_io_set_blocking(struct bdd_conversation *conversation, bdd_io_id io_id, bool block) {
	if (conversation == NULL || io_id < 0 || io_id >= bdd_conversation_n_max_io(conversation)) {
		fputs("programming error: bdd_io_set_blocking called with invalid arguments\n", stderr);
		assert(false);
		return false;
	}
	struct bdd_io *io = &(conversation->io_array[io_id]);
	if (
		bdd_io_state(io) != BDD_IO_STATE_CREATED &&
		bdd_io_state(io) != BDD_IO_STATE_CONNECT &&
		bdd_io_state(io) != BDD_IO_STATE_CONNECTING &&
		bdd_io_state(io) != BDD_IO_STATE_SSL_CONNECTING &&
		bdd_io_state(io) != BDD_IO_STATE_ESTABLISHED
	) {
		fputs("programming error: bdd_io_set_blocking called with an io_id which is in an invalid state\n", stderr);
		assert(false);
		return false;
	}
	int fd = bdd_io_fd(io);
	int flags = fcntl(fd, F_GETFL, 0);
	if (flags == -1) {
		return false;
	}
	if (block) {
		flags &= ~(O_NONBLOCK);
	} else {
		flags |= O_NONBLOCK;
	}
	if (fcntl(fd, F_SETFL, flags) == -1) {
		return false;
	}
	return true;
}
bool bdd_io_set_epoll_events(struct bdd_conversation *conversation, bdd_io_id io_id, uint32_t epoll_events) {
	if (conversation == NULL || io_id < 0 || io_id >= bdd_conversation_n_max_io(conversation)) {
		fputs("programming error: bdd_io_set_epoll_events called with invalid arguments\n", stderr);
		assert(false);
		return false;
	}
	struct bdd_io *io = &(conversation->io_array[io_id]);
	if (
		bdd_io_state(io) != BDD_IO_STATE_CREATED &&
		bdd_io_state(io) != BDD_IO_STATE_CONNECT &&
		bdd_io_state(io) != BDD_IO_STATE_CONNECTING &&
		bdd_io_state(io) != BDD_IO_STATE_SSL_CONNECTING &&
		bdd_io_state(io) != BDD_IO_STATE_ESTABLISHED
	) {
		fputs("programming error: bdd_io_set_epoll_events called with an io_id which is in an invalid state\n", stderr);
		assert(false);
		return false;
	}
	if ((epoll_events & EPOLLIN) && !(epoll_events & EPOLLRDHUP)) {
		fputs("programming warning: bdd_io_set_epoll_events called with epoll_events where EPOLLIN is set and EPOLLRDHUP is not set, which is rarely desired", stderr);
	}
	io->epoll_events = epoll_events;
	return true;
}
bool bdd_io_blocking(struct bdd_conversation *conversation, bdd_io_id io_id) {
	if (conversation == NULL || io_id < 0 || io_id >= bdd_conversation_n_max_io(conversation)) {
		fputs("programming error: bdd_io_blocking called with invalid arguments\n", stderr);
		assert(false);
		return false;
	}
	struct bdd_io *io = &(conversation->io_array[io_id]);
	if (
		bdd_io_state(io) != BDD_IO_STATE_CREATED &&
		bdd_io_state(io) != BDD_IO_STATE_CONNECT &&
		bdd_io_state(io) != BDD_IO_STATE_CONNECTING &&
		bdd_io_state(io) != BDD_IO_STATE_SSL_CONNECTING &&
		bdd_io_state(io) != BDD_IO_STATE_ESTABLISHED
	) {
		fputs("programming error: bdd_io_blocking called with an io_id which is in an invalid state\n", stderr);
		assert(false);
		return false;
	}
	int fd = bdd_io_fd(io);
	int flags = fcntl(fd, F_GETFL, 0);
	if (flags == -1) {
		return false;
	}
	return (flags & O_NONBLOCK) ? false : true;
}
uint32_t bdd_io_epoll_events(struct bdd_conversation *conversation, bdd_io_id io_id) {
	if (conversation == NULL || io_id < 0 || io_id >= bdd_conversation_n_max_io(conversation)) {
		fputs("programming error: bdd_io_epoll_events called with invalid arguments\n", stderr);
		assert(false);
		return -1;
	}
	struct bdd_io *io = &(conversation->io_array[io_id]);
	if (
		bdd_io_state(io) != BDD_IO_STATE_CREATED &&
		bdd_io_state(io) != BDD_IO_STATE_CONNECT &&
		bdd_io_state(io) != BDD_IO_STATE_CONNECTING &&
		bdd_io_state(io) != BDD_IO_STATE_SSL_CONNECTING &&
		bdd_io_state(io) != BDD_IO_STATE_ESTABLISHED
	) {
		fputs("programming error: bdd_io_epoll_events called with an io_id which is in an invalid state\n", stderr);
		assert(false);
		return -1;
	}
	return io->epoll_events;
}
