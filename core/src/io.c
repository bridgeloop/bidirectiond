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
#include "headers/bdd_io_connect.h"
#include "headers/bdd_io_shutdown.h"
#include "headers/internal_globals.h"

void bdd_io_internal_set_state(struct bdd_conversation *conversation, struct bdd_io *io, uint8_t state) {
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
			io->state == BDD_IO_STATE_ESTABLISHED ||
			io->state == BDD_IO_STATE_ESTABLISHED_BROKEN
		)) ||
		(state == BDD_IO_STATE_ESTABLISHED_BROKEN && (
			io->state == BDD_IO_STATE_ESTABLISHED
		))
	);
	#ifndef NDEBUG
	if (io->state == BDD_IO_STATE_BROKEN) {
		assert(state == BDD_IO_STATE_UNUSED);
	}
	if (io->state == BDD_IO_STATE_ESTABLISHED_BROKEN) {
		assert(state == BDD_IO_STATE_UNUSED || state == BDD_IO_STATE_BROKEN);
	}
	#endif
	if (
		(io->state != BDD_IO_STATE_CONNECTING && io->state != BDD_IO_STATE_SSL_CONNECTING) &&
		(state == BDD_IO_STATE_CONNECTING || state == BDD_IO_STATE_SSL_CONNECTING)
	) {
		conversation->n_connecting += 1;
	} else if (
		(io->state == BDD_IO_STATE_CONNECTING || io->state == BDD_IO_STATE_SSL_CONNECTING) &&
		(state != BDD_IO_STATE_CONNECTING && state != BDD_IO_STATE_SSL_CONNECTING)
	) {
		conversation->n_connecting -= 1;
	}
	io->state = state;
	return;
}
int bdd_io_internal_fd(struct bdd_io *io) {
	assert(
		io->state == BDD_IO_STATE_CREATED ||
		io->state == BDD_IO_STATE_CONNECT ||
		io->state == BDD_IO_STATE_CONNECTING ||
		io->state == BDD_IO_STATE_SSL_CONNECTING ||
		io->state == BDD_IO_STATE_ESTABLISHED ||
		io->state == BDD_IO_STATE_BROKEN ||
		io->state == BDD_IO_STATE_ESTABLISHED_BROKEN
	);
	if (io->ssl) {
		return SSL_get_fd(io->io.ssl);
	} else {
		return io->io.fd;
	}
}
bool bdd_io_internal_has_epoll_state(struct bdd_conversation *conversation, struct bdd_io *io) {
	if (io->no_epoll) {
		return false;
	}
	if (conversation->n_connecting == 0) {
		return (
			io->state == BDD_IO_STATE_ESTABLISHED ||
			io->state == BDD_IO_STATE_BROKEN ||
			io->state == BDD_IO_STATE_ESTABLISHED_BROKEN
		);
	}
	return (
		io->state == BDD_IO_STATE_CONNECTING ||
		io->state == BDD_IO_STATE_SSL_CONNECTING ||
		(io->shutdown_called && !io->shutdown_complete)
	);
}
void bdd_io_internal_break(struct bdd_conversation *conversation, struct bdd_io *io, bool from_core) {
	bdd_io_internal_set_state(conversation, io, BDD_IO_STATE_BROKEN);
	if (!from_core) {
		io->no_epoll = 1;
	} else {
		conversation->core_caused_broken_io = true;
	}
	return;
}
void bdd_io_internal_break_established(struct bdd_conversation *conversation, struct bdd_io *io, bool from_core) {
	assert(io->state == BDD_IO_STATE_ESTABLISHED);
	bdd_io_internal_set_state(conversation, io, BDD_IO_STATE_ESTABLISHED_BROKEN);
	shutdown(bdd_io_internal_fd(io), SHUT_RD);
	if (!from_core) {
		io->no_epoll = 1;
	} else {
		conversation->core_caused_broken_io = true;
	}
	return;
}

// returns the number of bytes read, returns 0 on rdhup, returns -1 on err
__attribute__((warn_unused_result)) ssize_t bdd_io_read(
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
	if (io->state != BDD_IO_STATE_ESTABLISHED && io->state != BDD_IO_STATE_ESTABLISHED_BROKEN) {
		fputs("programming error: bdd_read called with an io_id which is in an invalid state\n", stderr);
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
			} else if (err == SSL_ERROR_ZERO_RETURN /* received close_notify */) {
				if (SSL_get_shutdown(io->io.ssl) == (SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN)) {
					io->no_epoll = 1;
				}
				return -2;
			} else if (
				(
					err == SSL_ERROR_WANT_READ /* read all of the bytes and no close_notify received */ ||
					err == SSL_ERROR_NONE
				)
			) {
				return 0;
			}
			bdd_io_internal_break(conversation, io, false);
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
			bdd_io_internal_break(conversation, io, false);
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
	if (io->state != BDD_IO_STATE_ESTABLISHED) {
		fputs("programming error: bdd_write called with an io_id which is in a state not equal to BDD_IO_STATE_ESTABLISHED\n", stderr);
		assert(false);
		return -1;
	}
	if (io->shutdown_called) {
		fputs("programming error: bdd_write called with an io_id which has been passed to bdd_io_shutdown\n", stderr);
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
			bdd_io_internal_break_established(conversation, io, false);
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
			bdd_io_internal_break_established(conversation, io, false);
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
	struct bdd_io *io;
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

	int fd = socket(domain, type | SOCK_NONBLOCK, protocol);
	if (fd < 0) {
		return false;
	}

	bdd_io_internal_set_state(conversation, io, BDD_IO_STATE_CREATED);
	io->shutdown_called = 0;

	io->tcp = (type & ~(SOCK_NONBLOCK | SOCK_CLOEXEC)) == SOCK_STREAM ? 1 : 0;
	io->shutdown_complete = 0;
	io->ssl = 0;
	io->ssl_alpn = 0;
	io->ssl_shutdown_fully = 0;

	io->in_epoll = 0;

	io->eof = 0;
	io->no_epoll = 0;

	io->listen_read = 1;
	io->listen_write = 0;

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
	if (io->state != BDD_IO_STATE_CREATED) {
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

enum bdd_io_connect_status bdd_io_internal_connect_continue(struct bdd_conversation *conversation, struct bdd_io *io) {
	switch (io->state) {
		case (BDD_IO_STATE_CONNECTING): {
			if (!io->ssl) {
				bdd_io_internal_set_state(conversation, io, BDD_IO_STATE_ESTABLISHED);
				return bdd_io_connect_established;
			}

			bdd_io_internal_set_state(conversation, io, BDD_IO_STATE_SSL_CONNECTING);
		}

		case (BDD_IO_STATE_SSL_CONNECTING): {
			int r = SSL_connect(io->io.ssl);
			if (r == -1) {
				int err = SSL_get_error(io->io.ssl, r);
				if (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ) {
					return bdd_io_connect_inprogress;
				}
				r = 0;
			}
			if (r == 0) {
				return bdd_io_connect_err;
			}

			const unsigned char *alpn;
			unsigned int alpn_sz = 0;
			if (io->ssl_alpn) {
				SSL_get0_alpn_selected(io->io.ssl, &(alpn), &(alpn_sz));
				if (alpn == NULL) {
					return bdd_io_connect_err;
				}
			}

			bdd_io_internal_set_state(conversation, io, BDD_IO_STATE_ESTABLISHED);
			return bdd_io_connect_established;
		}

		default: {
			abort();
		}
	}
}
__attribute__((warn_unused_result)) enum bdd_io_connect_status bdd_io_connect(struct bdd_conversation *conversation, bdd_io_id io_id, struct sockaddr *addr, socklen_t addrlen) {
	const char *err = NULL;
	if (conversation == NULL || io_id < 0 || io_id >= bdd_conversation_n_max_io(conversation) || addr == NULL || addrlen == 0) {
		err = "programming error: bdd_io_connect called with invalid arguments\n";
		goto err;
	}
	struct bdd_io *io = &(conversation->io_array[io_id]);

	switch (io->state) {
		case (BDD_IO_STATE_CREATED): case (BDD_IO_STATE_CONNECT): {
			while (connect(bdd_io_internal_fd(io), addr, addrlen) != 0) {
				if (errno == EAGAIN) {
					bdd_io_internal_set_state(conversation, io, BDD_IO_STATE_CONNECT);
					return bdd_io_connect_again;
				} else if (errno == EINPROGRESS) {
					bdd_io_internal_set_state(conversation, io, BDD_IO_STATE_CONNECTING);
					return bdd_io_connect_inprogress;
				} else if (errno != EINTR) {
					// failed to connect
					bdd_io_internal_break(conversation, io, false);
					goto err;
				}
			}
			bdd_io_internal_set_state(conversation, io, BDD_IO_STATE_SSL_CONNECTING);
			enum bdd_io_connect_status s = bdd_io_internal_connect_continue(conversation, io);
			if (s == bdd_io_connect_err) {
				bdd_io_internal_break(conversation, io, false);
				goto err;
			}
			return s;
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


enum bdd_io_shutdown_status bdd_io_internal_shutdown_continue(struct bdd_io *io) {
	int fd = bdd_io_internal_fd(io);
	if (io->ssl) {
		int r = SSL_shutdown(io->io.ssl);
		if (r < 0) {
			r = SSL_get_error(io->io.ssl, r);
			if (r == SSL_ERROR_WANT_WRITE) {
				return bdd_io_shutdown_inprogress;
			}
			if (r == SSL_ERROR_WANT_READ) {
				// hopefully impossible?
				// https://git.tcp.direct/aiden/bidirectiond/issues/33#issuecomment-363
				abort();
			}
			return bdd_io_shutdown_err;
		}
		if (r == 1) {
			io->ssl_shutdown_fully = 1;
		}
	} else if (shutdown(fd, SHUT_WR) != 0) {
		return bdd_io_shutdown_err;
	}
	io->shutdown_complete = 1;
	return bdd_io_shutdown_success;
}

__attribute__((warn_unused_result)) enum bdd_io_shutdown_status bdd_io_shutdown(struct bdd_conversation *conversation, bdd_io_id io_id) {
	const char *err = NULL;
	if (conversation == NULL || io_id < 0 || io_id >= bdd_conversation_n_max_io(conversation)) {
		err = "programming error: bdd_io_shutdown called with invalid arguments\n";
		goto err;
	}
	struct bdd_io *io = &(conversation->io_array[io_id]);
	if (io->state != BDD_IO_STATE_ESTABLISHED || !io->tcp) {
		err = "programming error: bdd_io_shutdown called with an io_id which is in an invalid state\n";
		goto err;
	}
	if (io->shutdown_called) {
		err = "programming error: bdd_io_shutdown called with an io_id which has already been passed to bdd_io_shutdown\n";
		goto err;
	}
	io->shutdown_called = 1;

	enum bdd_io_shutdown_status s = bdd_io_internal_shutdown_continue(io);
	if (s == bdd_io_shutdown_err) {
		bdd_io_internal_break_established(conversation, io, false);
	}
	return s;

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
	if (io->state == BDD_IO_STATE_UNUSED) {
		fputs("programming error: bdd_io_remove called with an io_id which is in a state equal to BDD_IO_STATE_UNUSED\n", stderr);
		assert(false);
		return;
	}

	int fd = bdd_io_internal_fd(io);
	if (io->ssl) {
		if (
			io->state == BDD_IO_STATE_ESTABLISHED &&
			io->shutdown_complete &&
			!io->ssl_shutdown_fully &&
			SSL_get_shutdown(io->io.ssl) == (SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN)
		) {
			SSL_shutdown(io->io.ssl);
		}
		SSL_free(io->io.ssl);
		shutdown(fd, SHUT_WR);
	}
	close(fd);
	bdd_io_internal_set_state(conversation, io, BDD_IO_STATE_UNUSED);
	return;
}
