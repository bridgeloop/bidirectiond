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
#include "headers/signal.h"
#include "headers/conversations.h"
#include "headers/bdd_service.h"
#include "headers/bdd_poll_io.h"
#include "headers/bdd_io.h"
#include "headers/workers.h"
#include "headers/bdd_io_connect.h"
#include "headers/bdd_pthread_preinit.h"
#include "headers/bdd_io_shutdown.h"
#include "headers/unlikely.h"
#include "headers/internal_globals.h"

bdd_io_id bdd_conversation_n_max_io(struct bdd_conversation *conversation) {
	return conversation->service->n_max_io;
}
int bdd_conversation_id(struct bdd_instance *instance, struct bdd_conversation *conversation) {
	return (((char *)conversation - (char *)(instance->conversations)) / sizeof(struct bdd_conversation));
}
void *bdd_get_associated(struct bdd_conversation *conversation) {
	return conversation->associated.data;
}

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

int bdd_poll(struct bdd_conversation *conversation, struct bdd_poll_io *io_ids, bdd_io_id n_io_ids, int timeout) {
	if (conversation == NULL || io_ids == NULL || n_io_ids == 0) {
		fputs("programming error: bdd_poll called with invalid arguments\n", stderr);
		assert(false);
		return -1;
	}
	struct pollfd *pollfds;
	bool heap;
	if (n_io_ids <= 0x7f) {
		pollfds = alloca(n_io_ids * sizeof(struct pollfd));
		heap = false;
	} else {
		pollfds = malloc(n_io_ids * sizeof(struct pollfd));
		if (pollfds == NULL) {
			fputs("bdd_poll malloc failed\n", stderr);
			return -1;
		}
		heap = true;
	}
	int n_revents = -1;
	for (
		bdd_io_id idx = 0;
		idx < n_io_ids;
		++idx
	) {
		bdd_io_id io_id = io_ids[idx].io_id;
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
		struct bdd_io *io = &(conversation->io[io_id]);
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
		pollfds[idx].events = io_ids[idx].events;
		pollfds[idx].revents = 0;
	}
	n_revents = poll(pollfds, n_io_ids, timeout);
	if (n_revents < 0) {
		goto out;
	}
	for (
		bdd_io_id idx = 0;
		idx < n_io_ids;
		++idx
	) {
		bdd_io_id io_id = io_ids[idx].io_id;
		struct bdd_io *io = &(conversation->io[io_id]);
		io_ids[idx].revents = pollfds[idx].revents;
		if (io->ssl) {
			if (SSL_has_pending(io->io.ssl)) {
				io_ids[idx].revents |= POLLIN;
				if (pollfds[idx].revents == 0) {
					n_revents += 1;
				}
			}
		}
	}
	out:;
	if (heap) {
		free(pollfds);
	}
	return n_revents;
}

__attribute__((warn_unused_result)) ssize_t bdd_read(
	struct bdd_conversation *conversation,
	bdd_io_id io_id,
	void *buf,
	ssize_t sz
) {
	if (conversation == NULL || io_id < 0 || io_id >= bdd_conversation_n_max_io(conversation) || buf == NULL || sz <= 0) {
		fputs("programming error: bdd_read called with invalid arguments\n", stderr);
		assert(false);
		return -1;
	}
	struct bdd_io *io = &(conversation->io[io_id]);
	if (bdd_io_state(io) != BDD_IO_STATE_ESTABLISHED) {
		fputs("programming error: bdd_read called with an io_id which is in a state not equal to BDD_IO_STATE_ESTABLISHED\n", stderr);
		assert(false);
		return -1;
	}

	ssize_t r = 0;
	do {
		if (io->ssl) {
			r = SSL_read(io->io.ssl, buf, sz);
			if (r <= 0) {
				int err = SSL_get_error(io->io.ssl, r);
				if (err == SSL_ERROR_WANT_WRITE) {
					return -2;
				}
				if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_NONE) {
					return 0;
				}
				bdd_io_set_state(io, BDD_IO_STATE_BROKEN);
				return -1;
			}
		} else {
			r = recv(io->io.fd, buf, sz, 0);
			if (r < 0) {
				if (errno == EAGAIN || errno == EWOULDBLOCK) {
					return 0;
				}
				bdd_io_set_state(io, BDD_IO_STATE_BROKEN);
				return -1;
			}
		}
	} while (r < 0 && errno == EINTR);
	return r;
}

__attribute__((warn_unused_result)) ssize_t bdd_write(
	struct bdd_conversation *conversation,
	bdd_io_id io_id,
	void *buf,
	ssize_t sz
) {
	if (conversation == NULL || io_id < 0 || io_id >= bdd_conversation_n_max_io(conversation) || buf == NULL || sz <= 0) {
		fputs("programming error: bdd_write called with invalid arguments\n", stderr);
		assert(false);
		return -1;
	}
	struct bdd_io *io = &(conversation->io[io_id]);
	if (bdd_io_state(io) != BDD_IO_STATE_ESTABLISHED) {
		fputs("programming error: bdd_write called with an io_id which is in a state not equal to BDD_IO_STATE_ESTABLISHED\n", stderr);
		assert(false);
		return -1;
	}

	ssize_t r = 0;
	do {
		if (io->ssl) {
			r = SSL_write(io->io.ssl, buf, sz);
			if (r <= 0) {
				int err = SSL_get_error(io->io.ssl, r);
				if (err == SSL_ERROR_WANT_READ) {
					return -2;
				}
				if (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_NONE) {
					return 0;
				}
				bdd_io_set_state(io, BDD_IO_STATE_BROKEN);
				return -1;
			}
		} else {
			r = send(io->io.fd, buf, sz, 0);
			if (r < 0) {
				if (errno == EAGAIN || errno == EWOULDBLOCK) {
					return 0;
				}
				bdd_io_set_state(io, BDD_IO_STATE_BROKEN);
				return -1;
			}
		}
	} while (r < 0 && errno == EINTR);
	return r;
}

void bdd_set_associated(
	struct bdd_conversation *conversation,
	void *data,
	void (*destructor)(void *)
) {
	assert(conversation != NULL);
	if (conversation->associated.destructor != NULL) {
		conversation->associated.destructor(conversation->associated.data);
	}
#ifndef NDEBUG
	if (data != NULL || destructor != NULL) {
		assert(data != NULL && destructor != NULL);
	}
#endif
	conversation->associated.data = data;
	conversation->associated.destructor = destructor;
	return;
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
		if (conversation->io[idx].state == BDD_IO_STATE_UNUSED) {
			io = &(conversation->io[idx]);
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
	io->ssl_shut = 0;
	io->in_epoll = 0;
	io->no_epoll = 0;
	io->hup = 0;
	io->io.fd = fd;
	(*io_id) = idx;
	return true;
}

// to-do: alpn
bool bdd_io_prep_ssl(struct bdd_conversation *conversation, bdd_io_id io_id, char *ssl_name) {
	SSL *ssl = NULL;
	const char *err = NULL;
	if (conversation == NULL || io_id < 0 || io_id >= bdd_conversation_n_max_io(conversation) || ssl_name == NULL) {
		err = "programming error: bdd_io_prep_ssl called with invalid arguments\n";
		goto err;
	}
	struct bdd_io *io = &(conversation->io[io_id]);
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
	if (unlikely(!SSL_set_tlsext_host_name(ssl, ssl_name))) {
		goto err;
	}
	// hostname vertification
	SSL_set_hostflags(ssl, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
	// does strdup: https://github.com/openssl/openssl/blob/1c0eede9827b0962f1d752fa4ab5d436fa039da4/crypto/x509/x509_vpm.c#L59
	if (!SSL_set1_host(ssl, ssl_name)) {
		goto err;
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
	struct bdd_io *io = &(conversation->io[io_id]);

	switch (bdd_io_state(io)) {
		case (BDD_IO_STATE_CONNECT): case (BDD_IO_STATE_CREATED): {
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
			// connected
			break;
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
	struct bdd_io *io = &(conversation->io[io_id]);
	if (bdd_io_state(io) != BDD_IO_STATE_SSL_CONNECTING && bdd_io_state(io) != BDD_IO_STATE_ESTABLISHED) {
		err = "programming error: bdd_io_shutdown called with an io_id which is in an invalid state\n";
		goto err;
	}
	if (
		(io->tcp && (io->ssl && io->ssl_shut == 2)) ||
		(io->shut_wr)
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
	struct bdd_io *io = &(conversation->io[io_id]);
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
	struct bdd_io *io = &(conversation->io[io_id]);
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
bool bdd_io_set_epoll_events(struct bdd_conversation *conversation, bdd_io_id io_id, short int epoll_events) {
	if (conversation == NULL || io_id < 0 || io_id >= bdd_conversation_n_max_io(conversation)) {
		fputs("programming error: bdd_io_set_epoll_events called with invalid arguments\n", stderr);
		assert(false);
		return false;
	}
	struct bdd_io *io = &(conversation->io[io_id]);
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
	struct bdd_io *io = &(conversation->io[io_id]);
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
short int bdd_io_epoll_events(struct bdd_conversation *conversation, bdd_io_id io_id) {
	if (conversation == NULL || io_id < 0 || io_id >= bdd_conversation_n_max_io(conversation)) {
		fputs("programming error: bdd_io_epoll_events called with invalid arguments\n", stderr);
		assert(false);
		return -1;
	}
	struct bdd_io *io = &(conversation->io[io_id]);
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

enum bdd_conversation_init_status bdd_conversation_init(
	struct bdd_conversation *conversation,
	SSL **client_ssl_ref,
	struct sockaddr client_sockaddr,
	const struct bdd_service *service,
	const char *protocol_name,
	void *instance_info
) {
	assert(service->n_max_io > 0);
	SSL *client_ssl = (*client_ssl_ref);

	conversation->noatime = 0;

	conversation->service = service;

	conversation->io = malloc(
		(sizeof(struct bdd_io) * service->n_max_io) +
		(sizeof(short int) * service->n_max_io)
	);

	if (conversation->io == NULL) {
		return bdd_conversation_init_failed;
	}

	conversation->io[0].epoll_events = EPOLLIN | EPOLLRDHUP;
	conversation->io[0].state = BDD_IO_STATE_ESTABLISHED;
	conversation->io[0].tcp = 1;
	conversation->io[0].shut_wr = 0;
	conversation->io[0].ssl = 1;
	conversation->io[0].ssl_shut = 0;
	conversation->io[0].in_epoll = 0;
	conversation->io[0].no_epoll = 0;
	conversation->io[0].hup = 0;

	(*client_ssl_ref) = NULL;
	conversation->io[0].io.ssl = client_ssl;

	for (bdd_io_id idx = 1; idx < service->n_max_io; ++idx) {
		conversation->io[idx].state = BDD_IO_STATE_UNUSED;
	}
	if (
		service->conversation_init != NULL &&
		!service->conversation_init(conversation, protocol_name, instance_info, 0, client_sockaddr)
	) {
		return bdd_conversation_init_failed_wants_deinit;
	}
	return bdd_conversation_init_success;
}
void bdd_conversation_deinit(struct bdd_conversation *conversation) {
	if (conversation->io != NULL) {
		for (bdd_io_id io_id = 0; io_id < bdd_conversation_n_max_io(conversation); ++io_id) {
			struct bdd_io *io = &(conversation->io[io_id]);
			if (bdd_io_state(io) == BDD_IO_STATE_UNUSED) {
				continue;
			}
			bdd_io_remove(conversation, io_id);
		}
		free(conversation->io);
		conversation->io = NULL;
	}
	bdd_set_associated(conversation, NULL, NULL);
	return;
}
void bdd_conversation_link(struct bdd_instance *instance, struct bdd_conversation **conversation_ref) {
	assert(conversation_ref != NULL);
	struct bdd_conversation *conversation = (*conversation_ref);
	(*conversation_ref) = NULL;
	assert(conversation != NULL);
	pthread_mutex_lock(&(instance->to_epoll.mutex));
	conversation->next = (void *)instance->to_epoll.head;
	instance->to_epoll.head = (void *)conversation;
	bdd_signal(instance);
	pthread_mutex_unlock(&(instance->to_epoll.mutex));
	return;
}
struct bdd_conversation *bdd_conversation_obtain(struct bdd_instance *instance) {
	struct bdd_conversation *conversation = NULL;
	pthread_mutex_lock(&(instance->available_conversations.mutex));
	while (!atomic_load(&(instance->exiting)) && instance->available_conversations.idx == instance->n_conversations) {
		pthread_cond_wait(&(instance->available_conversations.cond), &(instance->available_conversations.mutex));
	}
	if (!atomic_load(&(instance->exiting))) {
		int id = instance->available_conversations.ids[instance->available_conversations.idx++];
		conversation = &(instance->conversations[id]);
	}
	pthread_mutex_unlock(&(instance->available_conversations.mutex));
	return conversation;
}
void bdd_conversation_release(struct bdd_instance *instance, struct bdd_conversation **conversation_ref) {
	assert(conversation_ref != NULL);

	struct bdd_conversation *conversation = (*conversation_ref);
	(*conversation_ref) = NULL;
	assert(conversation != NULL);

	pthread_mutex_lock(&(instance->available_conversations.mutex));

	assert(instance->available_conversations.idx != 0);

	int id = bdd_conversation_id(instance, conversation);

	assert(id >= 0 && id < instance->n_conversations);

	instance->available_conversations.ids[--(instance->available_conversations.idx)] = id;

	pthread_cond_signal(&(instance->available_conversations.cond));
	pthread_mutex_unlock(&(instance->available_conversations.mutex));

	return;
}
