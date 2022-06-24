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
#include "headers/bidirectiond_n_io.h"

bdd_io_id bdd_io_id_of(struct bdd_io *io) {
	struct bdd_conversation *conversation = io_conversation(io);
	return (((char *)io - (char *)conversation->io_array) / sizeof(struct bdd_io));
}

struct bdd_io *bdd_io(struct bdd_conversation *conversation, bdd_io_id io_id) {
	if (conversation == NULL || io_id >= BIDIRECTIOND_N_IO) {
		return NULL;
	}
	return &(conversation->io_array[io_id]);
}

int bdd_io_fd(struct bdd_io *io) {
	if (io->ssl) {
		return SSL_get_fd(io->io.ssl);
	} else {
		return io->io.fd;
	}
}

uint32_t bdd_epoll_to_epoll(uint8_t bdd_epoll) {
	uint32_t output = 0;
	if (bdd_epoll & bdd_epoll_in) {
		output |= EPOLLIN;
	}
	if (bdd_epoll & bdd_epoll_out) {
		output |= EPOLLOUT;
	}
	if (bdd_epoll & bdd_epoll_et) {
		output |= EPOLLET;
	}
	return output;
}

void bdd_io_epoll_mod(struct bdd_io *io, uint8_t remove_events, uint8_t add_events, bool edge_trigger) {
	uint8_t old_events = io->epoll_events;
	io->epoll_events &= ~remove_events;
	io->epoll_events |= add_events;
	if (edge_trigger) {
		io->epoll_events |= bdd_epoll_et;
	} else {
		io->epoll_events &= ~bdd_epoll_et;
	}
	#ifndef NDEBUG
	if (io->rdhup) {
		assert(!(io->epoll_events & bdd_epoll_in));
	}
	#endif
	if (io->in_epoll) {
		if ((old_events & ~bdd_epoll_et) == 0) {
			if ((io->epoll_events & ~bdd_epoll_et) != 0) {
				io_conversation(io)->n_in_epoll_with_events += 1;
			}
		} else if ((io->epoll_events & ~bdd_epoll_et) == 0) {
			io_conversation(io)->n_in_epoll_with_events -= 1;
		}
		struct epoll_event ev = {
			.events = bdd_epoll_to_epoll(io->epoll_events),
			.data = { .ptr = io, },
		};
		if (epoll_ctl(io_conversation(io)->epoll_fd, EPOLL_CTL_MOD, bdd_io_fd(io), &(ev)) != 0) {
			abort();
		}
	}
	return;
}

bool bdd_io_epoll_add(struct bdd_io *io) {
	if (io->in_epoll) {
		return true;
	}
	io->in_epoll = 1;
	struct epoll_event ev = {
		.events = bdd_epoll_to_epoll(io->epoll_events),
		.data = { .ptr = io, },
	};
	if (epoll_ctl(io_conversation(io)->epoll_fd, EPOLL_CTL_ADD, bdd_io_fd(io), &(ev)) != 0) {
		return false;
	}
	if ((io->epoll_events & ~bdd_epoll_et) != 0) {
		io_conversation(io)->n_in_epoll_with_events += 1;
	}
	return true;
}

void bdd_io_epoll_remove(struct bdd_io *io) {
	if (!io->in_epoll || io_conversation(io)->epoll_fd < 0) {
		return;
	}
	io->in_epoll = 0;
	if (epoll_ctl(io_conversation(io)->epoll_fd, EPOLL_CTL_DEL, bdd_io_fd(io), NULL) != 0) {
		abort();
	}
	if ((io->epoll_events & ~bdd_epoll_et) != 0) {
		io_conversation(io)->n_in_epoll_with_events -= 1;
	}
	return;
}

bool bdd_io_hup(struct bdd_io *io, bool rdhup) {
	assert(io->state >= bdd_io_est);
	if (rdhup) {
		io->rdhup = 1;
	} else {
		io->wrhup = 1;
	}
	return (io->rdhup && io->wrhup);
}

bool bdd_io_state(struct bdd_io *io, enum bdd_io_state new_state) {
	struct bdd_conversation *conversation = io_conversation(io);
	enum bdd_io_state state = io->state;

	assert(state != new_state);

	if (state == bdd_io_connecting || state == bdd_io_out) {
		conversation->n_blocking -= 1;
		if (!conversation->n_blocking) {
			for (bdd_io_id idx = 0; idx < BIDIRECTIOND_N_IO; ++idx) {
				struct bdd_io *idx_io = bdd_io(conversation, idx);
				if (idx_io == io || (idx_io->state != bdd_io_est && idx_io->state != bdd_io_ssl_shutting)) {
					continue;
				}
				if (!idx_io->rdhup) {
					bdd_io_epoll_mod(idx_io, 0, bdd_epoll_in, false);
				}
				if (idx_io->state == bdd_io_est) {
					if (!bdd_io_epoll_add(idx_io)) {
						return false;
					}
				}
			}
		}
	}

	if (new_state == bdd_io_connecting || new_state == bdd_io_out) {
		if (conversation->n_blocking == 0) {
			for (bdd_io_id idx = 0; idx < BIDIRECTIOND_N_IO; ++idx) {
				struct bdd_io *idx_io = bdd_io(conversation, idx);
				if (idx_io == io || idx_io->state == bdd_io_connecting || idx_io->state == bdd_io_out) {
					continue;
				}
				if (idx_io->state == bdd_io_ssl_shutting) {
					bdd_io_epoll_mod(idx_io, bdd_epoll_in, 0, false);
				} else if (idx_io->state == bdd_io_est) {
					bdd_io_epoll_remove(idx_io);
				}
			}
		}
		conversation->n_blocking += 1;
	}

	if (new_state == bdd_io_connecting) {
		bdd_io_epoll_mod(io, 0, bdd_epoll_in | bdd_epoll_out, true);
		if (!bdd_io_epoll_add(io)) {
			return true;
		}
	} else if (new_state == bdd_io_out) {
		bdd_io_epoll_mod(io, bdd_epoll_in, bdd_epoll_out, false);
		if (!bdd_io_epoll_add(io)) {
			return true;
		}
	} else if (new_state == bdd_io_est) {
		uint8_t epollin = bdd_epoll_in;
		if (io->rdhup) {
			epollin = 0;
		}
		bdd_io_epoll_mod(io, bdd_epoll_out, epollin, false);
		if (conversation->n_blocking == 0) {
			if (!bdd_io_epoll_add(io)) {
				return false;
			}
		} else {
			bdd_io_epoll_remove(io);
		}
	} else if (new_state == bdd_io_ssl_shutting) {
		bdd_io_epoll_mod(io, 0, bdd_epoll_out, false);
		if (!bdd_io_epoll_add(io)) {
			return false;
		}
	} else {
		bdd_io_epoll_remove(io);
	}

	io->state = new_state;

	return true;
}

// returns the number of bytes read (where 0 is a possible value), returns -4 on rdhup, returns -3 if conversation to be discarded, returns -2 if IO discarded, returns -1 on err
__attribute__((warn_unused_result)) ssize_t bdd_io_read(
	struct bdd_conversation *conversation,
	bdd_io_id io_id,
	void *buf,
	ssize_t sz
) {
	if (conversation->remove) {
		fputs("programming error: bdd_io_read called with an io_id of a discarded conversation\n", stderr);
		abort();
		return -3;
	}
	struct bdd_io *io = bdd_io(conversation, io_id);
	if (io == NULL || buf == NULL || sz <= 0 || conversation->n_blocking > 0) {
		fputs("programming error: bdd_io_read called with invalid arguments\n", stderr);
		abort();
		return -1;
	}
	if (io->state < bdd_io_est || io->rdhup) {
		fputs("programming error: bdd_io_read called with an io_id which is in an invalid state\n", stderr);
		printf("io->state %i, io->rdhup %i\n", io->state, io->rdhup);
		abort();
		return -1;
	}

	ssize_t r;
	if (io->ssl) {
		r = SSL_read(io->io.ssl, buf, sz);
		if (r <= 0) {
			int err = SSL_get_error(io->io.ssl, r);
			if (err == SSL_ERROR_WANT_WRITE) {
				abort(); // fuck re-negotiation
			} else if (err == SSL_ERROR_ZERO_RETURN /* received close_notify */) {
				if (bdd_io_hup(io, true)) {
					if (!bdd_io_discard(io)) {
						goto conversation_discard;
					}
					return -2;
				}
				bdd_io_epoll_mod(io, bdd_epoll_in, 0, false);
				return -4;
			} else if (
				(
					err == SSL_ERROR_WANT_READ /* read all of the bytes and no close_notify received */ ||
					err == SSL_ERROR_NONE
				)
			) {
				return 0;
			}
			if (!bdd_io_discard(io)) {
				goto conversation_discard;
			}
			return -2;
		}
	} else {
		r = recv(io->io.fd, buf, sz, 0);
		if (r < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				return 0;
			}
			if (!bdd_io_discard(io)) {
				goto conversation_discard;
			}
			return -2;
		}
		if (r == 0) {
			if (bdd_io_hup(io, true)) {
				if (!bdd_io_discard(io)) {
					goto conversation_discard;
				}
				return -2;
			}
			bdd_io_epoll_mod(io, bdd_epoll_in, 0, false);
			return -4;
		}
	}
	return r;
	conversation_discard:;
	conversation->remove = true;
	return -3;
}

// returns the number of bytes written, returns -3 if conversation to be discarded, returns -2 if IO discarded, returns -1 on err
__attribute__((warn_unused_result)) ssize_t bdd_io_write(
	struct bdd_conversation *conversation,
	bdd_io_id io_id,
	void *buf,
	ssize_t sz
) {
	if (conversation->remove) {
		fputs("programming error: bdd_io_write called with an io_id of a discarded conversation\n", stderr);
		abort();
		return -3;
	}
	struct bdd_io *io = bdd_io(conversation, io_id);
	if (io == NULL || buf == NULL || sz <= 0) {
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
	if (io->ssl) {
		r = SSL_write(io->io.ssl, buf, sz);
		if (r <= 0) {
			int err = SSL_get_error(io->io.ssl, r);
			if (err == SSL_ERROR_WANT_READ) {
				abort(); // fuck re-negotiation
			} else if (err == SSL_ERROR_WANT_WRITE) {
				r = 0;
				goto want_send;
			}
			if (bdd_io_hup(io, false)) {
				return -2;
			}
			return -1;
		}
		if (r != sz) {
			goto want_send;
		}
	} else {
		r = send(io->io.fd, buf, sz, 0);
		if (r < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				r = 0;
				goto want_send;
			}
			if (bdd_io_hup(io, false)) {
				return -2;
			}
			return -1;
		}
		if (r != sz) {
			goto want_send;
		}
	}
	return sz;
	want_send:;
	if (!bdd_io_state(io, bdd_io_out)) {
		goto conversation_discard;
	}
	return r;
	conversation_discard:;
	conversation->remove = true;
	return -3;
}

bool bdd_io_obtain(struct bdd_conversation *conversation, bdd_io_id *io_id) {
	for (size_t idx = 0; idx < BIDIRECTIOND_N_IO; ++idx) {
		struct bdd_io *io = &(conversation->io_array[idx]);
		if (io->state == bdd_io_unused) {
			io->rdhup = io->wrhup = 0;
			io->ssl_alpn = io->ssl = 0;
			io->in_epoll = 0;
			io->epoll_events = 0;
			io->io.fd = -1;
			bool sstate = bdd_io_state(io, bdd_io_obtained);
			assert(sstate);
			*io_id = (bdd_io_id)idx;
			return true;
		}
	}
	return false;
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

enum bdd_shutdown_status bdd_io_shutdown(struct bdd_conversation *conversation, bdd_io_id io_id) {
	if (conversation->remove) {
		fputs("programming error: bdd_io_shutdown called with an io_id of a discarded conversation\n", stderr);
		abort();
		return bdd_shutdown_conversation_discard;
	}
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
		if (!bdd_io_state(io, bdd_io_ssl_shutting)) {
			goto conversation_discard;
		}
		if (bdd_ssl_shutdown_continue(io) == bdd_shutdown_inprogress) {
			return bdd_shutdown_inprogress;
		}
	} else {
		shutdown(bdd_io_fd(io), SHUT_WR);
	}
	if (bdd_io_hup(io, false)) {
		if (!bdd_io_discard(io)) {
			goto conversation_discard;
		}
		return bdd_shutdown_discard;
	}
	if (io->ssl) {
		if (!bdd_io_state(io, bdd_io_est)) {
			goto conversation_discard;
		}
	}
	return bdd_shutdown_complete;

	conversation_discard:;
	conversation->remove = true;
	return bdd_shutdown_conversation_discard;
}

void bdd_io_clean(struct bdd_io *io, enum bdd_io_state prev_state) {
	if (prev_state >= bdd_io_connecting) {
		int fd = bdd_io_fd(io);
		if (
			io->ssl &&
			io->rdhup &&
			io->wrhup &&
			(SSL_get_shutdown(io->io.ssl) & SSL_SENT_SHUTDOWN)
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
bool bdd_io_discard(struct bdd_io *io) {
	enum bdd_io_state state = io->state;
	if (state == bdd_io_unused) {
		return true;
	}
	if (!bdd_io_state(io, bdd_io_unused)) {
		return false;
	}
	bdd_io_clean(io, state);
	return true;
}

bool bdd_io_prep_ssl(struct bdd_conversation *conversation, bdd_io_id io_id, char *ssl_name, char *alp) {
	struct bdd_io *io = bdd_io(conversation, io_id);
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
	io->ssl = 1;
	io->io.ssl = ssl;
	bool sstate = bdd_io_state(io, bdd_io_prepd_ssl);
	assert(sstate);
	return true;

	err:;
	/*io->ssl = 0;
	if (io->state == bdd_io_prepd_ssl) {
		bdd_io_state(io, bdd_io_obtained);
	}*/
	if (ssl != NULL) {
		SSL_free(ssl);
	}
	bool sdiscard = bdd_io_discard(io);
	assert(sdiscard);
	return false;
}

enum bdd_cont bdd_io_connect(
	struct bdd_conversation *conversation,
	bdd_io_id io_id,
	struct sockaddr *sockaddr,
	socklen_t addrlen
) {
	if (conversation->remove) {
		fputs("programming error: bdd_io_connect called with an io_id of a discarded conversation\n", stderr);
		abort();
		return bdd_cont_conversation_discard;
	}
	struct bdd_io *io = bdd_io(conversation, io_id);
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
	if (connect(fd, sockaddr, addrlen) == 0) {
		switch (bdd_connect_continue(io)) {
			case (bdd_cont_discard): {
				goto err;
			}
			case (bdd_cont_inprogress): {
				if (!bdd_io_state(io, bdd_io_connecting)) {
					goto conversation_discard;
				}
				return bdd_cont_inprogress;
			}
			case (bdd_cont_established): {
				if (!bdd_io_state(io, bdd_io_est)) {
					goto conversation_discard;
				}
				return bdd_cont_established;
			}
		}
	}
	if (errno == EINPROGRESS) {
		if (!bdd_io_state(io, bdd_io_connecting)) {
			goto conversation_discard;
		}
		return bdd_cont_inprogress;
	}

	err:;
	if (!bdd_io_discard(io)) {
		goto conversation_discard;
	}
	return bdd_cont_discard;

	conversation_discard:;
	conversation->remove = true;
	return bdd_cont_conversation_discard;
}
