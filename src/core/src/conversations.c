#include <poll.h>
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

int bdd_poll(struct bdd_conversation *conversation, struct bdd_poll_io *io_ids, bdd_io_id n_io_ids, int timeout) {
	if (conversation == NULL || io_ids == NULL || n_io_ids == 0) {
		fputs("programming error: bdd_poll called with invalid arguments\n", stderr);
		assert(false);
		return -1;
	}
	struct pollfd *pollfds;
	bool heap;
	int n_revents = -1;
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
	for (
		bdd_io_id idx = 0;
		idx < n_io_ids;
		++idx
	) {
		bdd_io_id io_id = io_ids[idx].io_id;
		if (io_id < 0 || io_id >= bdd_conversation_n_max_io(conversation)) {
			fputs("programming error: bdd_poll called with an out-of-bounds io_id\n", stderr);
			assert(false);
			goto out;
		}
		struct bdd_io *io = &(conversation->io[io_id]);
		if (io->state != BDD_IO_STATE_SSL_CONNECTING && io->state != BDD_IO_STATE_ESTABLISHED) {
			fputs("programming error: bdd_poll called with an io_id which is in a state not equal to BDD_IO_STATE_SSL_CONNECTING and not equal to BDD_IO_STATE_ESTABLISHED\n", stderr);
			assert(false);
			io->state = BDD_IO_STATE_BROKEN;
			goto out;
		}
		if (io->ssl) {
			pollfds[idx].fd = SSL_get_fd(io->io.ssl);
			if (SSL_has_pending(io->io.ssl)) {
				timeout = 0;
			}
		} else {
			pollfds[idx].fd = io->io.fd;
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

// to-do: set errno depending on SSL_read (and do a similar thing for bdd_write)
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
	if (io->state != BDD_IO_STATE_ESTABLISHED) {
		fputs("programming error: bdd_read called with an io_id which is in a state not equal to BDD_IO_STATE_ESTABLISHED\n", stderr);
		assert(false);
		io->state = BDD_IO_STATE_BROKEN;
		return -1;
	}

	ssize_t r = 0;
	do {
		if (io->ssl) {
			// SSL_read on a shut_rd socket returns 0 (wth no error) (assuming there is no pending data to be read)
			r = SSL_read(io->io.ssl, buf, sz);
			if (r <= 0) {
				int err = SSL_get_error(io->io.ssl, r);
				if (err == SSL_ERROR_WANT_READ) {
					return -2;
				}
				if (err == SSL_ERROR_ZERO_RETURN || err == SSL_ERROR_NONE) {
					return 0;
				}
				io->state = BDD_IO_STATE_BROKEN;
				return -1;
			}
		} else {
			// recv on a shut_rd socket returns 0 (assuming there is no pending data to be read)
			r = recv(io->io.fd, buf, sz, 0);
			if (r < 0) {
				if (errno == EAGAIN) {
					return -2;
				}
				io->state = BDD_IO_STATE_BROKEN;
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
	if (io->state != BDD_IO_STATE_ESTABLISHED) {
		fputs("programming error: bdd_write called with an io_id which is in a state not equal to BDD_IO_STATE_ESTABLISHED\n", stderr);
		assert(false);
		io->state = BDD_IO_STATE_BROKEN;
		return -1;
	}

	ssize_t r = 0;
	do {
		if (io->ssl) {
			// SSL_write on a shut_wr socket returns -1
			r = SSL_write(io->io.ssl, buf, sz);
			if (r <= 0) {
				int err = SSL_get_error(io->io.ssl, r);
				// SSL_write on a shut_wr socket's err is -1
				if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
					return -2;
				}
				if (err == SSL_ERROR_ZERO_RETURN || err == SSL_ERROR_NONE) {
					return 0;
				}
				io->state = BDD_IO_STATE_BROKEN;
				return -1;
			}
		} else {
			// send on a shut_wr socket returns -1
			r = send(io->io.fd, buf, sz, 0);
			if (r < 0) {
				if (errno == EAGAIN) {
					return -2;
				}
				io->state = BDD_IO_STATE_BROKEN;
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
	io->state = BDD_IO_STATE_CREATED;
	io->tcp = (type & ~(SOCK_NONBLOCK | SOCK_CLOEXEC)) == SOCK_STREAM ? 1 : 0;
	io->shut_wr = 0;
	io->ssl = 0;
	io->ssl_shut = 0;
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
	if (unlikely(!SSL_set_tlsext_host_name(ssl, ssl_name))) {
		goto err;
	}
	// hostname vertification
	SSL_set_hostflags(ssl, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
	// to-do: does this strdup?
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
	if (io->state != BDD_IO_STATE_UNUSED) {
		io->state = BDD_IO_STATE_BROKEN;
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

	if (io->state == BDD_IO_STATE_CREATED) {
		io->state = BDD_IO_STATE_CONNECTING;
		io->substate = BDD_IO_CONNECTING_SUBSTATE_AGAIN;
		goto connecting;
	} else if (io->state == BDD_IO_STATE_CONNECTING) {
		connecting:;
		int fd;
		if (!io->ssl) {
			fd = io->io.fd;
		} else {
			fd = SSL_get_fd(io->io.ssl);
			assert(fd >= 0);
		}
		if (io->substate == BDD_IO_CONNECTING_SUBSTATE_IN_PROGRESS) {
			struct pollfd pollfd = {
				.fd = fd,
				.events = POLLOUT,
				.revents = 0,
			};
			poll(&(pollfd), 1, 0);
			if (pollfd.revents & POLLERR) {
				goto err;
			}
			if (!(pollfd.revents & POLLOUT)) {
				return bdd_io_connect_connecting;
			}
			// connected
		} else {
			assert(
				io->state == BDD_IO_STATE_CONNECTING &&
				io->substate == BDD_IO_CONNECTING_SUBSTATE_AGAIN
			);
			if (addr == NULL || addrlen == 0) {
				err = "programming error: bdd_io_connect called with invalid arguments\n";
				goto err;
			}
			while (connect(fd, addr, addrlen) != 0) {
				if (errno == EAGAIN) {
					assert(
						io->state == BDD_IO_STATE_CONNECTING &&
						io->substate == BDD_IO_CONNECTING_SUBSTATE_AGAIN
					);
					return bdd_io_connect_connecting;
				} else if (errno == EINPROGRESS) {
					io->substate = BDD_IO_CONNECTING_SUBSTATE_IN_PROGRESS;
					assert(
						io->state == BDD_IO_STATE_CONNECTING &&
						io->substate == BDD_IO_CONNECTING_SUBSTATE_IN_PROGRESS
					);
					return bdd_io_connect_connecting;
				} else if (errno != EINTR) {
					// failed to connect
					goto err;
				}
			}
			// connected
		}

		if (!io->ssl) {
			io->state = BDD_IO_STATE_ESTABLISHED;
			return bdd_io_connect_established;
		}
		io->state = BDD_IO_STATE_SSL_CONNECTING;
		io->state = BDD_IO_SSL_CONNECTING_SUBSTATE_WANTS_WRITE;
		goto ssl_connecting;
	} else if (io->state == BDD_IO_STATE_SSL_CONNECTING) {
		ssl_connecting:;
		int r = SSL_connect(io->io.ssl);
		if (r == -1) {
			int err = SSL_get_error(io->io.ssl, r);
			if (err == SSL_ERROR_WANT_WRITE) {
				io->substate = BDD_IO_SSL_CONNECTING_SUBSTATE_WANTS_WRITE;
				return bdd_io_connect_connecting;
			} else if (err == SSL_ERROR_WANT_READ) {
				io->substate = BDD_IO_SSL_CONNECTING_SUBSTATE_WANTS_READ;
				return bdd_io_connect_connecting;
			} else {
				goto err;
			}
		} else if (r == 0) {
			goto err;
		}

		io->state = BDD_IO_STATE_ESTABLISHED;
		return bdd_io_connect_established;
	}

	err:;
	if (err != NULL) {
		fputs(err, stderr);
		assert(false);
	}
	if (io->state != BDD_IO_STATE_UNUSED) {
		io->state = BDD_IO_STATE_BROKEN;
	}
	return bdd_io_connect_broken;
}

enum bdd_io_shutdown_state bdd_io_shutdown(struct bdd_conversation *conversation, bdd_io_id io_id) {
	const char *err = NULL;
	if (conversation == NULL || io_id < 0 || io_id >= bdd_conversation_n_max_io(conversation)) {
		err = "programming error: bdd_io_shutdown called with invalid arguments\n";
		goto err;
	}
	struct bdd_io *io = &(conversation->io[io_id]);
	if (io->state != BDD_IO_STATE_SSL_CONNECTING && io->state != BDD_IO_STATE_ESTABLISHED) {
		err = "programming error: bdd_io_shutdown called with an io_id which is in a state which is not BDD_IO_STATE_SSL_CONNECTING and is not BDD_IO_STATE_ESTABLISHED\n";
		goto err;
	}
	if (io->tcp) {
		if (
			(io->ssl && io->ssl_shut) ||
			(io->shut_wr)
		) {
			err = "programming error: bdd_io_shutdown called with an io_id which has already been shut-down\n";
			goto err;
		}
	} else {
		err = "programming error: bdd_io_shutdown called with an io_id which does not hold a tcp socket\n";
		goto err;
	}
	int fd;
	if (io->ssl) {
		fd = SSL_get_fd(io->io.ssl);
	} else {
		fd = io->io.fd;
	}
	fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) & ~O_NONBLOCK);
	if (io->ssl) {
		int r = SSL_shutdown(io->io.ssl);
		if (!io->shut_wr) {
			shutdown(fd, SHUT_WR);
			io->shut_wr = 1;
		}
		if (r == 0) {
			return bdd_io_shutdown_again;
		} else if (r < 0) {
			r = SSL_get_error(io->io.ssl, r);
			if (r == SSL_ERROR_WANT_WRITE) {
				io->substate = BDD_IO_SSL_CONNECTING_SUBSTATE_WANTS_WRITE;
				return bdd_io_shutdown_again;
			} else if (r == SSL_ERROR_WANT_READ) {
				io->substate = BDD_IO_SSL_CONNECTING_SUBSTATE_WANTS_READ;
				return bdd_io_shutdown_again;
			}
			goto err;
		} else {
			io->ssl_shut = 1;
		}
	} else {
		shutdown(io->io.fd, SHUT_WR);
		io->shut_wr = 1;
	}
	return bdd_io_shutdown_success;

	err:;
	if (err != NULL) {
		fputs(err, stderr);
		assert(false);
	}
	if (io->state != BDD_IO_STATE_UNUSED) {
		io->state = BDD_IO_STATE_BROKEN;
	}
	return bdd_io_shutdown_broken;
}
void bdd_io_remove(struct bdd_conversation *conversation, bdd_io_id io_id) {
	if (conversation == NULL || io_id < 0 || io_id >= bdd_conversation_n_max_io(conversation)) {
		fputs("programming error: bdd_io_remove called with invalid arguments\n", stderr);
		assert(false);
		return;
	}
	struct bdd_io *io = &(conversation->io[io_id]);
	if (io->state == BDD_IO_STATE_UNUSED) {
		fputs("programming error: bdd_io_remove called with an io_id which is in a state equal to BDD_IO_STATE_UNUSED\n", stderr);
		assert(false);
		// no point in setting the io's state to broken; this function doesn't even return a boolean
		return;
	}

	int fd;
	if (io->ssl) {
		fd = SSL_get_fd(io->io.ssl);
		SSL_free(io->io.ssl);
	} else {
		fd = io->io.fd;
	}
	shutdown(fd, SHUT_RDWR);
	close(fd);
	io->state = BDD_IO_STATE_UNUSED;
	return;
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

	conversation->release = 0;

	conversation->service = service;

	if ((conversation->io = malloc(sizeof(struct bdd_io) * service->n_max_io)) == NULL) {
		return bdd_conversation_init_failed;
	}

	conversation->io[0].state = BDD_IO_STATE_ESTABLISHED;
	conversation->io[0].tcp = 1;
	conversation->io[0].shut_wr = 0;
	conversation->io[0].ssl = 1;
	conversation->io[0].ssl_shut = 0;

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
			if (io->state == BDD_IO_STATE_UNUSED) {
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
	pthread_mutex_lock(&(instance->linked_conversations.mutex));
	conversation->next = instance->linked_conversations.head;
	instance->linked_conversations.head = conversation;
	bdd_signal(instance);
	pthread_mutex_unlock(&(instance->linked_conversations.mutex));
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