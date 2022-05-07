#include "internal.h"

#include <errno.h>
#include <openssl/x509v3.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#define INST_CONNECTIONS (instance->connections)

int bdd_poll(struct bdd_connections *connections, struct bdd_poll_io *io_ids, bdd_io_id n_io_ids, int timeout) {
	if (connections == NULL || io_ids == NULL || n_io_ids == 0 ||
		n_io_ids > 0xff /* arbitrary limit; the array can technically be SIGNED_INT_MAX entries long, meaning that its greatest index may be SIGNED_INT_MAX - 1 */)
	{
		fputs("programming error: bdd_poll called with invalid arguments\n", stderr);
		assert(false);
		return false;
	}
	struct pollfd pollfds[n_io_ids]; // may overflow the stack if n_poll_io_ids is huge
	for (
		bdd_io_id idx = 0;
		idx < n_io_ids;
		++idx
	) {
		bdd_io_id io_id = io_ids[idx].io_id;
		if (io_id < 0 || io_id >= bdd_connections_n_max_io(connections)) {
			fputs("programming error: bdd_poll called with an out-of-bounds io_id\n", stderr);
			assert(false);
			return -1;
		}
		struct bdd_io *io = &(connections->io[io_id]);
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
	int n_revents = poll(pollfds, n_io_ids, timeout);
	if (n_revents < 0) {
		return n_revents;
	}
	for (
		bdd_io_id idx = 0;
		idx < n_io_ids;
		++idx
	) {
		bdd_io_id io_id = io_ids[idx].io_id;
		struct bdd_io *io = &(connections->io[io_id]);
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
	return n_revents;
}
__attribute__((warn_unused_result)) ssize_t bdd_read_internal(
	struct bdd_io *io,
	void *buf,
	ssize_t sz
) {
	/*if (sz <= 0) {
		return 0;
	}*/
	ssize_t r = 0;
	do {
		if (io->ssl) {
			r = SSL_read(io->io.ssl, buf, sz);
		} else {
			r = recv(io->io.fd, buf, sz, 0);
		}
	} while (r < 0 && errno == EINTR);
	return r;
}
__attribute__((warn_unused_result)) ssize_t bdd_read(
	struct bdd_connections *connections,
	bdd_io_id io_id,
	void *buf,
	ssize_t sz
) {
	if (connections == NULL || io_id < 0 || io_id >= bdd_connections_n_max_io(connections) || buf == NULL || sz <= 0) {
		fputs("programming error: bdd_read called with invalid arguments\n", stderr);
		assert(false);
		return false;
	}
	struct bdd_io *io = &(connections->io[io_id]);
	if (io->state != BDD_IO_STATE_ESTABLISHED) {
		fputs("programming error: bdd_read called with an io_id which is in a state not equal to BDD_IO_STATE_ESTABLISHED\n", stderr);
		assert(false);
		io->state = BDD_IO_STATE_BROKEN;
		return false;
	}
	return bdd_read_internal(io, buf, sz);
}

__attribute__((warn_unused_result)) ssize_t bdd_write_internal(
	struct bdd_io *io,
	void *buf,
	ssize_t sz
) {
	/*if (sz <= 0) {
		return 0;
	}*/
	ssize_t r = 0;
	do {
		if (io->ssl) {
			r = SSL_write(io->io.ssl, buf, sz);
		} else {
			r = send(io->io.fd, buf, sz, 0);
		}
	} while (r < 0 && errno == EINTR);
	return r;
}
__attribute__((warn_unused_result)) ssize_t bdd_write(
	struct bdd_connections *connections,
	bdd_io_id io_id,
	void *buf,
	ssize_t sz
) {
	if (connections == NULL || io_id < 0 || io_id >= bdd_connections_n_max_io(connections) || buf == NULL || sz <= 0) {
		fputs("programming error: bdd_write called with invalid arguments\n", stderr);
		assert(false);
		return false;
	}
	struct bdd_io *io = &(connections->io[io_id]);
	if (io->state != BDD_IO_STATE_ESTABLISHED) {
		fputs("programming error: bdd_write called with an io_id which is in a state not equal to BDD_IO_STATE_ESTABLISHED\n", stderr);
		assert(false);
		io->state = BDD_IO_STATE_BROKEN;
		return false;
	}
	return bdd_write_internal(io, buf, sz);
}

void bdd_set_associated(
	struct bdd_connections *connections,
	void *data,
	void (*destructor)(void *)
) {
	assert(connections != NULL);
	if (connections->associated.destructor != NULL) {
		connections->associated.destructor(connections->associated.data);
	}
#ifndef NDEBUG
	if (data != NULL || destructor != NULL) {
		assert(data != NULL && destructor != NULL);
	}
#endif
	connections->associated.data = data;
	connections->associated.destructor = destructor;
	return;
}

// thread-unsafe
bool bdd_io_create(
	struct bdd_connections *connections,
	bdd_io_id *io_id,
	int domain,
	int type,
	int protocol
) {
	if (connections == NULL || io_id == NULL) {
		fputs("programming error: bdd_io_create called with invalid arguments\n", stderr);
		assert(false);
		return false;
	}
	struct bdd_io *io = NULL;
	bdd_io_id idx = 0;
	for (; idx < bdd_connections_n_max_io(connections); ++idx) {
		if (connections->io[idx].state == BDD_IO_STATE_UNUSED) {
			io = &(connections->io[idx]);
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
	io->connect_stage = BDD_IO_CONNECT_STAGE_CONNECT;
	io->connect_state = BDD_IO_CONNECT_STATE_WANTS_CALL;
	io->tcp = (type & ~(SOCK_NONBLOCK | SOCK_CLOEXEC)) == SOCK_STREAM ? 1 : 0;
	io->shutdown = 0;
	io->ssl = 0;
	io->io.fd = fd;
	(*io_id) = idx;
	return true;
}

bool bdd_io_prep_ssl(struct bdd_connections *connections, bdd_io_id io_id, char *ssl_name) {
	if (connections == NULL || io_id < 0 || io_id >= bdd_connections_n_max_io(connections) || ssl_name == NULL) {
		fputs("programming error: bdd_io_prep_ssl called with invalid arguments\n", stderr);
		assert(false);
		return false;
	}
	struct bdd_io *io = &(connections->io[io_id]);
	if (io->state != BDD_IO_STATE_CREATED) {
		fputs("programming error: bdd_io_prep_ssl called with an io_id which is in a state not equal to BDD_IO_STATE_CREATED\n", stderr);
		assert(false);
		io->state = BDD_IO_STATE_BROKEN;
		return false;
	}
	if (!io->tcp) {
		fputs("programming error: bdd_io_prep_ssl called with an io_id which does not use tcp\n", stderr);
		assert(false);
		io->state = BDD_IO_STATE_BROKEN;
		return false;
	}
	if (io->ssl) {
		fputs("programming error: bdd_io_prep_ssl called with an io_id which already has ssl prepared\n", stderr);
		assert(false);
		io->state = BDD_IO_STATE_BROKEN;
		return false;
	}

	SSL *ssl = SSL_new(BDD_GLOBAL_CL_SSL_CTX);
	if (ssl == NULL) {
		SSL_free(ssl);
		io->state = BDD_IO_STATE_BROKEN;
		return false;
	}
	SSL_set_fd(ssl, io->io.fd);
	// sni
	// to-do: does this strdup?
	if (unlikely(!SSL_set_tlsext_host_name(ssl, ssl_name))) {
		SSL_free(ssl);
		io->state = BDD_IO_STATE_BROKEN;
		return false;
	}
	// hostname vertification
	SSL_set_hostflags(ssl, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
	// to-do: does this strdup?
	if (!SSL_set1_host(ssl, ssl_name)) {
		SSL_free(ssl);
		io->state = BDD_IO_STATE_BROKEN;
		return false;
	}
	SSL_set_verify(ssl, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);

	io->ssl = 1;
	io->io.ssl = ssl;

	return true;
}

enum bdd_io_connect_status bdd_io_connect(struct bdd_connections *connections, bdd_io_id io_id, struct sockaddr *addr, socklen_t addrlen) {
	if (connections == NULL || io_id < 0 || io_id >= bdd_connections_n_max_io(connections)) {
		fputs("programming error: bdd_io_connect called with invalid arguments\n", stderr);
		assert(false);
		return bdd_io_connect_err;
	}
	struct bdd_io *io = &(connections->io[io_id]);
	if (addr == NULL && io->connect_state == BDD_IO_CONNECT_STATE_WANTS_CALL) {
		fputs("programming error: bdd_io_connect called with invalid arguments\n", stderr);
		assert(false);
		return bdd_io_connect_err;
	}
	if (io->state != BDD_IO_STATE_CREATED) {
		fputs("programming error: bdd_io_connect called with an io_id which is in a state not equal to BDD_IO_STATE_CREATED\n", stderr);
		assert(false);
		io->state = BDD_IO_STATE_BROKEN;
		return bdd_io_connect_broken;
	}

	int fd;
	if (!io->ssl) {
		fd = io->io.fd;
	} else {
		fd = SSL_get_fd(io->io.ssl);
		assert(fd >= 0);
	}

	if (io->connect_stage == BDD_IO_CONNECT_STAGE_CONNECT) {
		if (io->connect_state == BDD_IO_CONNECT_STATE_WANTS_CALL) {
			io->connect_state = BDD_IO_CONNECT_STATE_WANTS_CALL_ONCE_WRITABLE;
			if (connect(fd, addr, addrlen) != 0) {
				if (errno == EAGAIN || errno == EINPROGRESS) {
					return bdd_io_connect_connecting;
				}
				// failed to connect
				io->state = BDD_IO_STATE_BROKEN;
				return bdd_io_connect_broken;
			}
		} else if (io->connect_state != BDD_IO_CONNECT_STATE_WANTS_CALL_ONCE_WRITABLE) {
			fputs("bdd_io_connect internal error\n", stderr);
			assert(false);
			io->state = BDD_IO_STATE_BROKEN;
			return bdd_io_connect_broken;
		}
		if (!io->ssl) {
			io->state = BDD_IO_STATE_ESTABLISHED;
			return bdd_io_connect_established;
		}
		io->connect_stage = BDD_IO_CONNECT_STAGE_SSL_CONNECT;
	}
	assert(io->connect_stage == BDD_IO_CONNECT_STAGE_SSL_CONNECT && io->connect_state != BDD_IO_CONNECT_STATE_WANTS_CALL); // this should be guaranteed to pass

	int r = SSL_connect(io->io.ssl);
	if (r == -1) {
		int err = SSL_get_error(io->io.ssl, r);
		if (err == SSL_ERROR_WANT_WRITE) {
			io->connect_state = BDD_IO_CONNECT_STATE_WANTS_CALL_ONCE_WRITABLE;
			return bdd_io_connect_connecting;
		} else if (err == SSL_ERROR_WANT_READ) {
			io->connect_state = BDD_IO_CONNECT_STATE_WANTS_CALL_ONCE_READABLE;
			return bdd_io_connect_connecting;
		} else {
			io->state = BDD_IO_STATE_BROKEN;
			return bdd_io_connect_broken;
		}
	} else if (r == 0) {
		io->state = BDD_IO_STATE_BROKEN;
		return bdd_io_connect_broken;
	}

	io->state = BDD_IO_STATE_ESTABLISHED;
	return bdd_io_connect_established;
}

void bdd_io_shutdown(struct bdd_connections *connections, bdd_io_id io_id) {
	if (connections == NULL || io_id < 0 || io_id >= bdd_connections_n_max_io(connections)) {
		fputs("programming error: bdd_io_shutdown called with invalid arguments\n", stderr);
		assert(false);
		return;
	}
	struct bdd_io *io = &(connections->io[io_id]);
	if (io->state == BDD_IO_STATE_UNUSED) {
		fputs("programming error: bdd_io_shutdown called with an io_id which is in a state equal to BDD_IO_STATE_UNUSED\n", stderr);
		assert(false);
		return;
	}
	if (io->state == BDD_IO_STATE_BROKEN) {
		fputs("programming error: bdd_io_shutdown called with an io_id which is in a state equal to BDD_IO_STATE_BROKEN\n", stderr);
		assert(false);
		return;
	}
	// to-do: can you shutdown a non-blocking socket while it's connecting?
	if (io->connect_state == BDD_IO_CONNECT_STATE_WANTS_CALL) {
		assert(io->state == BDD_IO_STATE_CREATED);
		fputs("programming error: bdd_io_shutdown called with an io_id which is in a connect state equal to BDD_IO_CONNECT_STATE_WANTS_CALL\n", stderr);
		assert(false);
		return;
	}
	if (!io->tcp) {
		fputs("programming error: bdd_io_shutdown called with an io_id which does not hold a tcp socket\n", stderr);
		assert(false);
		return;
	}
	if (io->shutdown) {
		fputs("programming error: bdd_io_shutdown called with an io_id which has already been shut-down\n", stderr);
		assert(false);
		return;
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
		shutdown(fd, SHUT_WR);
		if (r == 0) {
			SSL_shutdown(io->io.ssl);
		}
	} else {
		shutdown(io->io.fd, SHUT_WR);
	}
	io->shutdown = 1;
	return;
}
void bdd_io_remove(struct bdd_connections *connections, bdd_io_id io_id) {
	if (connections == NULL || io_id < 0 || io_id >= bdd_connections_n_max_io(connections)) {
		fputs("programming error: bdd_io_remove called with invalid arguments\n", stderr);
		assert(false);
		return;
	}
	struct bdd_io *io = &(connections->io[io_id]);
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
	shutdown(fd, SHUT_RD);
	close(fd);
	io->state = BDD_IO_STATE_UNUSED;
	return;
}

enum bdd_connections_init_status bdd_connections_init(
	struct bdd_connections *connections,
	SSL **client_ssl_ref,
	struct sockaddr client_sockaddr,
	const struct bdd_service *service,
	const char *protocol_name,
	void *instance_info
) {
	assert(service->n_max_io > 0);
	SSL *client_ssl = (*client_ssl_ref);
	(*client_ssl_ref) = NULL;
	if ((connections->io = malloc(sizeof(struct bdd_io) * service->n_max_io)) == NULL) {
		SSL_free(client_ssl);
		return bdd_connections_init_failed;
	}
	connections->service = service;
	connections->io[0].state = BDD_IO_STATE_ESTABLISHED;
	connections->io[0].connect_state = BDD_IO_CONNECT_STATE_DO_NOT_CALL;
	connections->io[0].tcp = 1;
	connections->io[0].shutdown = 0;
	connections->io[0].ssl = 1;
	connections->io[0].io.ssl = client_ssl;
	for (bdd_io_id idx = 1; idx < service->n_max_io; ++idx) {
		connections->io[idx].state = BDD_IO_STATE_UNUSED;
	}
	if (service->connections_init != NULL &&
		!service->connections_init(connections, protocol_name, instance_info, 0, client_sockaddr))
	{
		return bdd_connections_init_failed_wants_deinit;
	}
	return bdd_connections_init_success;
}
void bdd_connections_deinit(struct bdd_connections *connections) {
	if (connections->io != NULL) {
		for (bdd_io_id io_id = 0; io_id < bdd_connections_n_max_io(connections); ++io_id) {
			struct bdd_io *io = &(connections->io[io_id]);
			if (io->state == BDD_IO_STATE_UNUSED) {
				continue;
			}
			bdd_io_remove(connections, io_id);
		}
		free(connections->io);
		connections->io = NULL;
	}
	bdd_set_associated(connections, NULL, NULL);
	connections->working = false;
	connections->broken = false;
	return;
}
void bdd_connections_link(struct bdd_instance *instance, struct bdd_connections **connections_ref) {
	assert(connections_ref != NULL);
	struct bdd_connections *connections = (*connections_ref);
	(*connections_ref) = NULL;
	assert(connections != NULL);
	pthread_mutex_lock(&(instance->linked_connections.mutex));
	connections->next = instance->linked_connections.head;
	instance->linked_connections.head = connections;
	bdd_signal(instance);
	pthread_mutex_unlock(&(instance->linked_connections.mutex));
	return;
}
struct bdd_connections *bdd_connections_obtain(struct bdd_instance *instance) {
	struct bdd_connections *connections = NULL;
	pthread_mutex_lock(&(INST_CONNECTIONS.available_mutex));
	while (!atomic_load(&(instance->exiting)) && INST_CONNECTIONS.available_idx == INST_CONNECTIONS.n_connections) {
		pthread_cond_wait(&(INST_CONNECTIONS.available_cond), &(INST_CONNECTIONS.available_mutex));
	}
	if (!atomic_load(&(instance->exiting))) {
		// todo: i should maybe make this *not* an int
		int id = INST_CONNECTIONS.available[INST_CONNECTIONS.available_idx++];
		connections = &(INST_CONNECTIONS.connections[id]);
	}
	pthread_mutex_unlock(&(INST_CONNECTIONS.available_mutex));
	return connections;
}
void bdd_connections_release(struct bdd_instance *instance, struct bdd_connections **connections_ref) {
	assert(connections_ref != NULL);

	struct bdd_connections *connections = (*connections_ref);
	(*connections_ref) = NULL;
	assert(connections != NULL);

	pthread_mutex_lock(&(INST_CONNECTIONS.available_mutex));

	assert(INST_CONNECTIONS.available_idx != 0);

	int id = bdd_connections_id(instance, connections);

	assert(id >= 0 && id < INST_CONNECTIONS.n_connections);

	INST_CONNECTIONS.available[--(INST_CONNECTIONS.available_idx)] = id;

	pthread_cond_signal(&(INST_CONNECTIONS.available_cond));
	pthread_mutex_unlock(&(INST_CONNECTIONS.available_mutex));

	return;
}
