#include "internal.h"
#include <string.h>
#include <errno.h>
#include <openssl/x509v3.h>
#include <unistd.h>

__attribute__((warn_unused_result)) int bdd_poll(struct bdd_connections *connections, bdd_io_id io_id) {
	assert(connections != NULL && io_id >= 0 && io_id < bdd_connections_n_max_io(connections));
	struct bdd_io *io = &(connections->io[io_id]);
	assert(io->fd != -1);
	struct pollfd pollfd = {
		.fd = io->fd,
		.events = POLLIN | POLLOUT | POLLRDHUP,
		.revents = 0,
	};
	poll(&(pollfd), 1, 0);
	if (io->ssl != NULL && SSL_has_pending(io->ssl)) {
		pollfd.revents |= POLLIN;
	}
	return pollfd.revents;
}
__attribute__((warn_unused_result)) ssize_t bdd_read_internal(struct bdd_io *io, void *buf, ssize_t sz) {
	if (sz <= 0) {
		return 0;
	}
	ssize_t r = 0;
	do {
		if (io->ssl != NULL) {
			r = SSL_read(io->ssl, buf, sz);
		} else {
			r = recv(io->fd, buf, sz, 0);
		}
	} while (r < 0 && errno == EINTR);
	return r;
}
__attribute__((warn_unused_result)) ssize_t bdd_read(struct bdd_connections *connections, bdd_io_id io_id, void *buf, ssize_t sz) {
	assert(connections != NULL && io_id >= 0 && io_id < bdd_connections_n_max_io(connections));
	struct bdd_io *io = &(connections->io[io_id]);
	assert(io->fd != -1);
	return bdd_read_internal(io, buf, sz);
}
__attribute__((warn_unused_result)) ssize_t bdd_read_whole(struct bdd_connections *connections, bdd_io_id io_id, void *buf, ssize_t sz) {
	assert(connections != NULL && io_id >= 0 && io_id < bdd_connections_n_max_io(connections));
	struct bdd_io *io = &(connections->io[io_id]);
	assert(io->fd != -1);
	ssize_t n = 0;
	while (n < sz) {
		ssize_t r = bdd_read_internal(io, buf + n, sz - n);
		if (r < 0) {
			return r;
		} else if (r == 0) {
			return n;
		}
		n += r;
	}
	return n;
}

__attribute__((warn_unused_result)) ssize_t bdd_write_internal(struct bdd_io *io, void *buf, ssize_t sz) {
	if (sz <= 0) {
		return 0;
	}
	ssize_t r = 0;
	do {
		if (io->ssl != NULL) {
			r = SSL_write(io->ssl, buf, sz);
		} else {
			r = send(io->fd, buf, sz, 0);
		}
	} while (r < 0 && errno == EINTR);
	return r;
}
__attribute__((warn_unused_result)) ssize_t bdd_write(struct bdd_connections *connections, bdd_io_id io_id, void *buf, ssize_t sz) {
	assert(connections != NULL && io_id >= 0 && io_id < bdd_connections_n_max_io(connections));
	struct bdd_io *io = &(connections->io[io_id]);
	assert(io->fd != -1);
	return bdd_write_internal(io, buf, sz);
}
__attribute__((warn_unused_result)) ssize_t bdd_write_whole(struct bdd_connections *connections, bdd_io_id io_id, void *buf, ssize_t sz) {
	assert(connections != NULL && io_id >= 0 && io_id < bdd_connections_n_max_io(connections));
	struct bdd_io *io = &(connections->io[io_id]);
	assert(io->fd != -1);
	ssize_t n = 0;
	while (n < sz) {
		ssize_t r = bdd_write_internal(io, buf + n, sz - n);
		if (r < 0) {
			return r;
		} else if (r == 0) {
			return n;
		}
		n += r;
	}
	return n;
}

void bdd_set_associated(struct bdd_connections *connections, void *data, void (*destructor)(void *)) {
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
bool bdd_create_io(struct bdd_connections *connections, bdd_io_id *io_id, int *fd, char *ssl_name) {
	assert(connections != NULL && io_id != NULL);
	struct bdd_io *io = NULL;
	bdd_io_id idx = 0;
	for (; idx < bdd_connections_n_max_io(connections); ++idx) {
		if (connections->io[idx].fd == -1) {
			io = &(connections->io[idx]);
			break;
		}
	}
	assert(io != NULL);
	if (unlikely(io == NULL)) {
		return false;
	}
	SSL *ssl = NULL;
	if (ssl_name != NULL) {
		// i think it's not finna write to the ctx, so a global mutex lock is not required here
		// also, BDD_GLOBAL_CL_SSL_CTX is guaranteed to be valid here
		if ((ssl = SSL_new(BDD_GLOBAL_CL_SSL_CTX)) == NULL) {
			return false;
		}
		if (unlikely(!SSL_set_fd(ssl, (*fd)))) {
			SSL_free(ssl);
			return false;
		}
		SSL_set_hostflags(ssl, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
		if (unlikely(!SSL_set_tlsext_host_name(ssl, ssl_name) || !SSL_set1_host(ssl, ssl_name))) {
			SSL_free(ssl);
			return false;
		}
		SSL_set_verify(ssl, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
		if (SSL_connect(ssl) != 1) {
			SSL_free(ssl);
			return false;
		}
	}
	io->fd = (*fd);
	io->ssl = ssl;
	(*fd) = -1;
	(*io_id) = idx;
	return true;
}
void bdd_remove_io(struct bdd_connections *connections, bdd_io_id io_id) {
	assert(connections != NULL && io_id >= 0 && io_id < bdd_connections_n_max_io(connections));
	struct bdd_io *io = &(connections->io[io_id]);
	assert(io->fd >= 0);
	if (io->ssl != NULL) {
		SSL_shutdown(io->ssl);
		SSL_free(io->ssl);
	} else {
		shutdown(io->fd, SHUT_RDWR);
	}
	close(io->fd);
	io->fd = -1;
	return;
}

enum bdd_connections_init_status bdd_connections_init(struct bdd_connections *connections, SSL **client_ssl, struct sockaddr client_sockaddr, const struct bdd_internal_service *service, void *service_info) {
	assert(service->n_max_io > 0);
	if ((connections->io = malloc(sizeof(struct bdd_io) * service->n_max_io)) == NULL) {
		return bdd_connections_init_failed;
	}
	connections->service = service;
	connections->io[0].fd = SSL_get_fd((*client_ssl));
	connections->io[0].ssl = (*client_ssl);
	(*client_ssl) = NULL;
	for (bdd_io_id idx = 1; idx < service->n_max_io; ++idx) {
		connections->io[idx].fd = -1;
		connections->io[idx].ssl = NULL;
	}
	if (service->connections_init != NULL && !service->connections_init(connections, service_info, 0, client_sockaddr)) {
		return bdd_connections_init_failed_wants_deinit;
	}
	return bdd_connections_init_success;
}
void bdd_connections_deinit(struct bdd_connections *connections) {
	if (connections->io != NULL) {
		for (bdd_io_id io_id = 0; io_id < bdd_connections_n_max_io(connections); ++io_id) {
			struct bdd_io *io = &(connections->io[io_id]);
			if (io->fd < 0) {
				continue;
			}
			bdd_remove_io(connections, io_id);
		}
		free(connections->io);
		connections->io = NULL;
	}
	bdd_set_associated(connections, NULL, NULL);
	connections->working = false;
	connections->broken = false;
	return;
}
void bdd_connections_link(struct bdd_instance *instance, struct bdd_connections **_connections) {
	assert(_connections != NULL);
	struct bdd_connections *connections = (*_connections);
	assert(connections != NULL);
	pthread_mutex_lock(&(instance->linked_connections.mutex));
	connections->next = instance->linked_connections.head;
	instance->linked_connections.head = connections;
	bdd_signal(instance);
	pthread_mutex_unlock(&(instance->linked_connections.mutex));
	(*_connections) = NULL;
	return;
}
struct bdd_connections *bdd_connections_obtain(struct bdd_instance *instance) {
	if (instance->connections.n_connections <= 0) {
		return NULL;
	}
	struct bdd_connections *connections = NULL;
	pthread_mutex_lock(&(instance->connections.available_mutex));
	while (!atomic_load(&(instance->exiting)) && instance->connections.available_idx == instance->connections.n_connections) {
		pthread_cond_wait(&(instance->connections.available_cond), &(instance->connections.available_mutex));
	}
	if (!atomic_load(&(instance->exiting))) {
		connections = &(instance->connections.connections[instance->connections.available[instance->connections.available_idx++]]);
	}
	pthread_mutex_unlock(&(instance->connections.available_mutex));
	return connections;
}
void bdd_connections_release(struct bdd_instance *instance, struct bdd_connections **_connections) {
	assert(_connections != NULL);
	struct bdd_connections *connections = (*_connections);
	assert(connections != NULL);
	pthread_mutex_lock(&(instance->connections.available_mutex));
	assert(instance->connections.available_idx != 0);
	int id = bdd_connections_id(instance, connections);
	assert(id >= 0 && id < instance->connections.n_connections);
	instance->connections.available[--(instance->connections.available_idx)] = id;
	pthread_cond_signal(&(instance->connections.available_cond));
	pthread_mutex_unlock(&(instance->connections.available_mutex));
	(*_connections) = NULL;
	return;
}
