#include <errno.h>
#include <sys/epoll.h>
#include <openssl/ssl.h>
#include <poll.h>
#include <assert.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>

#include "headers/instance.h"
#include "headers/accept.h"
#include "headers/unlikely.h"
#include "headers/debug_log.h"
#include "headers/conversations.h"
#include "headers/name_descs.h"
#include "headers/bdd_service.h"
#include "headers/bdd_stop.h"

int bdd_alpn_cb(
	SSL *client_ssl,
	const unsigned char **out,
	unsigned char *outlen,
	const unsigned char *_,
	unsigned int __,
	struct bdd_conversation *conversation
) {
	const unsigned char *protocol_name = conversation->soac.ac.protocol_name;
	if (protocol_name == NULL) {
		return SSL_TLSEXT_ERR_NOACK;
	}
	*out = protocol_name + 1;
	*outlen = protocol_name[0];
	return SSL_TLSEXT_ERR_OK;
}

int bdd_hello_cb(SSL *client_ssl, int *alert, struct bdd_conversation *conversation) {
	struct hashmap *name_descs = bdd_gv.name_descs;
	struct hashmap_key key = HASHMAP_KEY_INITIALIZER;
	int r = SSL_CLIENT_HELLO_ERROR;
	const unsigned char *extension;
	size_t extension_sz;
	if (SSL_client_hello_get0_ext(client_ssl, TLSEXT_TYPE_server_name, &(extension), &(extension_sz)) == 0) {
		return SSL_CLIENT_HELLO_ERROR;
	}
	if (extension == NULL) {
		return SSL_CLIENT_HELLO_ERROR;
	}
	if (extension_sz <= 4) {
		return SSL_CLIENT_HELLO_ERROR;
	}
	if (unlikely(extension[2] != TLSEXT_NAMETYPE_host_name)) {
		return SSL_CLIENT_HELLO_ERROR;
	}

	unsigned short int name_sz = ntohs(*(unsigned short int *)(&(extension[3])));
	const unsigned char *name = (char *)&(extension[5]);

	if (name_sz >= 1 && name[name_sz - 1] == '.') {
		name_sz -= 1;
	}

	const unsigned char *alpn;
	size_t alpn_sz;
	if (SSL_client_hello_get0_ext(client_ssl, TLSEXT_TYPE_application_layer_protocol_negotiation, &(alpn), &(alpn_sz)) != 0) {
		if (alpn == NULL) {
			goto alpn_err;
		}
		if (alpn_sz <= 3) {
			goto alpn_err;
		}
		if ((size_t)ntohs(*(unsigned short int *)alpn) != alpn_sz - 2) {
			goto alpn_err;
		}
		// skip the 0 byte, and also skip the size byte
		alpn += 2;
		alpn_sz -= 2;
	} else {
		alpn_err:;
		alpn = NULL;
		alpn_sz = 0;
	}

	uint8_t found_req = 0;
	for (size_t idx = 0;;) {
		hashmap_key_obtain(
			name_descs,
			&(key),
			&(name[idx]),
			name_sz
		);
		struct bdd_name_desc *name_desc;
		if (hashmap_get(name_descs, &(key), (void *)&(name_desc))) {
			if (!(found_req & 0b01) && name_desc->x509 != NULL) {
				found_req |= 0b01;
				SSL_use_certificate(client_ssl, name_desc->x509);
				SSL_use_PrivateKey(client_ssl, name_desc->pkey);
			}
			struct bdd_service_instance *inst = name_desc->service_instances;
			if (!(found_req & 0b10) && inst != NULL) {
				struct bdd_service_instance *found = NULL;
				// the client has not sent the alpn extension
				if (alpn == NULL) {
					// use the first service instance in the linked list
					found = inst;
					goto skip_alpn;
				}

				// find the service which implements either the client's most preferred protocol, or a wildcard
				do {
					assert(inst->service != NULL);
					// the service's supported protocols
					const char *const *sp = inst->service->supported_protocols;
					// service supports any protocol (wildcard)
					if (sp == NULL) {
						// if we have not found any services which a more
						// specific protocol of the client's choice yet...
						if (found == NULL) {
							// ...then use this service
							found = inst;
							uint8_t alpn_len = alpn[0];
							// bounds checking
							if (alpn_len == 0 || alpn_sz - 1 < alpn_len) {
								return SSL_CLIENT_HELLO_ERROR;
							}
							assert(conversation->soac.ac.protocol_name == NULL);
							assert(conversation->soac.ac.cstr_protocol_name == NULL);
						}
						// skip the for loop
						goto alpn_find_iter;
					}
					// loop through the list of protocols that the client
					// prefers (over the currently selected one)
					for (uint8_t alpn_idx = 0; alpn_idx < alpn_sz;) {
						uint8_t alpn_len = alpn[alpn_idx];
						// bounds checking
						if (alpn_len == 0 || alpn_sz - 1 - alpn_idx < alpn_len) {
							return SSL_CLIENT_HELLO_ERROR;
						}
						// loop through the list of the service's supported protocols' names,
						// to hopefully find a match for the client's protocol's name
						for (size_t sp_idx = 0; sp[sp_idx] != NULL; ++sp_idx) {
							if (
								strncmp(
									&(alpn[alpn_idx + 1 /* length byte */]),
									sp[sp_idx],
									alpn_len
								) == 0
							) {
								alpn_sz = alpn_idx; // includes the length byte
								conversation->soac.ac.protocol_name = &(alpn[alpn_idx]);
								conversation->soac.ac.cstr_protocol_name = sp[sp_idx];
								found = inst;
								// the rest of the service's implemented protocols
								// cannot be more preferred by the client
								break;
							}
						}
						// skip over the current client protocol's length and its name
						alpn_idx += 1 + alpn_len;
					}
					if (alpn_sz == 0) {
						break;
					}
					alpn_find_iter:;
					inst = inst->next;
				} while (inst != NULL);

				if (found != NULL) {
					skip_alpn:;
					assert(found->service != NULL);
					conversation->sosi.service_instance = found;
					found_req |= 0b10;
				}
			}
			if (found_req == 0b11) {
				break;
			}
		}
		if (name_sz == 0) {
			*alert = SSL_AD_UNRECOGNIZED_NAME;
			goto out;
		}
		do {
			idx += 1;
			name_sz -= 1;
		} while (name_sz != 0 && name[idx] != '.');
	}
	r = SSL_CLIENT_HELLO_SUCCESS;
	out:;
	hashmap_key_release(bdd_gv.name_descs, &(key), false);
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

enum bdd_cont bdd_accept_continue(struct bdd_conversation *conversation, int epoll_fd) {
	struct bdd_io *io = &(conversation->client);
	SSL_CTX *ssl_ctx = SSL_get_SSL_CTX(io->io.ssl);
	SSL_CTX_set_client_hello_cb(ssl_ctx, (void *)bdd_hello_cb, conversation);
	SSL_CTX_set_alpn_select_cb(ssl_ctx, (void *)bdd_alpn_cb, conversation);
	int r = SSL_accept(io->io.ssl);
	if (r <= 0) {
		r = SSL_get_error(io->io.ssl, r);
		if (r == SSL_ERROR_WANT_WRITE || r == SSL_ERROR_WANT_READ) {
			return bdd_cont_inprogress;
		}
		return bdd_cont_discard;
	}
	int fd = bdd_io_internal_fd(io);

	struct bdd_service_instance *service_inst = conversation->sosi.service_instance;
	const char *cstr_protocol_name = conversation->soac.ac.cstr_protocol_name;

	conversation->sosi.service = service_inst->service;
	bdd_io_init(conversation, &(conversation->soac.server));

	struct sockaddr sockaddr;
	socklen_t socklen = sizeof(struct sockaddr);
	getsockname(fd, &(sockaddr), &(socklen));

	if (!service_inst->service->conversation_init(conversation, cstr_protocol_name, service_inst->instance_info, 0, sockaddr)) {
		return bdd_cont_discard;
	}

	if (conversation->state != bdd_conversation_connect) {
		fputs("programming error: conversation_init did not connect to anything\n", stderr);
		return bdd_cont_discard;
	}

	enum bdd_cont cont = bdd_connect_continue(conversation, epoll_fd);
	if (cont != bdd_cont_established) {
		io->in_epoll = 0;
		epoll_ctl(epoll_fd, EPOLL_CTL_DEL, fd, NULL);
	}
	return cont;
}
enum bdd_cont bdd_connect_continue(struct bdd_conversation *conversation, int epoll_fd) {
	bool est = true;
	if (conversation->state != bdd_conversation_connect && conversation->state != bdd_conversation_ssl_connect) {
		return bdd_cont_discard;
	}
	struct bdd_io *io = &(conversation->soac.server);
	if (conversation->state == bdd_conversation_connect) {
		struct pollfd pollfd = {
			.fd = bdd_io_internal_fd(io),
			.events = POLLOUT,
		};
		poll(&(pollfd), 1, 0);
		if (pollfd.revents & POLLERR) {
			return bdd_cont_discard;
		}
		if (!(pollfd.revents & POLLOUT)) {
			goto inprogress;
		}
		if (io->ssl) {
			conversation->state = bdd_conversation_ssl_connect;
		} else {
			goto established;
		}
	}
	assert(conversation->state == bdd_conversation_ssl_connect);
	int r = SSL_connect(io->io.ssl);
	if (r == -1) {
		r = SSL_get_error(io->io.ssl, r);
		if (r == SSL_ERROR_WANT_WRITE || r == SSL_ERROR_WANT_READ) {
			goto inprogress;
		}
		r = 0;
	}
	if (r == 0) {
		return bdd_cont_discard;
	}
	const unsigned char *alpn;
	unsigned int alpn_sz = 0;
	if (io->ssl_alpn) {
		SSL_get0_alpn_selected(io->io.ssl, &(alpn), &(alpn_sz));
		if (alpn == NULL) {
			return bdd_cont_discard;
		}
	}

	goto established;

	inprogress:;
	est = false;
	established:;
	conversation->state = bdd_conversation_established;
	struct epoll_event ev = {
		.events = EPOLLIN | EPOLLOUT | EPOLLET,
	};
	if (!io->in_epoll) {
		io->in_epoll = 1;
		ev.data.ptr = io;
		if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, bdd_io_internal_fd(io), &(ev)) != 0) {
			return bdd_cont_discard;
		}
	}
	if (est) {
		io = &(conversation->client);
		if (!io->in_epoll) {
			io->in_epoll = 1;
			ev.data.ptr = io;
			if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, bdd_io_internal_fd(io), &(ev)) != 0) {
				return bdd_cont_discard;
			}
		}
	}
	if (est) {
		return bdd_cont_established;
	}
	return bdd_cont_inprogress;
}

void *bdd_accept(void) {
	size_t worker_id = 0;
	struct bdd_worker_data *worker_data = bdd_gv_worker(worker_id);
	poll:;

	while (poll(bdd_gv.accept.pollfds, 2, -1) < 0) {
		if (errno != EINTR) {
			bdd_stop();
			break;
		}
	}

	struct bdd_conversation *conversation = bdd_conversation_obtain();
	if (conversation == NULL) {
		bdd_thread_exit();
	}
	SSL *ssl = SSL_new(worker_data->ssl_ctx);
	if (ssl == NULL) {
		goto err;
	}

	int fd = -1;

	// accept
	BDD_DEBUG_LOG("accepting tcp connection\n");
	do {
		fd = accept(bdd_gv.sv_socket, NULL, NULL);
	} while (fd < 0 && errno == EINTR);
	if (fd < 0) {
		BDD_DEBUG_LOG("rejected tcp connection\n");
		goto err;
	}
	BDD_DEBUG_LOG("accepted tcp connection\n");
	fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);

	if (!SSL_set_fd(ssl, fd)) {
		goto err;
	}

	struct bdd_io *io = &(conversation->client);
	conversation->state = bdd_conversation_accept;
	bdd_io_apply_ssl(io, ssl);
	ssl = NULL;

	pthread_mutex_lock(&(conversation->mutex));
	struct epoll_event ev = {
		.events = EPOLLIN | EPOLLOUT | EPOLLET,
		.data = {
			.ptr = io,
		},
	};
	io->in_epoll = 1;
	bool err = epoll_ctl(worker_data->epoll_fd, EPOLL_CTL_ADD, fd, &(ev)) != 0;
	if (!err) {
		bdd_tl_link(&(worker_data->timeout_list), conversation);
	}
	pthread_mutex_unlock(&(conversation->mutex));

	if (err) {
		goto err;
	}

	worker_id = (worker_id + 1) % bdd_gv.n_workers;
	worker_data = bdd_gv_worker(worker_id);

	goto poll;

	err:;
	BDD_DEBUG_LOG("failed to accept connection\n");
	bdd_conversation_discard(conversation, -1);
	if (ssl != NULL) {
		SSL_free(ssl);
	}
	close(fd);

	goto poll;
}
