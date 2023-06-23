#include <errno.h>
#include <pthread.h>
#include <sys/epoll.h>
#include <openssl/ssl.h>
#include <poll.h>
#include <assert.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <netinet/in.h>

#include "headers/bdd_cont.h"
#include "headers/instance.h"
#include "headers/accept.h"
#include "headers/serve.h"
#include "headers/unlikely.h"
#include "headers/debug_log.h"
#include "headers/conversations.h"
#include "headers/name_descs.h"
#include "headers/bdd_service.h"
#include "headers/bdd_stop.h"
#include "headers/hashmap.h"

int bdd_alpn_cb(
	SSL *client_ssl,
	const unsigned char **out,
	unsigned char *outlen,
	const unsigned char *_,
	unsigned int __,
	struct bdd_ssl_cb_ctx *___
) {
	uintptr_t find = (uintptr_t)&(client_ssl);
	struct bdd_ssl_cb_ctx *ctx;
	for (size_t it = 0; it < 0x4000; ++it) {
		if (*(uintptr_t *)(find + it) == 0x9072348923641788) {
			ctx = *(struct bdd_ssl_cb_ctx **)(find + it + 8);
			break;
		}
	}

	const unsigned char *protocol_name = ctx->protocol_name;
	if (protocol_name == NULL) {
		return SSL_TLSEXT_ERR_NOACK;
	}
	*out = protocol_name + 1;
	*outlen = protocol_name[0];
	return SSL_TLSEXT_ERR_OK;
}

int bdd_hello_cb(SSL *client_ssl, int *alert, struct bdd_ssl_cb_ctx *_) {
	uintptr_t find = (uintptr_t)&(client_ssl);
	struct bdd_ssl_cb_ctx *ctx = NULL;
	for (size_t it = 0; it < 0x8000; ++it) {
		if (*(uintptr_t *)(find + it) == 0x9072348923641788) {
			ctx = *(struct bdd_ssl_cb_ctx **)(find + it + 8);
			break;
		}
	}

	struct bdd_conversation *conversation = ctx->conversation;
	struct hashmap *name_descs = bdd_gv.name_descs;
	struct hashmap_key key;
	int r = SSL_CLIENT_HELLO_ERROR;
	const unsigned char *extension;
	size_t extension_sz;
	if (SSL_client_hello_get0_ext(client_ssl, TLSEXT_TYPE_server_name, &(extension), &(extension_sz)) == 0) {
		return SSL_CLIENT_HELLO_ERROR;
	}
	if (extension == NULL) {
		return SSL_CLIENT_HELLO_ERROR;
	}
	if (extension_sz < 5) {
		return SSL_CLIENT_HELLO_ERROR;
	}
	if (unlikely(extension[2] != TLSEXT_NAMETYPE_host_name)) {
		return SSL_CLIENT_HELLO_ERROR;
	}

	size_t name_sz = (size_t)ntohs(*(unsigned short int *)(&(extension[3])));
	if (extension_sz != 5 + name_sz) {
		return SSL_CLIENT_HELLO_ERROR;
	}
	const char *name = (const char *)&(extension[5]);

	name = bdd_name(name, &(name_sz));
	if (unlikely(name == NULL)) {
		return SSL_CLIENT_HELLO_ERROR;
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
		alpn += 2;
		alpn_sz -= 2;
	} else {
		alpn_err:;
		alpn = NULL;
		alpn_sz = 0;
	}

	uint8_t found_req = 0;
	for (size_t idx = 0;;) {
		hashmap_key(
			(void *)&(name[idx]),
			name_sz,
			&(key)
		);
		struct bdd_name_desc *name_desc;
		if (hashmap_cas(name_descs, ctx->area, &(key), (void **)&(name_desc), NULL, hashmap_cas_get, (void *)1) == hashmap_cas_again) {
			if (!(found_req & 0b01) && name_desc->x509 != NULL) {
				found_req |= 0b01;
				// this does up the rc
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
						// if we have not found any services that suppprt a
						// more specific protocol of the client's choice yet...
						if (found == NULL) {
							// ...then use this service
							found = inst;
							assert(ctx->protocol_name == NULL);
							assert(ctx->cstr_protocol_name == NULL);
						}
						// skip the for loop
						goto alpn_find_iter;
					}
					// loop through the list of protocols that the client
					// prefers (over the currently selected one)
					for (uint16_t alpn_idx = 0; alpn_idx < alpn_sz;) {
						uint8_t alpn_len = alpn[alpn_idx];
						// bounds checking
						if (alpn_len == 0 || alpn_sz - 1 - alpn_idx < alpn_len) {
							pthread_rwlock_unlock(&(name_desc->rwlock));
							return SSL_CLIENT_HELLO_ERROR;
						}
						// loop through the list of the service's supported protocols' names,
						// to hopefully find a match for the client's protocol's name
						for (size_t sp_idx = 0; sp[sp_idx] != NULL; ++sp_idx) {
							if (
								strncmp(
									(const char *)&(alpn[alpn_idx + 1 /* length byte */]),
									sp[sp_idx],
									alpn_len
								) == 0
							) {
								alpn_sz = alpn_idx; // includes the length byte
								ctx->protocol_name = &(alpn[alpn_idx]);
								ctx->cstr_protocol_name = sp[sp_idx];
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

			pthread_rwlock_unlock(&(name_desc->rwlock));

			if (found_req == 0b11) {
				break;
			}
		}
		if (name_sz == 0) {
			*alert = SSL_AD_UNRECOGNIZED_NAME;
			return SSL_CLIENT_HELLO_ERROR;
		}
		do {
			idx += 1;
			name_sz -= 1;
		} while (name_sz != 0 && name[idx] != '.');
	}

	return SSL_CLIENT_HELLO_SUCCESS;
}

void *gbl;

enum bdd_cont bdd_accept_continue(SSL_CTX *ssl_ctx, struct bdd_ssl_cb_ctx *ctx) {
	struct bdd_conversation *conversation = ctx->conversation;
	struct bdd_io *io = conversation->io_array;

	// openssl is _genuinely_ retarded
	// i am pretty sure there's no avoiding this
	uintptr_t buf[2];
	buf[0] = 0x9072348923641788;
	buf[1] = (uintptr_t)ctx;
	gbl = &(buf);

	SSL_set_SSL_CTX(io->io.ssl, ssl_ctx);
	int r = SSL_accept(io->io.ssl);
	if (r <= 0) {
		r = SSL_get_error(io->io.ssl, r);
		if (r == SSL_ERROR_WANT_WRITE || r == SSL_ERROR_WANT_READ) {
			return bdd_cont_inprogress;
		}
		return bdd_cont_conversation_discard;
	}

	BDD_CONVERSATION_AGE_MS(conversation, "accept");

	int fd = bdd_io_fd(io);

	struct bdd_service_instance *service_inst = conversation->sosi.service_instance;
	conversation->sosi.service = service_inst->service;
	const char *cstr_protocol_name = ctx->cstr_protocol_name;
	conversation->associated.data = NULL;
	conversation->associated.destructor = NULL;
	conversation->state = bdd_conversation_established;

	struct sockaddr sockaddr;
	socklen_t socklen = sizeof(struct sockaddr);
	getsockname(fd, &(sockaddr), &(socklen));

	struct epoll_event ev = {
		.events = EPOLLIN,
		.data = { .ptr = io, },
	};
	if (epoll_ctl(conversation->epoll_inst, EPOLL_CTL_MOD, fd, &(ev)) != 0) {
		abort();
	}

	if (
		service_inst->service->conversation_init != NULL &&
		!service_inst->service->conversation_init(conversation, cstr_protocol_name, service_inst->instance_info, 0, sockaddr)
	) {
		return bdd_cont_conversation_discard;
	}

	return bdd_cont_established;
}
enum bdd_cont bdd_connect_continue(struct bdd_io *io) {
	if (!io->ssl) {
		return bdd_cont_established;
	}
	int r = SSL_connect(io->io.ssl);
	if (r == -1) {
		r = SSL_get_error(io->io.ssl, r);
		if (r == SSL_ERROR_WANT_WRITE || r == SSL_ERROR_WANT_READ) {
			return bdd_cont_inprogress;
		}
		return bdd_cont_discard;
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
	return bdd_cont_established;
}

void bdd_accept(SSL_CTX *ssl_ctx) {
	struct bdd_conversation *conversation = NULL;

	SSL *ssl = SSL_new(ssl_ctx);
	int fd = -1;
	if (ssl == NULL) {
		goto err;
	}

	// accept
	fd = accept(bdd_gv.serve_fd, NULL, NULL);
	if (fd < 0) {
		BDD_DEBUG_LOG("rejected tcp connection\n");
		goto err;
	}
	fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);

	conversation = bdd_conversation_obtain();
	if (conversation == NULL) {
		return;
	}

	if (!SSL_set_fd(ssl, fd)) {
		goto err;
	}

	struct bdd_io *io = conversation->io_array;
	struct epoll_event ev = {
		.events = EPOLLIN | EPOLLOUT | EPOLLET,
		.data = { .ptr = io, },
	};
	if (epoll_ctl(conversation->epoll_inst, EPOLL_CTL_ADD, fd, &(ev)) != 0) {
		goto err;
	}

	ev = bdd_epoll_conv(conversation);
	if (epoll_ctl(bdd_gv.epoll_fd, EPOLL_CTL_MOD, conversation->epoll_inst, &(ev)) != 0) {
		abort();
	}

	conversation->state = bdd_conversation_accept;
	conversation->n_in_epoll_with_events = 1;

	io->state = bdd_io_est;

	io->rdhup = 0;
	io->wrhup = 0;

	io->ssl = 1;
	io->ssl_alpn = 0;

	io->in_epoll = 1;

	io->epoll_events = bdd_epoll_in;

	io->io.ssl = ssl;

	return;

	err:;
	BDD_DEBUG_LOG("failed to accept connection\n");
	if (conversation != NULL) {
		bdd_conversation_discard(conversation);
	}
	if (ssl != NULL) {
		SSL_free(ssl);
	}
	close(fd);

	return;
}
