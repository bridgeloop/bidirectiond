#include <errno.h>
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
#include "headers/signal.h"

int bdd_alpn_cb(
	SSL *client_ssl,
	const unsigned char **out,
	unsigned char *outlen,
	const unsigned char *_,
	unsigned int __,
	struct bdd_instance *instance
) {
	struct bdd_accept_ctx *ctx = &(instance->accept.ctx);
	if (ctx->protocol_name == NULL) {
		return SSL_TLSEXT_ERR_NOACK;
	}
	*out = ctx->protocol_name + 1;
	*outlen = ctx->protocol_name[0];
	return SSL_TLSEXT_ERR_OK;
}

int bdd_hello_cb(SSL *client_ssl, int *alert, struct bdd_instance *instance) {
	struct bdd_accept_ctx *ctx = &(instance->accept.ctx);
	struct hashmap *name_descs = instance->name_descs;
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
							assert(ctx->protocol_name == NULL);
							assert(ctx->cstr_protocol_name == NULL);
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
					ctx->service_instance = found;
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
	hashmap_key_release(instance->name_descs, &(key), false);
	return r;
}

void *bdd_accept(struct bdd_instance *instance) {
	struct bdd_accept_ctx *ctx = &(instance->accept.ctx);
	poll:;
	while (poll(instance->accept.pollfds, 2, -1) < 0) {
		if (errno != EINTR) {
			bdd_stop(instance);
			break;
		}
	}
	if (unlikely(atomic_load(&(instance->exiting)))) {
		bdd_thread_exit(instance);
	}

	struct bdd_conversation *conversation = NULL;
	SSL *client_ssl = NULL;
	ctx->service_instance = NULL;
	ctx->protocol_name = NULL;
	ctx->cstr_protocol_name = NULL;
	int cl_socket = -1;
	conversation = bdd_conversation_obtain(instance);
	assert(conversation != NULL);
	if ((client_ssl = SSL_new(instance->accept.ssl_ctx)) == NULL) {
		goto err;
	}

	// accept
	BDD_DEBUG_LOG("accepting tcp connection\n");
	struct sockaddr cl_sockaddr;
	socklen_t sockaddr_sz = sizeof(struct sockaddr);
	do {
		cl_socket = accept(instance->sv_socket, &(cl_sockaddr), &(sockaddr_sz));
	} while (cl_socket < 0 && errno == EINTR);
	if (cl_socket < 0) {
		BDD_DEBUG_LOG("rejected tcp connection\n");
		goto err;
	}
	BDD_DEBUG_LOG("accepted tcp connection\n");

	// to-do: non-blocking here
	int flags = fcntl(cl_socket, F_GETFL, 0);
	fcntl(cl_socket, F_SETFL, flags & ~(O_NONBLOCK));

	if (!SSL_set_fd(client_ssl, cl_socket)) {
		goto err;
	}

	if (SSL_accept(client_ssl) <= 0) {
		BDD_DEBUG_LOG("rejected tls setup\n");
		goto err;
	}

	fcntl(cl_socket, F_SETFL, flags | O_NONBLOCK);

	struct bdd_service_instance *service_inst = ctx->service_instance;
	assert(service_inst != NULL);

	switch (bdd_conversation_init(
		conversation,
		&(client_ssl),
		cl_sockaddr,
		service_inst->service,
		ctx->cstr_protocol_name,
		service_inst->instance_info
	)) {
		case (bdd_conversation_init_failed): {
			goto err;
		}
		case (bdd_conversation_init_success): {
			bdd_conversation_link(instance, &(conversation));
			break;
		}
		case (bdd_conversation_init_failed_wants_deinit): {
			bdd_conversation_deinit(conversation);
			goto err;
		}
	}

	goto poll;

	err:;

	BDD_DEBUG_LOG("failed to accept connection\n");

	if (client_ssl != NULL) {
		SSL_free(client_ssl);
	}
	if (cl_socket >= 0) {
		close(cl_socket);
	}
	if (conversation != NULL) {
		bdd_conversation_release(instance, &(conversation));
	}
	goto poll;
}
