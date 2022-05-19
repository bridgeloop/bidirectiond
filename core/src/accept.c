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
		if (alpn_sz <= 3) {
			goto alpn_err;
		}
		if (alpn[0] != 0) { /* to-do: that byte seems to always be a `0`? */
			goto alpn_err;
		}
		if (alpn[1] != alpn_sz - 2) {
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
			struct bdd_service_instance *inst;
			if (!(found_req & 0b10) && (inst = name_desc->service_instances) != NULL) {
				const char *cstr_protocol_name = NULL;
				unsigned short int offset = alpn_sz;
				struct bdd_service_instance *found = NULL;

				if (alpn == NULL || unlikely(alpn_sz == 0) /* to-do: is that case possible if alpn is non-null? */) {
					goto skip_alpn;
				}

				do {
					assert(inst->service != NULL);
					const char *const *sp = inst->service->supported_protocols;
					if (sp == NULL) {
						if (found == NULL) {
							found = inst;
						}
						goto alpn_find_iter;
					}
					for (unsigned char alpn_idx = 0; alpn_idx < offset;) {
						unsigned char alpn_len = alpn[alpn_idx];
						if (alpn_len == 0 || alpn_sz - alpn_idx < alpn_len) {
							return SSL_CLIENT_HELLO_ERROR;
						}
						for (size_t sp_idx = 0; sp[sp_idx] != NULL; ++sp_idx) {
							if (strncmp(&(alpn[alpn_idx + 1]), sp[sp_idx], alpn_len) == 0 && alpn_idx < offset) {
								cstr_protocol_name = sp[sp_idx];
								if ((offset = alpn_idx) == 0) {
									goto found_alp;
								}
								found = inst;
							}
						}
						alpn_idx += alpn_len + 1;
					}
					alpn_find_iter:;
					inst = inst->next;
				} while (inst != NULL);

				if ((inst = found) != NULL) {
					found_alp:;
					if (cstr_protocol_name != NULL) {
						ctx->protocol_name = &(alpn[offset]);
						ctx->cstr_protocol_name = cstr_protocol_name;
					}
					skip_alpn:;
					assert(inst->service != NULL);
					found_req |= 0b10;
					ctx->service_instance = inst;
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

#ifdef BIDIRECTIOND_ACCEPT_OCBCNS
	if ((conversation = bdd_conversation_obtain(instance)) == NULL) {
		goto err;
	}
#endif
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
	fcntl(cl_socket, F_SETFL, fcntl(cl_socket, F_GETFL, 0) & ~(O_NONBLOCK));
	setsockopt(cl_socket, SOL_SOCKET, SO_SNDTIMEO, &(instance->client_timeout), sizeof(instance->client_timeout));
	setsockopt(cl_socket, SOL_SOCKET, SO_RCVTIMEO, &(instance->client_timeout), sizeof(instance->client_timeout));

	if (!SSL_set_fd(client_ssl, cl_socket)) {
		goto err;
	}

	if (SSL_accept(client_ssl) <= 0) {
		BDD_DEBUG_LOG("rejected tls setup\n");
		goto err;
	}

	assert(ctx->service_instance != NULL);

	struct bdd_service_instance *service_inst = ctx->service_instance;
#ifndef BIDIRECTIOND_ACCEPT_OCBCNS
	if ((conversation = bdd_conversation_obtain(instance)) == NULL) {
		goto err;
	}
#endif
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
