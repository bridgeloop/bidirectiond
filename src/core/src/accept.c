#include <errno.h>
#include <openssl/ssl.h>
#include <poll.h>
#include <assert.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "headers/instance.h"
#include "headers/accept.h"
#include "headers/unlikely.h"
#include "headers/debug_log.h"
#include "headers/conversations.h"
#include "headers/name_descriptions.h"
#include "headers/bdd_service.h"
#include "headers/signal.h"

int bdd_hello_cb(SSL *client_ssl, int *alert, struct bdd_accept_ctx *ctx) {
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

	uint8_t found_req = 0;
	for (size_t idx = 0;;) {
		struct bdd_name_description *name_description = locked_hashmap_get_wl(
			ctx->locked_name_descriptions,
			(char *)&(name[idx]),
			name_sz
		);
		if (name_description != NULL) {
			if (!(found_req & 0b01) && name_description->ssl_ctx != NULL) {
				found_req |= 0b01;
				SSL_set_SSL_CTX(client_ssl, name_description->ssl_ctx);
			}
			if (!(found_req & 0b10) && name_description->service_instances != NULL) {
				found_req |= 0b10;
				ctx->service_instance = name_description->service_instances;
			}
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

void *bdd_accept(struct bdd_instance *instance) {
	struct bdd_accept_ctx *ctx = &(instance->accept.accept_ctx);
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

	if ((ctx->locked_name_descriptions = hashmap_lock(instance->name_descriptions)) == NULL) {
		BDD_DEBUG_LOG("failed to obtain name_descriptions\n");
		goto err;
	}
	if (SSL_accept(client_ssl) <= 0) {
		BDD_DEBUG_LOG("rejected tls setup\n");
		goto err;
	}

	assert(ctx->service_instance != NULL);
	// assert(ctx->protocol_name != NULL); // unused variable for now

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
		ctx->protocol_name,
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

	locked_hashmap_unlock(&(ctx->locked_name_descriptions));
	goto poll;

	err:;

	BDD_DEBUG_LOG("failed to accept connection\n");

	if (ctx->locked_name_descriptions != NULL) {
		locked_hashmap_unlock(&(ctx->locked_name_descriptions));
	}
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
