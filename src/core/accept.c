#include "internal.h"

#include <errno.h>
#include <fcntl.h>
#include <openssl/err.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>

SSL_CTX *bdd_ssl_ctx_skel(void) {
	SSL_CTX *ssl_ctx = SSL_CTX_new(TLS_server_method());
	if (ssl_ctx == NULL) {
		return NULL;
	}
	if (SSL_CTX_set_ciphersuites(
		ssl_ctx,
		"TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256"
	) != 1) {
		goto err;
	}
	SSL_CTX_set_min_proto_version(ssl_ctx, TLS1_3_VERSION);
	SSL_CTX_set_max_proto_version(ssl_ctx, TLS1_3_VERSION);
	return ssl_ctx;
	
	err:;
	SSL_CTX_free(ssl_ctx);
	return NULL;
}

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
		struct bdd_name_description *name_description
			= locked_hashmap_get_wl(ctx->locked_name_descriptions, (char *)&(name[idx]), name_sz);
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
bdd_accept_thread__poll:;
	while (poll(instance->accept.pollfds, 2, -1) < 0) {
		if (errno != EINTR) {
			bdd_stop(instance);
			break;
		}
	}
	if (unlikely(atomic_load(&(instance->exiting)))) {
		bdd_thread_exit(instance);
	}

	struct bdd_connections *connections = NULL;
	SSL *client_ssl = NULL;
	ctx->service_instance = NULL;
	ctx->protocol_name = NULL;
	int cl_socket = -1;

#ifdef BIDIRECTIOND_ACCEPT_OCBCNS
	if ((connections = bdd_connections_obtain(instance)) == NULL) {
		goto bdd_accept__err;
	}
#endif
	if ((client_ssl = SSL_new(instance->accept.ssl_ctx)) == NULL) {
		goto bdd_accept__err;
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
		goto bdd_accept__err;
	}
	BDD_DEBUG_LOG("accepted tcp connection\n");

	fcntl(cl_socket, F_SETFL, fcntl(cl_socket, F_GETFL, 0) & ~(O_NONBLOCK));
	setsockopt(cl_socket, SOL_SOCKET, SO_SNDTIMEO, &(instance->client_timeout), sizeof(instance->client_timeout));
	setsockopt(cl_socket, SOL_SOCKET, SO_RCVTIMEO, &(instance->client_timeout), sizeof(instance->client_timeout));

	if (!SSL_set_fd(client_ssl, cl_socket)) {
		goto bdd_accept__err;
	}

	if ((ctx->locked_name_descriptions = hashmap_lock(instance->name_descriptions)) == NULL) {
		BDD_DEBUG_LOG("failed to obtain name_descriptions\n");
		goto bdd_accept__err;
	}
	if (SSL_accept(client_ssl) <= 0) {
		ERR_print_errors_fp(stderr);
		BDD_DEBUG_LOG("rejected tls setup\n");
		goto bdd_accept__err;
	}

	assert(ctx->service_instance != NULL);
	// assert(ctx->protocol_name != NULL); // unused variable for now

	struct bdd_service_instance *service_inst = ctx->service_instance;
#ifndef BIDIRECTIOND_ACCEPT_OCBCNS
	if ((connections = bdd_connections_obtain(instance)) == NULL) {
		goto bdd_accept__err;
	}
#endif
	switch (bdd_connections_init(
		connections,
		&(client_ssl),
		cl_sockaddr,
		service_inst->service,
		ctx->protocol_name,
		service_inst->instance_info
	))
	{
		case (bdd_connections_init_failed): {
			goto bdd_accept__err;
		}
		case (bdd_connections_init_success): {
			bdd_connections_link(instance, &(connections));
			break;
		}
		case (bdd_connections_init_failed_wants_deinit): {
			bdd_connections_deinit(connections);
			goto bdd_accept__err;
		}
	}

	locked_hashmap_unlock(&(ctx->locked_name_descriptions));
	goto bdd_accept_thread__poll;

bdd_accept__err:;
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
	if (connections != NULL) {
		bdd_connections_release(instance, &(connections));
	}
	goto bdd_accept_thread__poll;
}
