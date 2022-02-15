#include "internal.h"
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>

int bdd_use_correct_ctx(SSL *client_ssl, int *_, struct bdd_accept_ctx *ctx) {
	int r = SSL_TLSEXT_ERR_ALERT_FATAL;

	char *name = (char *)SSL_get_servername(client_ssl, TLSEXT_NAMETYPE_host_name);
	if (unlikely(name == NULL)) {
		BDD_DEBUG_LOG("no dns name\n");
		goto ucc__err;
	}

	// to-do: strlen is slow af, maybe openssl can give us the length instead
	size_t name_len = strlen(name);
	if (name_len == 0 || (name_len == 254 && name[253] != '.') || name_len > 254) {
		goto ucc__err;
	}
	if (name[name_len - 1] == '.') {
		if ((name_len -= 1) == 0) {
			goto ucc__err;
		}
	}
	
	// i'm doing great, okay?
	// thabks
	uint8_t found_req = 0;
	for (size_t idx = 0;;) {
		struct bdd_name_description *name_description = locked_hashmap_get_wl(ctx->locked_name_descriptions, &(name[idx]), name_len);
		if (name_description != NULL) {
			if (!(found_req & 0b01) && name_description->ssl_ctx != NULL) {
				found_req |= 0b01;
				SSL_set_SSL_CTX(client_ssl, name_description->ssl_ctx);
			}
			if (!(found_req & 0b10) && name_description->service_type != bdd_service_type_none) {
				found_req |= 0b10;
				ctx->service_name_description = name_description;
			}
			if (found_req == 0b11) {
				r = SSL_TLSEXT_ERR_OK;
				break;
			}
		}
		bool fwc = name[idx] == '*';
		do {
			idx += 1;
			name_len -= 1;
			if (name_len == 0) {
				if (fwc) {
					goto ucc__err;
				}
				goto ucc__place_wc;
			}
			if (name[idx] == '.') {
				if (!fwc) {
					ucc__place_wc:;
					name_len += 1;
					name[--idx] = '*';
					break;
				}
				fwc = false;
			}
		} while (true);
	}

	ucc__err:;
	BDD_DEBUG_LOG("r: %i\n", r);
	return r;
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
	instance->accept.accept_ctx.service_name_description = NULL;
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
	if (SSL_accept(client_ssl) < 0) {
		BDD_DEBUG_LOG("rejected tls setup\n");
		goto bdd_accept__err;
	}
	
	switch (ctx->service_name_description->service_type) {
		case (bdd_service_type_internal): {
			#ifndef BIDIRECTIOND_ACCEPT_OCBCNS
			if ((connections = bdd_connections_obtain(instance)) == NULL) {
				goto bdd_accept__err;
			}
			#endif
			switch (bdd_connections_init(connections, &(client_ssl), cl_sockaddr, ctx->service_name_description->service.internal.service, ctx->service_name_description->service.internal.service_info)) {
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
			break;
		}
		default: {
			assert(false);
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
