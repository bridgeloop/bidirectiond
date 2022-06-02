#include <openssl/ssl.h>
#include "../../core/src/headers/conversations.h"
#include "../../core/src/headers/bdd_io.h"

#include <bdd-core/services.h>
#include <netdb.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <assert.h>
#include <stdlib.h>
#include <stdbool.h>

static uint8_t serve(struct bdd_conversation *conversation, uint8_t from, uint8_t to) {
	unsigned char buf[0x200];
	for (;;) {
		ssize_t n = bdd_io_read(conversation, from, buf, sizeof(buf));
		if (n == -2) {
			return 1;
		}
		if (n == -1) {
			return 0;
		}
		if (n == 0) {
			return 0;
		}
		if (bdd_io_write(conversation, to, buf, n) != n) {
			return 0;
		}
	}
}

void general_service__handle_events(struct bdd_conversation *conversation, uint8_t io_id, uint8_t events) {
	if (events & BDDEV_IN) {
		if (serve(conversation, io_id, io_id ^ 1)) {
			bdd_io_shutdown(conversation, io_id ^ 1);
		}
	}
	return;
}
struct general_service__info {
	struct addrinfo *addrinfo;
	const char *ssl_name;
};
bool general_service__conversation_init(
	struct bdd_conversation *conversation,
	const char *protocol_name,
	const void *service_info,
	uint8_t client_id,
	struct sockaddr client_sockaddr
) {
	const struct general_service__info *info = service_info;
	struct addrinfo *addrinfo = info->addrinfo;
	for (; addrinfo != NULL; addrinfo = addrinfo->ai_next) {
		if (info->ssl_name != NULL) {
			if (!bdd_prep_ssl(conversation, (void *)info->ssl_name, NULL)) {
				return true;
			}
		}

		if (bdd_connect(conversation, AF_INET, addrinfo->ai_addr, addrinfo->ai_addrlen)) {
			return true;
		}
	}
	return false;
}
void general_service__instance_info_destructor(void *hint) {
	struct general_service__info *info = hint;
	if (info != NULL) {
		if (info->addrinfo != NULL) {
			freeaddrinfo(info->addrinfo);
		}
		free(info);
	}
	return;
}
static bool handle_s(
	struct bdd_name_descs *name_descriptions,
	const struct bdd_service *service,
	const char *scope,
	const char *addr,
	const char *port,
	bool use_tls
) {
	struct general_service__info *info = malloc(sizeof(struct general_service__info));
	if (info == NULL) {
		return false;
	}
	info->addrinfo = NULL;
	if (use_tls) {
		info->ssl_name = addr;
	} else {
		info->ssl_name = NULL;
	}

	struct addrinfo hints = {
		0,
		.ai_family = AF_INET,
		.ai_socktype = SOCK_STREAM,
	};
	struct addrinfo *res = NULL;
	if (getaddrinfo(addr, port, &(hints), &(res)) != 0) {
		goto err;
	}
	info->addrinfo = res;
	res = NULL;

	if (!bdd_name_descs_add_service_instance(name_descriptions, scope, strlen(scope), service, (void *)&(info))) {
		goto err;
	}
	return true;

	err:;
	general_service__instance_info_destructor(info);
	return false;
}
bool general_service__instantiate(
	struct bdd_name_descs *name_descriptions,
	const struct bdd_service *service,
	size_t argc,
	const char **argv
) {
	if (strcmp(argv[0], "-s") == 0) {
		if (argc != 5) {
			return false;
		}
		bool use_tls;
		if (strcmp(argv[4], "true") == 0) {
			use_tls = true;
		} else if (strcmp(argv[4], "false") == 0) {
			use_tls = false;
		} else {
			return false;
		}
		return handle_s(name_descriptions, service, argv[1], argv[2], argv[3], use_tls);
	}
	return false;
}
