#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

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

struct general_service__associated {
	bdd_io_id client;
	bdd_io_id service;
};

static bool serve(struct bdd_conversation *conversation, bdd_io_id from, bdd_io_id to, bool *rdhup) {
	unsigned char buf[0x200];
	for (;;) {
		ssize_t n = bdd_io_read(conversation, from, buf, sizeof(buf));
		if (n == -2) {
			rdhup[from] = true;
			return true;
		}
		if (n == -1) {
			return false;
		}
		if (n == 0) {
			return true;
		}
		if (bdd_io_write(conversation, to, buf, n) != n) {
			return false;
		}
	}
}

void general_service__handle_events(struct bdd_conversation *conversation) {
	struct general_service__associated *associated = bdd_get_associated(conversation);
	short int revents[] = { bdd_revent(conversation, associated->client), bdd_revent(conversation, associated->service), };
	bool rdhup[] = { false, false, };
	if ((revents[0] | revents[1]) & BDDEV_ERR) {
		goto err;
	}
	if (revents[0] & BDDEV_IN) {
		if (!serve(conversation, associated->client, associated->service, (bool *)rdhup)) {
			goto err;
		}
	}
	if (revents[1] & BDDEV_IN) {
		if (!serve(conversation, associated->service, associated->client, (bool *)rdhup)) {
			goto err;
		}
	}
	if (rdhup[0]) {
		if (bdd_io_shutdown(conversation, associated->service) == bdd_io_shutdown_err) {
			goto err;
		}
	}
	if (rdhup[1]) {
		if (bdd_io_shutdown(conversation, associated->client) == bdd_io_shutdown_err) {
			goto err;
		}
	}
	return;

	err:;
	bdd_io_remove(conversation, associated->client);
	bdd_io_remove(conversation, associated->service);
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
	bdd_io_id client_id,
	struct sockaddr client_sockaddr
) {
	const struct general_service__info *info = service_info;
	struct addrinfo *addrinfo = info->addrinfo;
	bdd_io_id service;
	for (; addrinfo != NULL; addrinfo = addrinfo->ai_next) {
		if (!bdd_io_create(conversation, &(service), addrinfo->ai_family, addrinfo->ai_socktype, addrinfo->ai_protocol)) {
			continue;
		}

		if (info->ssl_name != NULL) {
			bdd_io_prep_ssl(conversation, service, (void *)info->ssl_name, NULL);
		}
		enum bdd_io_connect_status s = bdd_io_connect(conversation, service, addrinfo->ai_addr, addrinfo->ai_addrlen);
		if (s != bdd_io_connect_err && s != bdd_io_connect_again) {
			goto created;
		}

		bdd_io_remove(conversation, service);
	}
	return false;

	created:;
	struct general_service__associated *associated = malloc(sizeof(struct general_service__associated));
	if (associated == NULL) {
		// bdd-core will destroy the io
		return false;
	}
	associated->client = client_id;
	associated->service = service;
	bdd_set_associated(conversation, associated, free);
	return true;
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
