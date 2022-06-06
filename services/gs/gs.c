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
	unsigned char buf[0x400];
	for (;;) {
		ssize_t n = bdd_io_read(conversation, from, buf, sizeof(buf));
		if (n <= -2) {
			return 2;
		}
		if (n == -1) {
			return 1;
		}
		if (n == 0) {
			return 0;
		}
		if (bdd_io_write(conversation, to, buf, n) != n) {
			return 1;
		}
	}
}

#define gs_clsv(io_id) (io_id == 0 ? 0 : 3)

#define gs_rdhup 1
#define gs_called_shutdown 2
#define gs_wrhup 4

void general_service__handle_events(struct bdd_conversation *conversation) {
	size_t n_ev = bdd_n_ev(conversation);
	uint8_t events[2] = { 0, 0, };
	for (size_t idx = 0; idx < n_ev; ++idx) {
		struct bdd_ev *ev = bdd_ev(conversation, idx);
		events[ev->io_id] = ev->events;
	}
	for (size_t idx = 0; idx < 2; ++idx) {
		if (events[idx] & bdd_ev_err) {
			goto err;
		}
		if (events[idx] & bdd_ev_removed) {
			uintptr_t a = (uintptr_t)bdd_get_associated(conversation);
			bool c = true;
			if (!(a & (gs_rdhup << gs_clsv(idx)))) {
				c = false;
			}
			if (!(a & (gs_called_shutdown << gs_clsv(idx)))) {
				c = false;
			}
			if (c) {
				a |= (gs_wrhup << gs_clsv(idx));
			} else {
				goto err;
			}
		}
	}
	for (size_t idx = 0; idx < 2; ++idx) {
		if (events[idx] & bdd_ev_in) {
			switch (serve(conversation, idx, idx ^ 1)) {
				case (2): {
					uintptr_t a = (uintptr_t)bdd_get_associated(conversation);
					a |= (gs_rdhup << gs_clsv(idx));
					a |= (gs_called_shutdown << gs_clsv(idx ^ 1));
					bdd_set_associated(conversation, (void *)a, NULL);
					if (bdd_io_shutdown(conversation, idx ^ 1) != bdd_shutdown_inprogress) {
						 a |= (gs_wrhup << gs_clsv(idx ^ 1));
					}
					break;
				}
				case (1): {
					goto err;
				}
			}
		}
	}
	return;

	err:;
	bdd_conversation_remove_later(conversation);
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
		bdd_io_id io_id;
		if (!bdd_io_obtain(conversation, &(io_id))) {
			return false;
		}

		if (info->ssl_name != NULL) {
			if (!bdd_io_prep_ssl(conversation, io_id, (void *)info->ssl_name, NULL)) {
				return false;
			}
		}

		if (bdd_io_connect(conversation, io_id, addrinfo->ai_addr, addrinfo->ai_addrlen) != bdd_cont_discard) {
			bdd_set_associated(conversation, 0, NULL);
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
