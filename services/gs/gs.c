#include "../../bdd/headers/services.h"
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <assert.h>
#include <stdlib.h>
#include <stdbool.h>

#define buf_sz_each 0x400
#define clsvb(id) (buf_sz_each * id)

struct associated {
	ssize_t idx[2];
	ssize_t n[2];
	unsigned char buf[];
};

static inline uint8_t serve(struct bdd_conversation *conversation, bdd_io_id from, bdd_io_id to) {
	struct associated *associated = bdd_get_associated(conversation);
	for (size_t it = 0;; ++it) {
		ssize_t r;
		if (it < 10) {
			r = bdd_io_read(conversation, from, &(associated->buf[clsvb(to)]), buf_sz_each);
		} else {
			r = bdd_io_read_pending(conversation, from, &(associated->buf[clsvb(to)]), buf_sz_each);
		}
		associated->n[to] = r;
		if (r <= 0) {
			return r * -1;
		}
		r = associated->idx[to] = bdd_io_write(conversation, to, &(associated->buf[clsvb(to)]), r);
		if (r < 0) {
			return 1;
		}
		if (r != associated->n[to]) {
			return 0;
		}
	}
	return 0;
}

void general_service__handle_events(struct bdd_conversation *conversation) {
	struct associated *associated = bdd_get_associated(conversation);
	size_t n_ev = bdd_n_ev(conversation);

	for (bdd_io_id idx = 0; idx < n_ev; ++idx) {
		struct bdd_ev *ev = bdd_ev(conversation, idx);
		bdd_io_id io_id = ev->io_id;

		uint8_t removal_reason = ev->events & bdd_ev_removed;
		if (removal_reason == bdd_ev_removed_hup) {
			return;
		}
		if (removal_reason) {
			goto err;
		}

		if (ev->events & bdd_ev_err) {
			goto err;
		}
	}

	for (bdd_io_id idx = 0; idx < n_ev; ++idx) {
		struct bdd_ev *ev = bdd_ev(conversation, idx);
		bdd_io_id io_id = ev->io_id;

		if (ev->events & bdd_ev_out) {
			assert(!(ev->events & bdd_ev_in));
			ssize_t r = bdd_io_write(
				conversation,
				io_id,
				&(associated->buf[clsvb(io_id)]),
				associated->n[io_id] - associated->idx[io_id]
			);
			if (r < 0) {
				goto err;
			}
			associated->idx[io_id] += r;
		}
		if (ev->events & bdd_ev_in) {
			int r = serve(conversation, io_id, io_id ^ 1);
			switch (r) {
				case (4): case (2): { // rdhup
					switch (bdd_io_shutdown(conversation, io_id ^ 1)) {
						case (bdd_shutdown_conversation_discard): {
							return;
						}
						default:;
					}
					break;
				}
				case (3): { // conversation discarded
					return;
				}
				case (1): {
					goto err;
				}
				default: {
					bdd_io_flush(conversation, io_id ^ 1);
					break;
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
	bdd_io_id client_id,
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

		// fixme: connecting can fail after this
		if (bdd_io_connect(conversation, io_id, addrinfo->ai_addr, addrinfo->ai_addrlen) != bdd_cont_discard) {
			struct associated *a = malloc(sizeof(struct associated) + (buf_sz_each * 2));
			if (a == NULL) {
				return false;
			}
			bdd_set_associated(conversation, a, free);
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

	if (bdd_name_descs_add_service_instance(scope, strlen(scope), service, (void *)info)) {
		return true;
	}

	err:;
	general_service__instance_info_destructor(info);
	return false;
}
bool general_service__instantiate(
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
		return handle_s(service, argv[1], argv[2], argv[3], use_tls);
	}
	return false;
}
