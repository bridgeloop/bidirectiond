#include <openssl/ssl.h>
#include <bdd-core/services.h>
#include <netdb.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <assert.h>
#include <stdlib.h>
#include <stdbool.h>

#define buf_sz_each 0x400
#define clsvb(idx) (idx == 0 ? 0 : buf_sz_each)

struct associated {
	uint8_t flags;
	ssize_t idx[2];
	ssize_t n[2];
	unsigned char buf[];
};

static uint8_t serve(struct bdd_conversation *conversation, struct associated *a, uint8_t from, uint8_t to) {
	for (size_t it = 0; it < 10; ++it) {
		ssize_t r = a->n[to] = bdd_io_read(conversation, from, &(a->buf[clsvb(to)]), buf_sz_each);
		if (r == -4) {
			return 2;
		}
		if (r <= -1) {
			return 1;
		}
		if (r == 0) {
			return 0;
		}
		r = a->idx[to] = bdd_io_write(conversation, to, &(a->buf[clsvb(to)]), r);
		if (r < 0) {
			return 1;
		}
		if (r != a->n[to]) {
			return 0;
		}
	}
	return 0;
}

#define rdhup 1
#define called_shutdown 2
#define wrhup 4
#define clsv(idx) (idx == 0 ? 0 : 3)

void general_service__handle_events(struct bdd_conversation *conversation) {
	struct associated *a = bdd_get_associated(conversation);
	size_t n_ev = bdd_n_ev(conversation);
	for (size_t idx = 0; idx < n_ev; ++idx) {
		struct bdd_ev *ev = bdd_ev(conversation, idx);
		bdd_io_id io_id = ev->io_id;
		if (!(ev->events & (bdd_ev_err | bdd_ev_removed))) {
			break;
		}
		if (ev->events & bdd_ev_err) {
			goto err;
		}
		if (ev->events & bdd_ev_removed) {
			bool c = true;
			if (!(a->flags & (rdhup << clsv(io_id)))) {
				c = false;
			}
			if (!(a->flags & (called_shutdown << clsv(io_id)))) {
				c = false;
			}
			if (c) {
				a->flags |= (wrhup << clsv(ev->io_id));
			} else {
				goto err;
			}
		}
	}
	for (size_t idx = 0; idx < n_ev; ++idx) {
		struct bdd_ev *ev = bdd_ev(conversation, idx);
		bdd_io_id io_id = ev->io_id;
		if (ev->events & bdd_ev_out) {
			assert(!(ev->events & bdd_ev_in));
			ssize_t r = bdd_io_write(conversation, io_id, &(a->buf[clsvb(io_id)]), a->n[io_id] - a->idx[io_id]);
			if (r < 0) {
				goto err;
			}
			a->idx[io_id] += r;
		}
		if (ev->events & bdd_ev_in) {
			switch (serve(conversation, a, io_id, io_id ^ 1)) {
				case (2): {
					a->flags |= (rdhup << clsv(io_id));
					a->flags |= (called_shutdown << clsv(io_id ^ 1));
					if (bdd_io_shutdown(conversation, io_id ^ 1) != bdd_shutdown_inprogress) {
						 a->flags |= (wrhup << clsv(io_id ^ 1));
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
			struct associated *a = malloc(sizeof(struct associated) + (buf_sz_each * 2));
			if (a == NULL) {
				return false;
			}
			a->flags = 0;
			bdd_set_associated(conversation, a, NULL);
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
