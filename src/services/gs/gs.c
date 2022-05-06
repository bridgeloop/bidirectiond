#include <bddc/api.h>
#include <netdb.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
struct general_service__associated {
	bdd_io_id client;
	bdd_io_id service;
};
static bool serve(struct bdd_connections *connections, void *buf, size_t buf_size, bdd_io_id from, bdd_io_id to) {
	struct bdd_poll_io poll_io = {
		.io_id = from,
		.events = POLLIN,
		.revents = 0,
	};
	do {
		int n;
		if ((n = bdd_read(connections, from, buf, buf_size)) <= 0) {
			return false;
		}
		if (bdd_write(connections, to, buf, n) <= 0) {
			return false;
		}
		bdd_poll(connections, &(poll_io), 1, 0);
	} while (poll_io.revents & POLLIN);
	return true;
}
bool general_service__serve(struct bdd_connections *connections, void *buf, size_t buf_size) {
	struct general_service__associated *associated = bdd_get_associated(connections);
	struct bdd_poll_io poll_ios[] = {
		{
			.io_id = associated->client,
			.events = POLLIN,
			.revents = 0,
		},
		{
			.io_id = associated->service,
			.events = POLLIN,
			.revents = 0,
		},
	};
	bdd_poll(connections, poll_ios, 2, 0);
	if (poll_ios[0].revents & POLLIN) {
		if (!serve(connections, buf, buf_size, associated->client, associated->service)) {
			return false;
		}
	}
	if (poll_ios[1].revents & POLLIN) {
		if (!serve(connections, buf, buf_size, associated->service, associated->client)) {
			return false;
		}
	}
	return true;
}
struct general_service__info {
	struct addrinfo *addrinfo;
	const char *tls_name;
};
bool general_service__connections_init(
	struct bdd_connections *connections,
	const char *protocol_name,
	void *service_info,
	bdd_io_id client_id,
	struct sockaddr client_sockaddr
) {
	struct general_service__info *info = service_info;
	struct addrinfo *addrinfo = info->addrinfo;
	bdd_io_id service;
	for (; addrinfo != NULL; addrinfo = addrinfo->ai_next) {
		if (!bdd_io_create(connections, &(service), addrinfo->ai_family, addrinfo->ai_socktype, addrinfo->ai_protocol)) {
			continue;
		}

		if (bdd_io_connect(connections, service, addrinfo) == bdd_io_connect_established) {
			goto created;
		}

		bdd_io_remove(connections, service);
	}
	return false;

	created:;
	// to-do: tls
	struct general_service__associated *associated = malloc(sizeof(struct general_service__associated));
	if (associated == NULL) {
		// bdd-core will destroy the io
		return false;
	}
	associated->client = client_id;
	associated->service = service;
	bdd_set_associated(connections, associated, free);
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
	struct locked_hashmap *name_descriptions,
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
		info->tls_name = addr;
	} else {
		info->tls_name = NULL;
	}

	struct addrinfo hints = {
		0,
		.ai_family = AF_UNSPEC,
		.ai_socktype = SOCK_STREAM,
	};
	struct addrinfo *res = NULL;
	if (getaddrinfo(addr, port, &(hints), &(res)) != 0) {
		goto handle_s__err;
	}
	info->addrinfo = res;
	res = NULL;

	if (!bdd_name_descriptions_add_service_instance(name_descriptions, scope, strlen(scope), service, &(info))) {
		goto handle_s__err;
	}
	return true;

handle_s__err:;
	general_service__instance_info_destructor(info);
	return false;
}
bool general_service__service_init(
	struct locked_hashmap *name_descriptions,
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
