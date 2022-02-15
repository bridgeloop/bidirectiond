#include <bddc/api.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
struct general_service__associated {
	bdd_io_id client;
	bdd_io_id service;
};
static bool serve(struct bdd_connections *connections, void *buf, size_t buf_size, bdd_io_id from, bdd_io_id to) {
	do {
		int n;
		if ((n = bdd_read(connections, from, buf, buf_size)) <= 0) {
			return false;
		}
		if (bdd_write(connections, to, buf, n) <= 0) {
			return false;
		}
	} while ((bdd_poll(connections, from) & POLLIN));
	return true;
}
bool general_service__serve(struct bdd_connections *connections, void *buf, size_t buf_size) {
	struct general_service__associated *associated = bdd_get_associated(connections);
	if ((bdd_poll(connections, associated->client) & POLLIN)) {
		if (!serve(connections, buf, buf_size, associated->client, associated->service)) {
			return false;
		}
	}
	if ((bdd_poll(connections, associated->service)) & POLLIN) {
		if (!serve(connections, buf, buf_size, associated->service, associated->client)) {
			return false;
		}
	}
	return true;
}
struct general_service__info {
	struct addrinfo *addrinfo;
	char *tls_name;
};
bool general_service__connections_init(struct bdd_connections *connections, void *service_info, bdd_io_id client_id, struct sockaddr client_sockaddr) {
	struct general_service__info *info = service_info;
	struct addrinfo *addrinfo = info->addrinfo;
	int sock = -1;
	for (; addrinfo != NULL; addrinfo = addrinfo->ai_next) {
		if ((sock = socket(addrinfo->ai_family, addrinfo->ai_socktype, addrinfo->ai_protocol)) < 0) {
			continue;
		}
		
		if (connect(sock, addrinfo->ai_addr, addrinfo->ai_addrlen) >= 0) {
			break;
		}
		
		close(sock);
		sock = -1;
	}
	if (sock < 0) {
		return false;
	}
	bdd_io_id service;
	struct general_service__associated *associated;
	if (!bdd_create_io(connections, &(service), &(sock), info->tls_name)) {
		close(sock);
		return false;
	}
	if ((associated = malloc(sizeof(struct general_service__associated))) == NULL) {
		// bdd-core will destroy the io
		return false;
	}
	associated->client = client_id;
	associated->service = service;
	bdd_set_associated(connections, associated, free);
	return true;
}
void general_service__service_info_destructor(void *hint) {
	struct general_service__info *info = hint;
	freeaddrinfo(info->addrinfo);
	free(info);
}
static bool handle_s(struct locked_hashmap *name_descriptions, struct bdd_internal_service *service, char *scope, char *addr, char *port, bool use_tls) {
	struct general_service__info *info = malloc(sizeof(struct general_service__info));
	struct addrinfo hints = { 0, .ai_family = AF_UNSPEC, .ai_socktype = SOCK_STREAM, };
	struct addrinfo *res = NULL;
	if (info == NULL) {
		goto handle_s__err;
	}
	if (use_tls) {
		info->tls_name = addr;
	} else {
		info->tls_name = NULL;
	}
	if (getaddrinfo(addr, port, &(hints), &(res)) != 0) {
		goto handle_s__err;
	}
	info->addrinfo = res;
	if (!bdd_name_descriptions_set_internal_service(name_descriptions, scope, strlen(scope), service, info)) {
		goto handle_s__err;
	}
	return true;
	handle_s__err:;
	if (info != NULL) {
		free(info);
	}
	if (res != NULL) {
		freeaddrinfo(res);
	}
	return false;
}
bool general_service__service_init(struct locked_hashmap *name_descriptions, struct bdd_internal_service *service, size_t argc, char **argv) {
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
