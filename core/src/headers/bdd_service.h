#ifndef bidirectiond_core__bdd_service__h
#define bidirectiond_core__bdd_service__h

#include <stddef.h>
#include <stdbool.h>
#include <sys/socket.h>

#include "bdd_io_id.h"
struct bdd_conversation;
struct bdd_name_descs;
struct bdd_service {
	bool (*handle_events)(struct bdd_conversation *conversation, short int *revents);

	bool (*conversation_init)(
		struct bdd_conversation *conversation,
		const char *protocol_name,
		const void *instance_info,
		bdd_io_id client_id,
		struct sockaddr client_sockaddr
	);

	void (*instance_info_destructor)(void *instance_info);
	bool (*instantiate)(
		struct bdd_name_descs *name_descs,
		const struct bdd_service *service,
		size_t n_arguments,
		const char **arguments
	);
	const char *const *const supported_protocols;
	const char *const *const supported_arguments;
	const char *const arguments_help;

	bdd_io_id n_max_io;
};

#endif
