#ifndef bidirectiond__bdd_service__h
#define bidirectiond__bdd_service__h

#include <stddef.h>
#include <stdbool.h>
#include <sys/socket.h>

struct bdd_conversation;
struct bdd_name_descs;
struct bdd_service {
	void (*handle_events)(struct bdd_conversation *conversation);

	bool (*conversation_init)(
		struct bdd_conversation *conversation,
		const char *protocol_name,
		const void *instance_info,
		uint8_t client_id,
		struct sockaddr client_sockaddr
	);

	void (*instance_info_destructor)(void *instance_info);
	bool (*instantiate)(
		const struct bdd_service *service,
		size_t n_arguments,
		const char **arguments
	);
	const char *const *const supported_protocols;
	const char *const *const supported_arguments;
	const char *const arguments_help;
};

#endif
