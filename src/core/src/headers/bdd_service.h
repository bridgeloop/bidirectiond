#ifndef bidirectiond_core__bdd_service__h
#define bidirectiond_core__bdd_service__h

#include <stddef.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <hashmap/hashmap.h>

#include "bdd_io_id.h"
struct bdd_conversation;
struct bdd_service {
	bool (*serve)(struct bdd_conversation *conversation, void *buf, size_t buf_size);

	void (*io_removed)(struct bdd_conversation *conversation, bdd_io_id io_id);
	void (*io_established)(struct bdd_conversation *conversation, bdd_io_id io_id);

	bool (*conversation_init)(
		struct bdd_conversation *conversation,
		const char *protocol_name,
		void *instance_info,
		bdd_io_id client_id,
		struct sockaddr client_sockaddr
	);

	void (*instance_info_destructor)(void *instance_info);
	bool (*instantiate)(
		struct locked_hashmap *name_descriptions,
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
