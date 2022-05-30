#include <stdio.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <assert.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/epoll.h>

#include "headers/instance.h"
#include "headers/signal.h"
#include "headers/serve.h"
#include "headers/conversations.h"
#include "headers/bdd_service.h"
#include "headers/bdd_io.h"
#include "headers/bdd_io_remove.h"
#include "headers/workers.h"

unsigned char bdd_revent(struct bdd_conversation *conversation, bdd_io_id io_id) {
	if (conversation == NULL || io_id < 0 || io_id >= bdd_conversation_n_max_io(conversation)) {
		fputs("programming error: bdd_revent called with invalid arguments\n", stderr);
		assert(false);
		return 0;
	}
	unsigned char *revents = (unsigned char *)&(conversation->io_array[bdd_conversation_n_max_io(conversation)]);
	return revents[io_id];
}
bdd_io_id bdd_conversation_n_max_io(struct bdd_conversation *conversation) {
	return conversation->service->n_max_io;
}

void *bdd_get_associated(struct bdd_conversation *conversation) {
	return conversation->associated.data;
}
void bdd_set_associated(
	struct bdd_conversation *conversation,
	void *data,
	void (*destructor)(void *)
) {
	assert(conversation != NULL);
	if (conversation->associated.destructor != NULL) {
		conversation->associated.destructor(conversation->associated.data);
	}
#ifndef NDEBUG
	if (data != NULL || destructor != NULL) {
		assert(data != NULL && destructor != NULL);
	}
#endif
	conversation->associated.data = data;
	conversation->associated.destructor = destructor;
	return;
}

// init and de-init obtained conversations //

enum bdd_conversation_init_status bdd_conversation_init(
	struct bdd_conversation *conversation,
	SSL **client_ssl_ref,
	struct sockaddr client_sockaddr,
	const struct bdd_service *service,
	const char *protocol_name,
	const void *instance_info
) {
	assert(service->n_max_io > 0);
	SSL *client_ssl = (*client_ssl_ref);

	conversation->service = service;
	conversation->n_connecting = 0;

	conversation->associated.data = NULL;
	conversation->associated.destructor = NULL;

	conversation->io_array = malloc(
		(sizeof(struct bdd_io) * service->n_max_io) +
		(sizeof(unsigned char) * service->n_max_io)
	);

	struct bdd_io *io_array = conversation->io_array;
	if (conversation->io_array == NULL) {
		return bdd_conversation_init_failed;
	}

	io_array[0].state = BDD_IO_STATE_ESTABLISHED;
	io_array[0].shutdown_called = 0;

	io_array[0].tcp = 1;
	io_array[0].tcp_hup = 0;
	io_array[0].ssl = 1;
	io_array[0].ssl_alpn = 0; // irrelevant value
	io_array[0].ssl_shutdown_fully = 0;

	io_array[0].in_epoll = 0;

	io_array[0].eof = 0;

	io_array[0].listen_read = 1;
	io_array[0].listen_write = 0;

	(*client_ssl_ref) = NULL;
	io_array[0].io.ssl = client_ssl;

	for (bdd_io_id idx = 1; idx < service->n_max_io; ++idx) {
		io_array[idx].state = BDD_IO_STATE_UNUSED;
	}
	if (
		service->conversation_init != NULL &&
		!service->conversation_init(conversation, protocol_name, instance_info, 0, client_sockaddr)
	) {
		return bdd_conversation_init_failed_wants_deinit;
	}
	return bdd_conversation_init_success;
}
void bdd_conversation_deinit(struct bdd_conversation *conversation) {
	if (conversation->io_array != NULL) {
		for (bdd_io_id io_id = 0; io_id < bdd_conversation_n_max_io(conversation); ++io_id) {
			struct bdd_io *io = &(conversation->io_array[io_id]);
			if (io->state == BDD_IO_STATE_UNUSED) {
				continue;
			}
			if (io->in_epoll) {
				epoll_ctl(bdd_gv.epoll_fd, bdd_io_internal_fd(io), EPOLL_CTL_DEL, NULL);
			}
			bdd_io_remove(conversation, io_id);
		}
		free(conversation->io_array);
		conversation->io_array = NULL;
	}
	bdd_set_associated(conversation, NULL, NULL);
	return;
}
