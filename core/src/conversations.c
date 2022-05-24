#include <poll.h>
#include <sys/epoll.h>
#include <stdio.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <assert.h>
#include <unistd.h>
#include <fcntl.h>
#include <alloca.h>
#include <errno.h>

#include "headers/instance.h"
#include "headers/signal.h"
#include "headers/conversations.h"
#include "headers/bdd_service.h"
#include "headers/bdd_io.h"
#include "headers/bdd_io_remove.h"
#include "headers/workers.h"

bdd_io_id bdd_conversation_n_max_io(struct bdd_conversation *conversation) {
	return conversation->service->n_max_io;
}
int bdd_conversation_id(struct bdd_instance *instance, struct bdd_conversation *conversation) {
	return (((char *)conversation - (char *)(instance->conversations)) / sizeof(struct bdd_conversation));
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

	conversation->noatime = 0;

	conversation->service = service;

	conversation->io = malloc(
		(sizeof(struct bdd_io) * service->n_max_io) +
		(sizeof(short int) * service->n_max_io)
	);

	if (conversation->io == NULL) {
		return bdd_conversation_init_failed;
	}

	conversation->io[0].epoll_events = EPOLLIN | EPOLLRDHUP;
	conversation->io[0].state = BDD_IO_STATE_ESTABLISHED;
	conversation->io[0].tcp = 1;
	conversation->io[0].shut_wr = 0;
	conversation->io[0].ssl = 1;
	conversation->io[0].ssl_alpn = 0; // irrelevant value
	conversation->io[0].ssl_shut = 0;
	conversation->io[0].in_epoll = 0; // irrelevant value
	conversation->io[0].no_epoll = 0;
	conversation->io[0].hup = 0;
	conversation->io[0].rdhup = 0;

	(*client_ssl_ref) = NULL;
	conversation->io[0].io.ssl = client_ssl;

	for (bdd_io_id idx = 1; idx < service->n_max_io; ++idx) {
		conversation->io[idx].state = BDD_IO_STATE_UNUSED;
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
	if (conversation->io != NULL) {
		for (bdd_io_id io_id = 0; io_id < bdd_conversation_n_max_io(conversation); ++io_id) {
			struct bdd_io *io = &(conversation->io[io_id]);
			if (bdd_io_state(io) == BDD_IO_STATE_UNUSED) {
				continue;
			}
			bdd_io_remove(conversation, io_id);
		}
		free(conversation->io);
		conversation->io = NULL;
	}
	bdd_set_associated(conversation, NULL, NULL);
	return;
}

// put a conversation into conversations_to_epoll //

void bdd_conversation_link(struct bdd_instance *instance, struct bdd_conversation **conversation_ref) {
	assert(conversation_ref != NULL);
	struct bdd_conversation *conversation = (*conversation_ref);
	(*conversation_ref) = NULL;
	assert(conversation != NULL);
	pthread_mutex_lock(&(instance->conversations_to_epoll.mutex));
	conversation->next = instance->conversations_to_epoll.head;
	instance->conversations_to_epoll.head = conversation;
	bdd_signal(instance);
	pthread_mutex_unlock(&(instance->conversations_to_epoll.mutex));
	return;
}

// safely obtain and release conversations //

struct bdd_conversation *bdd_conversation_obtain(struct bdd_instance *instance) {
	struct bdd_conversation *conversation = NULL;
	pthread_mutex_lock(&(instance->available_conversations.mutex));
	while (!atomic_load(&(instance->exiting)) && instance->available_conversations.idx == instance->n_conversations) {
		pthread_cond_wait(&(instance->available_conversations.cond), &(instance->available_conversations.mutex));
	}
	if (!atomic_load(&(instance->exiting))) {
		int id = instance->available_conversations.ids[instance->available_conversations.idx++];
		conversation = &(instance->conversations[id]);
	}
	pthread_mutex_unlock(&(instance->available_conversations.mutex));
	return conversation;
}
void bdd_conversation_release(struct bdd_instance *instance, struct bdd_conversation **conversation_ref) {
	assert(conversation_ref != NULL);

	struct bdd_conversation *conversation = (*conversation_ref);
	(*conversation_ref) = NULL;
	assert(conversation != NULL);

	pthread_mutex_lock(&(instance->available_conversations.mutex));

	assert(instance->available_conversations.idx != 0);

	int id = bdd_conversation_id(instance, conversation);

	assert(id >= 0 && id < instance->n_conversations);

	instance->available_conversations.ids[--(instance->available_conversations.idx)] = id;

	pthread_cond_signal(&(instance->available_conversations.cond));
	pthread_mutex_unlock(&(instance->available_conversations.mutex));

	return;
}
