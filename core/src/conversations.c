#include <stdio.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <assert.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/epoll.h>

#include "headers/instance.h"
#include "headers/serve.h"
#include "headers/conversations.h"
#include "headers/bdd_service.h"
#include "headers/bdd_io.h"

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

int bdd_conversation_id(struct bdd_conversation *conversation) {
	return (((char *)conversation - (char *)(bdd_gv.conversations)) / sizeof(struct bdd_conversation));
}

struct bdd_conversation *bdd_conversation_obtain(void) {
	struct bdd_conversation *conversation = NULL;
	pthread_mutex_lock(&(bdd_gv.available_conversations.mutex));
	while (!atomic_load(&(bdd_gv.exiting)) && bdd_gv.available_conversations.idx == bdd_gv.n_conversations) {
		pthread_cond_wait(&(bdd_gv.available_conversations.cond), &(bdd_gv.available_conversations.mutex));
	}
	if (!atomic_load(&(bdd_gv.exiting))) {
		int id = bdd_gv.available_conversations.ids[bdd_gv.available_conversations.idx++];
		conversation = &(bdd_gv.conversations[id]);
		conversation->state = bdd_conversation_obtained;
		conversation->sosi.service_instance = NULL;
		bdd_io_init(&(conversation->client));
		conversation->soac.ac.protocol_name = NULL;
		conversation->socac.ac.cstr_protocol_name = NULL;
		conversation->associated.data = NULL;
		conversation->associated.destructor = NULL;
		conversation->in_discard_list = 0;
	}
	pthread_mutex_unlock(&(bdd_gv.available_conversations.mutex));
	return conversation;
}
void bdd_conversation_discard(struct bdd_conversation *conversation, int epoll_fd) {
	if (epoll_fd >= 0) {
		if (conversation->state >= bdd_conversation_accept) {
			bdd_io_deinit(&(conversation->client), epoll_fd);
		}
		if (conversation->state == bdd_conversation_ssl) {
			bdd_io_deinit(&(conversation->soac.server), -1);
		}
		if (conversation->state > bdd_conversation_ssl) {
			bdd_io_deinit(&(conversation->soac.server), epoll_fd);
		}
		bdd_set_associated(conversation, NULL, NULL);
	}

	pthread_mutex_lock(&(bdd_gv.available_conversations.mutex));

	assert(bdd_gv.available_conversations.idx != 0);

	int id = bdd_conversation_id(conversation);

	assert(id >= 0 && id < bdd_gv.n_conversations);

	bdd_gv.available_conversations.ids[--(bdd_gv.available_conversations.idx)] = id;

	pthread_cond_signal(&(bdd_gv.available_conversations.cond));
	pthread_mutex_unlock(&(bdd_gv.available_conversations.mutex));

	return;
}
