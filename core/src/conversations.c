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
	return conversation->aopn.associated.data;
}
void bdd_set_associated(
	struct bdd_conversation *conversation,
	void *data,
	void (*destructor)(void *)
) {
	assert(conversation != NULL);
	if (conversation->aopn.associated.destructor != NULL) {
		conversation->aopn.associated.destructor(conversation->aopn.associated.data);
	}
#ifndef NDEBUG
	if (data != NULL || destructor != NULL) {
		assert(data != NULL && destructor != NULL);
	}
#endif
	conversation->aopn.associated.data = data;
	conversation->aopn.associated.destructor = destructor;
	return;
}

int bdd_conversation_id(struct bdd_conversation *conversation) {
	return (((char *)conversation - (char *)(bdd_gv.conversations)) / sizeof(struct bdd_conversation));
}

struct bdd_ev *bdd_ev(struct bdd_conversation *conversation, typeof(BIDIRECTIOND_N_IO) idx) {
	if (idx >= conversation->ev_idx) {
		abort();
	}
	return &(((struct bdd_ev *)&(conversation->io_array[BIDIRECTIOND_N_IO]))[idx]);
}
typeof(BIDIRECTIOND_N_IO) bdd_n_ev(struct bdd_conversation *conversation) {
	return conversation->n_ev;
}

struct bdd_conversation *bdd_conversation_obtain(int epoll_fd) {
	struct bdd_io *io_array = malloc((sizeof(struct bdd_io) * BIDIRECTIOND_N_IO) + (sizeof(struct bdd_ev) * BIDIRECTIOND_N_IO));
	if (io_array == NULL) {
		return NULL;
	}
	struct bdd_conversation *conversation;
	pthread_mutex_lock(&(bdd_gv.available_conversations.mutex));
	if (atomic_load(&(bdd_gv.exiting)) || bdd_gv.available_conversations.idx == bdd_gv.n_conversations) {
		pthread_mutex_unlock(&(bdd_gv.available_conversations.mutex));
		free(io_array);
		return NULL;
	}
	int id = bdd_gv.available_conversations.ids[bdd_gv.available_conversations.idx++];
	if (bdd_gv.available_conversations.idx == bdd_gv.n_conversations) {
		for (size_t idx = 0; idx < bdd_gv.n_workers; ++idx) {
			struct bdd_worker_data *worker_data = bdd_gv_worker(idx);
			epoll_ctl(worker_data->epoll_fd, EPOLL_CTL_DEL, worker_data->serve_fd, NULL);
		}
	}
	pthread_mutex_unlock(&(bdd_gv.available_conversations.mutex));
	conversation = &(bdd_gv.conversations[id]);
	conversation->state = bdd_conversation_obtained;
	conversation->epoll_fd = -1;
	conversation->sosi.service_instance = NULL;
	conversation->io_array = io_array;
	conversation->n_connecting = 0;
	conversation->n_in_epoll_with_events = 0;
	conversation->n_ev = 0;
	conversation->aopn.pn.protocol_name = NULL;
	conversation->aopn.pn.cstr_protocol_name = NULL;
	return conversation;
}
void bdd_conversation_discard(struct bdd_conversation *conversation, int epoll_fd) {
	if (conversation->state >= bdd_conversation_accept) {
		bdd_set_associated(conversation, NULL, NULL);
		bdd_io_discard(&(conversation->client), epoll_fd);
	}
	if (conversation->state == bdd_conversation_ssl) {
		bdd_io_discard(&(conversation->soac.server), -1);
	}
	if (conversation->state > bdd_conversation_ssl) {
		bdd_io_discard(&(conversation->soac.server), epoll_fd);
	}
	if (conversation->state >= bdd_conversation_obtained) {
		pthread_mutex_lock(&(bdd_gv.available_conversations.mutex));

		assert(bdd_gv.available_conversations.idx != 0);

		int id = bdd_conversation_id(conversation);

		assert(id >= 0 && id < bdd_gv.n_conversations);

		bool made_avail = bdd_gv.available_conversations.idx == bdd_gv.n_conversations;

		bdd_gv.available_conversations.ids[--(bdd_gv.available_conversations.idx)] = id;

		if (made_avail) {
			for (size_t idx = 0; idx < bdd_gv.n_workers; ++idx) {
				struct bdd_worker_data *worker_data = bdd_gv_worker(idx);
				struct epoll_event ev = {
					.events = EPOLLIN,
					.data = { .ptr = NULL, },
				};
				epoll_ctl(worker_data->epoll_fd, EPOLL_CTL_ADD, worker_data->serve_fd, &(ev));
			}
		}

		pthread_mutex_unlock(&(bdd_gv.available_conversations.mutex));
	}
	conversation->state = bdd_conversation_unused;
	return;
}
