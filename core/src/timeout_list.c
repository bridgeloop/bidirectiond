#include <assert.h>
#include <sys/time.h>
#include <pthread.h>

#include "headers/timeout_list.h"
#include "headers/instance.h"
#include "headers/conversations.h"

time_t bdd_time(void) {
	time_t ms = 0;
	struct timeval x;
	gettimeofday(&(x), NULL);
	ms += x.tv_sec * 1000;
	ms += x.tv_usec / 1000;
	return ms;
}

void bdd_tl_unlink(struct bdd_tl *timeout_list, struct bdd_conversation *conversation) {
	pthread_mutex_lock(&(timeout_list->mutex));
	conversation->next = NULL;
	conversation->accessed_at = bdd_time();
	if (timeout_list->head == NULL) {
		assert(timeout_list->tail == NULL);
		conversation->prev = NULL;
		timeout_list->tail = (timeout_list->head = conversation);
	} else {
		assert(timeout_list->tail != NULL);
		conversation->prev = timeout_list->tail;
		timeout_list->tail->next = conversation;
		timeout_list->tail = conversation;
	}
	pthread_mutex_unlock(&(timeout_list->mutex));
	return;
}

void bdd_tl_link(struct bdd_tl *timeout_list, struct bdd_conversation *conversation) {
	pthread_mutex_lock(&(timeout_list->mutex));
	struct bdd_conversation *n;
	if ((n = conversation->prev) != NULL) {
		n->next = conversation->next;
	}
	if ((n = conversation->next) != NULL) {
		n->prev = conversation->prev;
	}
	if (timeout_list->tail == conversation) {
		if ((timeout_list->tail = conversation->prev) == NULL) {
			timeout_list->head = NULL;
		}
	} else if (timeout_list->head == conversation) {
		if ((timeout_list->head = conversation->next) == NULL) {
			timeout_list->tail = NULL;
		}
	}
	conversation->next = NULL;
	conversation->prev = NULL;
	pthread_mutex_unlock(&(timeout_list->mutex));
	return;
}

void bdd_tl_process(struct bdd_tl *timeout_list, int epoll_fd) {
	pthread_mutex_lock(&(timeout_list->mutex));
	for (;;) {
		struct bdd_conversation *conversation = timeout_list->head;
		pthread_mutex_lock(&(conversation->mutex));
		pthread_mutex_unlock(&(conversation->mutex));
		if (conversation == NULL) {
			timeout_list->tail = NULL;
			break;
		}
		if (bdd_time() - conversation->accessed_at < bdd_gv.epoll_timeout) {
			break;
		}
		timeout_list->head = conversation->next;
		if (timeout_list->head != NULL) {
			timeout_list->head->prev = NULL;
		}
		bdd_conversation_discard(conversation, epoll_fd);
	}
	pthread_mutex_unlock(&(timeout_list->mutex));
	return;
}