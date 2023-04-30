#include <assert.h>
#include <sys/time.h>
#include <pthread.h>

#include "headers/timeout_list.h"
#include "headers/instance.h"
#include "headers/conversations.h"

time_t bdd_time(void) {
    struct timespec now;
    clock_gettime(CLOCK_REALTIME, &(now));
    return (now.tv_sec * 1000) + (now.tv_nsec / 1000000);
}

void bdd_tl_link(struct bdd_tl *timeout_list, struct bdd_conversation *conversation) {
	conversation->tl = true;
	conversation->next = -1;
	conversation->accessed_at = bdd_time();
	if (timeout_list->head == NULL) {
		assert(timeout_list->tail == NULL);
		conversation->prev = -1;
		timeout_list->tail = (timeout_list->head = conversation);
	} else {
		assert(timeout_list->tail != NULL);
		conversation->prev = conversation_id(timeout_list->tail);
		timeout_list->tail->next = conversation_id(conversation);
		timeout_list->tail = conversation;
	}
	return;
}

void bdd_tl_unlink(struct bdd_tl *timeout_list, struct bdd_conversation *conversation) {
	struct bdd_conversation *next = conversation_next(conversation);
	struct bdd_conversation *prev = conversation_prev(conversation);
	if (prev != NULL) {
		prev->next = conversation->next;
	}
	if (next != NULL) {
		next->prev = conversation->prev;
	}
	if (timeout_list->tail == conversation) {
		if ((timeout_list->tail = prev) == NULL) {
			timeout_list->head = NULL;
		}
	} else if (timeout_list->head == conversation) {
		if ((timeout_list->head = next) == NULL) {
			timeout_list->tail = NULL;
		}
	}
	conversation->tl = false;
	conversation->next = -1;
	conversation->prev = -1;
	return;
}

void bdd_tl_process(struct bdd_tl *timeout_list) {
	for (;;) {
		struct bdd_conversation *conversation = timeout_list->head;
		if (conversation == NULL) {
			timeout_list->tail = NULL;
			break;
		}
		if (bdd_time() - conversation->accessed_at < bdd_gv.epoll_timeout) {
			break;
		}

		struct bdd_conversation *head = conversation_next(conversation);
		timeout_list->head = head;
		if (head != NULL) {
			head->prev = -1;
		}

		bdd_conversation_discard(conversation);
	}
	return;
}

void bdd_tl_init(struct bdd_tl *timeout_list) {
	timeout_list->head = timeout_list->tail = NULL;
	return;
}
