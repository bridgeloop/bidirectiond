#ifndef bidirectiond_core__bdd_coac__h
#define bidirectiond_core__bdd_coac__h

#include <time.h>
#include "conversations.h"
#include "accept.h"

enum bdd_coac_inner {
	bdd_coac_conversation,
	bdd_coac_accept_ctx,
	bdd_coac_none,
};
struct bdd_coac {
	struct bdd_coac *prev;
	struct bdd_coac *next;
	time_t accessed_at;

	enum bdd_coac_inner inner_type;
	union {
		struct bdd_conversation conversation;
		struct bdd_accept_ctx accept_ctx;
	} inner;
};

struct bdd_coac *bdd_coac_obtain(struct bdd_instance *instance);
void bdd_coac_release(struct bdd_instance *instance, struct bdd_coac **coac);
void bdd_coac_link(struct bdd_instance *instance, struct bdd_coac **coac);

#endif
