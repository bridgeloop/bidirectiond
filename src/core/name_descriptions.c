#include "internal.h"
#include <string.h>

// struct bdd_name_description
struct bdd_name_description *bdd_name_description_alloc(void) {
	struct bdd_name_description *name_description = malloc(sizeof(struct bdd_name_description));
	if (name_description == NULL) {
		return NULL;
	}
	name_description->ssl_ctx = NULL;
	name_description->service_instances = NULL;
	return name_description;
}

void bdd_name_description_clean_ssl_ctx(struct bdd_name_description *name_description) {
	if (name_description->ssl_ctx != NULL) {
		// misleading function name; it actually
		// decs the ref count and frees the ssl_ctx
		// if the rc hits 0
		SSL_CTX_free(name_description->ssl_ctx);
		name_description->ssl_ctx = NULL;
	}
	return;
}

void bdd_name_description_clean_services(struct bdd_name_description *name_description) {
	for (
		struct bdd_service_instance **service_inst = &(name_description->service_instances);
		(*service_inst) != NULL;
	) {
		struct bdd_service_instance *curr = (*service_inst);
		(*service_inst) = curr->next;
		curr->service->instance_info_destructor(curr->instance_info);
		free(curr);
	}
	return;
}


bool bdd_name_description_add_service_instance(
	struct bdd_name_description *name_description,
	struct bdd_service_instance **service_r
) {
	struct bdd_service_instance *service_inst = (*service_r);
	struct bdd_service_instance **curr = &(name_description->service_instances);
	const char **inst_sp = service_inst->service->supported_protocols;
	for (; (*curr) != NULL; curr = &((*curr)->next)) {
		const char **curr_sp = (*curr)->service->supported_protocols;
		if (inst_sp == NULL || curr_sp == NULL) {
			if (inst_sp == curr_sp) {
				return false;
			}
			continue;
		}
		for (size_t idx = 0; curr_sp[idx]; ++idx) {
			for (size_t idx2 = 0; inst_sp[idx2]; ++idx2) {
				if (strcmp(curr_sp[idx], inst_sp[idx2]) == 0) {
					return false;
				}
			}
		}
	}
	(*curr) = service_inst;
	(*service_r) = NULL;
	return true;
}

void bdd_name_description_set_ssl_ctx(struct bdd_name_description *name_description, SSL_CTX *ssl_ctx) {
	bdd_name_description_clean_ssl_ctx(name_description);
	name_description->ssl_ctx = ssl_ctx;
	return;
}

void bdd_name_description_destroy(struct bdd_name_description *name_description) {
	bdd_name_description_clean_services(name_description);
	bdd_name_description_clean_ssl_ctx(name_description);
	free(name_description);
	return;
}


// name_descriptions hashmap
#define bdd_name_descriptions() \
	if (scope_len == 0 || scope_len > 254 || (scope_len == 254 && scope[253] != '.')) { \
		return false; \
	} \
	if (scope[scope_len - 1] == '.') { \
		if ((scope_len -= 1) == 0) { \
			return false; \
		} \
	} \
	struct bdd_name_description *name_description = locked_hashmap_get_wl(name_descriptions, (char *)scope, scope_len); \
	bool created_name_description; \
	if (name_description == NULL) { \
		if ((name_description = bdd_name_description_alloc()) == NULL) { \
			return false; \
		} \
		created_name_description = true; \
	} else { \
		created_name_description = false; \
	}

bool bdd_name_descriptions_add_service_instance(
	struct locked_hashmap *name_descriptions,
	const char *scope,
	size_t scope_len,
	const struct bdd_service *service,
	void *instance_info
) {
	bdd_name_descriptions();

	struct bdd_service_instance *service_inst = malloc(sizeof(struct bdd_service_instance));
	service_inst->service = service;
	service_inst->instance_info = instance_info;
	service_inst->next = NULL;
	if (!bdd_name_description_add_service_instance(name_description, &(service_inst))) {
		if (created_name_description) {
			bdd_name_description_destroy(name_description);
		}
		free(service_inst);
		return false;
	}

	if (created_name_description
	    && !locked_hashmap_set_wl(name_descriptions, (char *)scope, scope_len, name_description, 1)) {
		bdd_name_description_destroy(name_description);
		return false;
	}

	return true;
}
bool bdd_name_descriptions_set_ssl_ctx(
	struct locked_hashmap *name_descriptions,
	const char *scope,
	size_t scope_len,
	SSL_CTX *ssl_ctx
) {
	bdd_name_descriptions();

	bdd_name_description_set_ssl_ctx(name_description, ssl_ctx);

	if (created_name_description
	    && !locked_hashmap_set_wl(name_descriptions, (char *)scope, scope_len, name_description, 1)) {
		bdd_name_description_destroy(name_description);
		return false;
	}

	return true;
}

struct hashmap *bdd_name_descriptions_create(void) {
	return hashmap_create((void (*)(void *))&(bdd_name_description_destroy));
};
