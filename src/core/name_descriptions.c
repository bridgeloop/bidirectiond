#include "internal.h"

// struct bdd_name_description
struct bdd_name_description *bdd_name_description_alloc(void) {
	struct bdd_name_description *name_description = malloc(sizeof(struct bdd_name_description));
	if (name_description == NULL) {
		return NULL;
	}
	name_description->ssl_ctx = NULL;
	name_description->service_type = bdd_service_type_none;
	return name_description;
}
void bdd_name_description_clean_ssl_ctx(struct bdd_name_description *name_description) {
	if (name_description->ssl_ctx != NULL) {
		SSL_CTX_free(name_description->ssl_ctx); // misleading function name; it actually decs the ref count and frees the ssl_ctx if the rc hits 0
		name_description->ssl_ctx = NULL;
	}
	return;
}
void bdd_name_description_clean_service(struct bdd_name_description *name_description) {
	if (name_description->service_type == bdd_service_type_internal && name_description->service.internal.service->service_info_destructor != NULL) {
		name_description->service.internal.service->service_info_destructor(name_description->service.internal.service_info);
	}
	name_description->service_type = bdd_service_type_none;
	return;
}
void bdd_name_description_set_internal_service(struct bdd_name_description *name_description, struct bdd_internal_service *service, void *service_info) {
	bdd_name_description_clean_service(name_description);
	name_description->service_type = bdd_service_type_internal;
	name_description->service.internal.service = service;
	name_description->service.internal.service_info = service_info;
	return;
}
void bdd_name_description_set_ssl_ctx(struct bdd_name_description *name_description, SSL_CTX *ssl_ctx) {
	bdd_name_description_clean_ssl_ctx(name_description);
	name_description->ssl_ctx = ssl_ctx;
	return;
}
void bdd_name_description_destroy(struct bdd_name_description *name_description) {
	bdd_name_description_clean_service(name_description);
	bdd_name_description_clean_ssl_ctx(name_description);
	free(name_description);
	return;
}

// name_descriptions hashmap
#define bdd_name_descriptions() \
	if (name_len == 0 || name_len > 254 || (name_len == 254 && name[253] != '.')) { \
		return false; \
	} \
	if (name[name_len - 1] == '.') { \
		if ((name_len -= 1) == 0) { \
			return false; \
		} \
	} \
	struct bdd_name_description *name_description = locked_hashmap_get_wl(name_descriptions, name, name_len); \
	if (name_description == NULL) { \
		if ((name_description = bdd_name_description_alloc()) == NULL) { \
			return false; \
		} \
		if (!locked_hashmap_set_wl(name_descriptions, name, name_len, name_description, 1)) { \
			bdd_name_description_destroy(name_description); \
			return false; \
		} \
	}
bool bdd_name_descriptions_set_internal_service(struct locked_hashmap *name_descriptions, char *name, size_t name_len, struct bdd_internal_service *service, void *service_info) {
	bdd_name_descriptions();
	
	bdd_name_description_set_internal_service(name_description, service, service_info);
	
	return true;
}
bool bdd_name_descriptions_set_ssl_ctx(struct locked_hashmap *name_descriptions, char *name, size_t name_len, SSL_CTX *ssl_ctx) {
	bdd_name_descriptions();
	
	bdd_name_description_set_ssl_ctx(name_description, ssl_ctx);
	
	return true;
}
