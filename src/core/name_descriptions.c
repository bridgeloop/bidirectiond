#include "internal.h"

#include <openssl/x509v3.h>
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
	for (struct bdd_service_instance **service_inst = &(name_description->service_instances);
	     (*service_inst) != NULL;) {
		struct bdd_service_instance *curr = (*service_inst);
		(*service_inst) = curr->next;
		curr->service->instance_info_destructor(curr->instance_info);
		free(curr);
	}
	return;
}


bool bdd_name_description_add_service_instance(
	struct bdd_name_description *name_description,
	struct bdd_service_instance *service_inst
) {
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
	if (scope_sz > 254 || (scope_sz == 254 && scope[253] != '.')) { \
		return false; \
	} \
	if (scope_sz > 0 && scope[scope_sz - 1] == '.') { \
		scope_sz -= 1; \
	} \
	if (scope_sz > 0 && scope[0] == '*') { \
		if (scope_sz > 1 && scope[1] != '.') { \
			return false; \
		} \
		scope += 1; \
		scope_sz -= 1; \
	} \
	struct bdd_name_description *name_description \
		= locked_hashmap_get_wl(name_descriptions, (char *)scope, scope_sz); \
	bool created_name_description; \
	if (name_description == NULL) { \
		if ((name_description = bdd_name_description_alloc()) == NULL) { \
			return false; \
		} \
		created_name_description = true; \
	} else { \
		created_name_description = false; \
	}

// exposed function
bool bdd_name_descriptions_add_service_instance(
	struct locked_hashmap *name_descriptions,
	const char *scope,
	size_t scope_sz,
	const struct bdd_service *service,
	void **instance_info
) {
	bdd_name_descriptions();

	struct bdd_service_instance *service_inst = malloc(sizeof(struct bdd_service_instance));
	service_inst->service = service;
	service_inst->next = NULL;
	if (!bdd_name_description_add_service_instance(name_description, service_inst)) {
		if (created_name_description) {
			bdd_name_description_destroy(name_description);
		}
		free(service_inst);
		return false;
	}

	if (created_name_description) {
		if (!locked_hashmap_set_wl(name_descriptions, (char *)scope, scope_sz, name_description, 1)) {
			// will free service_inst
			bdd_name_description_destroy(name_description);
			return false;
		}
	}

	service_inst->instance_info = *instance_info;
	*instance_info = NULL;
	return true;
}

// internal function
bool bdd_name_descriptions_set_ssl_ctx(
	struct locked_hashmap *name_descriptions,
	const char *scope,
	size_t scope_sz,
	SSL_CTX *ssl_ctx
) {
	bdd_name_descriptions();

	bdd_name_description_set_ssl_ctx(name_description, ssl_ctx);

	if (created_name_description) {
		if (!locked_hashmap_set_wl(name_descriptions, (char *)scope, scope_sz, name_description, 1)) {
			bdd_name_description_destroy(name_description);
			return false;
		}
	}

	return true;
}

// exposed function
bool bdd_name_descriptions_create_ssl_ctx(
	struct locked_hashmap *name_descriptions,
	X509 **x509_ref,
	EVP_PKEY **pkey_ref
) {
	X509 *x509 = *x509_ref;
	EVP_PKEY *pkey = *pkey_ref;

	SSL_CTX *ctx = bdd_ssl_ctx_skel();
	if (ctx == NULL) {
		return false;
	}

	// up some ref counts
	// free'ing an SSL_CTX will decrement those ref counts, and
	// we want the caller to still have control over those pointers
	// if this function fails
	X509_up_ref(x509);
	EVP_PKEY_up_ref(pkey);
	SSL_CTX_use_certificate(ctx, x509);
	SSL_CTX_use_PrivateKey(ctx, pkey);

	bool should_up_rc = false;
	GENERAL_NAMES *dns_alt_names = X509_get_ext_d2i(x509, NID_subject_alt_name, 0, 0);
	if (dns_alt_names != NULL) {
		int n_dns_alt_names = sk_GENERAL_NAME_num(dns_alt_names);
		if (n_dns_alt_names < 0) {
			n_dns_alt_names = 0;
		}
		for (int idx = 0; idx < n_dns_alt_names; ++idx) {
			GENERAL_NAME *entry = sk_GENERAL_NAME_value(dns_alt_names, idx);
			if (entry->type != GEN_DNS) {
				continue;
			}
			ASN1_IA5STRING *asn1_str = entry->d.dNSName;
			int data_length = asn1_str->length;
			bool s = bdd_name_descriptions_set_ssl_ctx(
				name_descriptions,
				(char *)asn1_str->data,
				data_length,
				ctx
			);
			if (s) {
				if (should_up_rc) {
					SSL_CTX_up_ref(ctx);
				} else {
					should_up_rc = true;
				}
			}
			// todo: an else block here which would free the SSL_CTX would fuck up if the SSL_CTX has already
			// been placed inside of a name_description which is in name_descriptions
			// the current behaviour is to not apply the SSL_CTX to a name description if the above call fails,
			// which is fine i think
		}
		GENERAL_NAMES_free(dns_alt_names);
	} else { // rfc6125
		X509_NAME *dns_subject_names = X509_get_subject_name(x509);
		if (dns_subject_names != NULL) {
			int n_dns_subject_names = X509_NAME_entry_count(dns_subject_names);
			if (n_dns_subject_names < 0) {
				n_dns_subject_names = 0;
			}
			for (int idx = 0; idx < n_dns_subject_names; ++idx) {
				X509_NAME_ENTRY *entry = X509_NAME_get_entry(dns_subject_names, idx);
				ASN1_OBJECT *asn1_obj = X509_NAME_ENTRY_get_object(entry);
				ASN1_STRING *asn1_str = X509_NAME_ENTRY_get_data(entry);
				if (asn1_obj == NULL || asn1_str == NULL) {
					continue;
				}
				if (OBJ_obj2nid(asn1_obj) != NID_commonName) {
					continue;
				}
				int data_length = asn1_str->length;
				bool s = bdd_name_descriptions_set_ssl_ctx(
					name_descriptions,
					(char *)asn1_str->data,
					data_length,
					ctx
				);
				if (s) {
					if (should_up_rc) {
						SSL_CTX_up_ref(ctx);
					} else {
						should_up_rc = true;
					}
				}
			}
		}
	}

	// if `ctx` is not referenced by any hashmap values,
	// then free `ctx`
	if (!should_up_rc) {
		SSL_CTX_free(ctx);
		// x509 and pkey's ref counts will be the same as
		// they were before this function was called
		return false;
	}

	// decrement ref counts, and invalidate some pointers
	X509_free(x509);
	EVP_PKEY_free(pkey);
	*x509_ref = NULL;
	*pkey_ref = NULL;
	return true;
}

struct hashmap *bdd_name_descriptions_create(void) {
	return hashmap_create((void (*)(void *)) & (bdd_name_description_destroy));
};
