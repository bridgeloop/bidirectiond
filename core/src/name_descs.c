#include <stdbool.h>
#include <stddef.h>
#include <hashmap/hashmap.h>
#include <openssl/x509v3.h>
#include <string.h>

#include "headers/name_descs.h"
#include "headers/bdd_name_descs.h"
#include "headers/bdd_service.h"

// struct bdd_name_desc
struct bdd_name_desc *bdd_name_desc_alloc(void) {
	struct bdd_name_desc *name_desc = malloc(sizeof(struct bdd_name_desc));
	if (name_desc == NULL) {
		return NULL;
	}
	name_desc->x509 = NULL;
	name_desc->pkey = NULL;
	name_desc->service_instances = NULL;
	return name_desc;
}

void bdd_name_desc_clean_cert_pkey(struct bdd_name_desc *name_desc) {
	if (name_desc->x509 != NULL) {
		// misleading function name; it actually
		// decs the ref count and frees the shit
		// if the rc hits 0
		X509_free(name_desc->x509);
		EVP_PKEY_free(name_desc->pkey);
		name_desc->x509 = NULL;
		name_desc->pkey = NULL;
	}
	return;
}

void bdd_name_desc_clean_services(struct bdd_name_desc *name_desc) {
	for (
		struct bdd_service_instance **service_inst = &(name_desc->service_instances);
		(*service_inst) != NULL;
	) {
		struct bdd_service_instance *curr = (*service_inst);
		(*service_inst) = curr->next;
		if (curr->instance_info != NULL) {
			curr->service->instance_info_destructor((void *)curr->instance_info);
		}
		free(curr);
	}
	return;
}

bool bdd_name_desc_add_service_instance(
	struct bdd_name_desc *name_desc,
	struct bdd_service_instance *service_inst
) {
	struct bdd_service_instance **curr = &(name_desc->service_instances);
	const char *const *inst_sp = service_inst->service->supported_protocols;
	for (; (*curr) != NULL; curr = &((*curr)->next)) {
		const char *const *curr_sp = (*curr)->service->supported_protocols;
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

void bdd_name_desc_set_cert_pkey(struct bdd_name_desc *name_desc, X509 *x509, EVP_PKEY *pkey) {
	bdd_name_desc_clean_cert_pkey(name_desc);
	name_desc->x509 = x509;
	name_desc->pkey = pkey;
	return;
}

void bdd_name_desc_destroy(struct bdd_name_desc *name_desc) {
	bdd_name_desc_clean_services(name_desc);
	bdd_name_desc_clean_cert_pkey(name_desc);
	free(name_desc);
	return;
}

void bdd_name_desc_destroy_hm(struct bdd_name_desc *name_desc, enum hashmap_drop_mode _) {
	bdd_name_desc_destroy(name_desc);
	return;
}


// name_descs hashmap
#define bdd_name_descs_prelude() \
	bool r = false; \
	struct hashmap *name_descs = (struct hashmap *)bdd_name_descs; \
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
	struct hashmap_key key = HASHMAP_KEY_INITIALIZER; \
	hashmap_key_obtain(name_descs, &(key), (char *)scope, scope_sz); \
	struct bdd_name_desc *name_desc; \
	bool created_name_desc; \
	if (!hashmap_get(name_descs, &(key), (void *)&(name_desc))) { \
		if ((name_desc = bdd_name_desc_alloc()) == NULL) { \
			goto out; \
		} \
		created_name_desc = true; \
	} else { \
		created_name_desc = false; \
	}
#define bdd_name_descs_out() \
	out:; \
	hashmap_key_release(name_descs, &(key), false); \
	return r;

// exposed function
// bdd_name_descs_add_service_instance **cannot** replace a service instance;
// it may only add service instances.
bool bdd_name_descs_add_service_instance(
	struct bdd_name_descs *bdd_name_descs,
	const char *scope,
	size_t scope_sz,
	const struct bdd_service *service,
	const void **instance_info
) {
	bdd_name_descs_prelude();

	struct bdd_service_instance *service_inst = malloc(sizeof(struct bdd_service_instance));
	if (service_inst == NULL) {
		goto out;
	}
	service_inst->service = service;
	service_inst->next = NULL;
	if (!bdd_name_desc_add_service_instance(name_desc, service_inst)) {
		if (created_name_desc) {
			bdd_name_desc_destroy(name_desc);
		}
		free(service_inst);
		goto out;
	}

	if (created_name_desc) {
		if (!hashmap_set(name_descs, &(key), name_desc)) {
			// will free service_inst
			bdd_name_desc_destroy(name_desc);
			goto out;
		}
	}

	service_inst->instance_info = *instance_info;
	*instance_info = NULL;
	r = true;

	goto out;

	bdd_name_descs_out();
}

// internal function
bool bdd_name_descs_set_cert_pkey(
	struct bdd_name_descs *bdd_name_descs,
	const char *scope,
	size_t scope_sz,
	X509 *x509,
	EVP_PKEY *pkey
) {
	bdd_name_descs_prelude();

	bdd_name_desc_set_cert_pkey(name_desc, x509, pkey);

	if (created_name_desc) {
		if (!hashmap_set(name_descs, &(key), name_desc)) {
			bdd_name_desc_destroy(name_desc);
			goto out;
		}
	}

	r = true;
	goto out;

	bdd_name_descs_out();
}

// exposed function
bool bdd_name_descs_use_cert_pkey(
	struct bdd_name_descs *bdd_name_descs,
	X509 **x509_ref,
	EVP_PKEY **pkey_ref
) {
	X509 *x509 = *x509_ref;
	EVP_PKEY *pkey = *pkey_ref;

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
			bool s = bdd_name_descs_set_cert_pkey(
				bdd_name_descs,
				(char *)asn1_str->data,
				data_length,
				x509,
				pkey
			);
			if (s) {
				if (should_up_rc) {
					X509_up_ref(x509);
					EVP_PKEY_up_ref(pkey);
				} else {
					should_up_rc = true;
				}
			}
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
				bool s = bdd_name_descs_set_cert_pkey(
					bdd_name_descs,
					(char *)asn1_str->data,
					data_length,
					x509,
					pkey
				);
				if (s) {
					if (should_up_rc) {
						X509_up_ref(x509);
						EVP_PKEY_up_ref(pkey);
					} else {
						should_up_rc = true;
					}
				}
			}
		}
	}

	if (!should_up_rc) {
		// x509 and pkey's ref counts will be the same as
		// they were before this function was called
		return false;
	}

	// invalidate some pointers
	*x509_ref = NULL;
	*pkey_ref = NULL;
	return true;
}

struct bdd_name_descs *bdd_name_descs_create(void) {
	return (struct bdd_name_descs *)hashmap_create(183, 1, (void *)&(bdd_name_desc_destroy_hm));
}

void bdd_name_descs_destroy(struct bdd_name_descs **name_descs) {
	hashmap_destroy_ref((struct hashmap **)name_descs);
	return;
}
