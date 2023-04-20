#include <limits.h>
#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <openssl/x509v3.h>
#include <string.h>

#include "headers/hashmap.h"

#include "headers/name_descs.h"
#include "headers/bdd_service.h"
#include "headers/instance.h"

#define HASHMAP bdd_gv.name_descs
static struct hashmap_area *AREA = NULL;

// name_descs: hashmap of name_desc
// name_desc: see `struct bdd_name_desc` in name_descs.h

// struct bdd_name_desc
static struct bdd_name_desc *alloc_name_desc(void) {
	struct bdd_name_desc *name_desc = malloc(sizeof(struct bdd_name_desc));
	if (name_desc == NULL) {
		return NULL;
	}
	if (pthread_rwlock_init(&(name_desc->rwlock), NULL) != 0) {
		free(name_desc);
		return NULL;
	}
	name_desc->x509 = NULL;
	name_desc->pkey = NULL;
	name_desc->service_instances = NULL;
	return name_desc;
}

static inline void remove_cert_pkey(struct bdd_name_desc *name_desc) {
	if (name_desc->x509 == NULL) {
		assert(name_desc->pkey == NULL);
		return;
	}
	assert(name_desc->pkey != NULL);

	// misleading function name; it
	// actually decs the ref count and
	// frees the shit if the rc hits 0
	X509_free(name_desc->x509);
	EVP_PKEY_free(name_desc->pkey);
	name_desc->x509 = NULL;
	name_desc->pkey = NULL;

	return;
}

static void remove_service_insts(struct bdd_name_desc *name_desc) {
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

static bool add_service_inst(
	struct bdd_name_desc *name_desc,
	struct bdd_service_instance *service_inst
) {
	const char *const *inst_sp = service_inst->service->supported_protocols;

	// iterate over the service instances
	// currently reachable from this name
	struct bdd_service_instance **curr = &(name_desc->service_instances);
	for (; (*curr) != NULL; curr = &((*curr)->next)) {
		const char *const *curr_sp = (*curr)->service->supported_protocols;

		// services without a protocol list can, with low
		// priority (see: accept.c), handle any protocol
		// a NULL protocol list is effectively a wildcard
		if (inst_sp == NULL || curr_sp == NULL) {
			// if inst_sp is NULL, and curr_sp is NULL, then
			// return false as to not have multiple wildcard services
			if (inst_sp == curr_sp) {
				return false;
			}
			continue;
		}

		// prevent conflicts where a protocol
		// is listed by multiple services
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

static inline void set_cert_pkey(struct bdd_name_desc *name_desc, X509 *x509, EVP_PKEY *pkey) {
	name_desc->x509 = x509;
	name_desc->pkey = pkey;
	return;
}

static void free_name_desc(struct bdd_name_desc *name_desc) {
	pthread_rwlock_destroy(&(name_desc->rwlock));
	remove_cert_pkey(name_desc);
	remove_service_insts(name_desc);
	free(name_desc);
	return;
}

// name_descs hashmap
static bool punycode_check(const char *input, unsigned int len, unsigned int n_basic) {
	// adapted from https://www.rfc-editor.org/rfc/rfc3492#appendix-C
	enum {
		base = 36, initial_bias = 72, initial_n = 0x80, tmin = 1, tmax = 26,
		skew = 38, damp = 700,
	};
	unsigned int
		n = initial_n,
		bias = initial_bias,
		out = n_basic;

	// process after delimiter
	for (
		unsigned int i = 0, in = 0, oldi;
		in < len; // break after in >= len
		++out
	) {
		oldi = i;

		unsigned int
			w = 1,
			k = base;

		for (;; k += base) {
			if (in == len) {
				return false;
			}
			unsigned int digit = input[in++];

			if (digit - 48 < 10) {
				digit -= 22;
			} else if (digit - 65 < 26) {
				digit -= 65;
			} else if (digit - 97 < 26) {
				digit -= 97;
			} else {
				return false;
			}

			if (digit >= base) {
				return false;
			}

			if (digit > (UINT_MAX - i) / w) {
				// `i += digit * w` would overflow
				return false;
			}
			i += digit * w;

			unsigned int t;
			if (k <= bias) {
				t = tmin;
			} else if (k >= bias + tmax) {
				t = tmax;
			} else {
				t = k - bias;
			}
			if (digit < t) {
				break;
			}

			if (w > UINT_MAX / (base - t)) {
			// `w *= (base - t)` would overflow
				return false;
			}
			w *= (base - t);
		}

		// `out + 1` to adapt for the character we're processing
		// (we'll increment `out` after this iteration with `++out` in the for loop's post statement)
		unsigned int numpoints = out + 1;
		unsigned int delta = (i - oldi) / (oldi == 0 ? damp : 2);
		delta += delta / numpoints;

		for (k = 0; delta > ((base - tmin) * tmax) / 2; k += base) {
			delta /= base - tmin;
		}

		bias = k + (base - tmin + 1) * delta / (delta + skew);

		// add the amount of times wrapped around to n
		if (i / (out + 1) > UINT_MAX - n) {
			// `n += i / (out + 1)` would overflow
			return false;
		}
		n += i / (out + 1);

		// wrap i around
		i %= (out + 1);

		// to-do: xn--iea should return false (uppercase; \u0114)
		//        (we already have `i` and `n`)
		// i'm not passionate enough to implement this; i don't
		// get paid enough ($0) and i'm rich anyway ($999,999,999).
		// am i the richest person ever? prolly.
	}
	return true;
}

// idna2008
const char *bdd_name(const char *name, size_t *name_sz) {
	size_t sz = *name_sz;
	size_t idx = 0;
	if (sz >= 1 && name[sz - 1] == '.') {
		// conceptually remove the period
		// from the end of the string
		sz -= 1;
	}
	// max length for a fully-qualified dns
	// name is 255. if the domain name passed
	// to the function ends with a period, then
	// we decrement its size by 1. this code will
	// then treat the dns name as though it does end
	// with a period. (since the dns name is assumed to
	// end with a period, the maximum amount of octets
	// that can come before it must be 254.)
	if (sz > 254) {
		return NULL;
	}
	bool req_prd;
	if (sz > 0 && name[0] == '*') {
		// conceptually remove the
		// asterisk from the string
		sz -= 1;
		name += 1;
		req_prd = true;
	} else {
		req_prd = false;
	}
	if (sz > 0 && name[0] == '.') {
		if (sz == 254) {
			// invalid wildcard; name
			// guaranteed to exceed 255 octets
			return NULL;
		}
		// skip period
		idx = 1;
	} else if (req_prd) {
		// a period MUST follow an asterisk
		return NULL;
	}

	if (sz == 0) {
		goto success;
	}

	bool name_contains_alphabetic_character = false;
	enum label_type { nr_ldh, a, }
		label_type = nr_ldh;
	size_t
		label_sz = 0,
		dash_idx;
	for (;; ++idx) {
		if (idx == sz || name[idx] == '.') {
			if (label_sz == 0) {
				return NULL;
			}
			if (label_type == a) {
				unsigned int label_idx = idx - label_sz;
				unsigned int before_idx = label_idx + 4 /* xn-- */;
				unsigned int
					n_after_delim = idx - (dash_idx + 1),
					n_before_delim = dash_idx < before_idx ? 0 : dash_idx - before_idx;
				if (n_after_delim == 0 || !punycode_check(&(name[dash_idx + 1]), n_after_delim, n_before_delim)) {
					return NULL;
				}
			}
			if (idx == sz) {
				break;
			} else {
				label_sz = 0;
				label_type = nr_ldh;
				continue;
			}
		}

		if (label_sz == 63) {
			return NULL;
		}

		if (name[idx] == '-') {
			dash_idx = idx;
			if (
				// first character in label
				label_sz == 0 ||
				// last character in the entire string
				// or the last character of the label
				(idx + 1 == sz || name[idx + 1] == '.')
			) {
				return NULL;
			}
			if (label_sz == 3 && name[idx - 1] == '-') {
				if (strncasecmp(&(name[idx - 3]), "xn", 2) != 0) {
					// label[2..=3] is "--", but label[0..=1] isn't "xn"
					return NULL;
				} else {
					assert(label_type == nr_ldh);
					label_type = a;
				}
			}
		} else if (name[idx] < '0' || name[idx] > '9') {
			if ((name[idx] | 0x20) >= 'a' && (name[idx] | 0x20) <= 'z') {
				name_contains_alphabetic_character = true;
			} else {
				// u-labels are unsupported
				return NULL;
			}
		}

		label_sz += 1;
	}
	if (!name_contains_alphabetic_character) {
		return NULL;
	}

	success:;
	*name_sz = sz;
	return name;
}

static struct bdd_name_desc *wlock_name_desc(struct hashmap_key *key/*, bool *created*/) {
	assert(key != NULL/* && created != NULL*/);

	struct bdd_name_desc *expected = NULL;
	enum hashmap_cas_result r;

	r = hashmap_cas(
		HASHMAP, AREA, key,
		(void **)&(expected), NULL,
		hashmap_cas_get, (void *)0
	);

	if (r == hashmap_cas_again) {
		//*created = false;
		return expected;
	}

	struct bdd_name_desc *name_desc = alloc_name_desc();
	if (name_desc == NULL) {
		return NULL;
	}
	pthread_rwlock_wrlock(&(name_desc->rwlock));
	// works because only the command thread (this thread) can mutate HASHMAP
	r = hashmap_cas(
		HASHMAP, AREA, key,
		(void **)&(expected), name_desc,
		hashmap_cas_set, NULL
	);

	if (r != hashmap_cas_success) {
		pthread_rwlock_unlock(&(name_desc->rwlock));
		free_name_desc(name_desc);
		return NULL;
	}

	//*created = true;
	return name_desc;
}

// exposed function
// bdd_name_descs_add_service_instance **cannot** replace a service instance.
// it may only add service instances.
bool bdd_name_descs_add_service_instance(
	const char *scope,
	size_t scope_sz,

	const struct bdd_service *service,
	const void *instance_info
) {
	// normalize scope
	scope = bdd_name(scope, &(scope_sz));
	if (scope == NULL) {
		return false;
	}

	struct bdd_service_instance *service_inst = malloc(sizeof(struct bdd_service_instance));
	if (service_inst == NULL) {
		return false;
	}
	service_inst->service = service;
	service_inst->instance_info = instance_info;
	service_inst->next = NULL;

	struct hashmap_key key;
	hashmap_key((void *)scope, scope_sz, &(key));
	struct bdd_name_desc *name_desc = wlock_name_desc(&(key));
	if (name_desc == NULL) {
		err:;
		free(service_inst);
		return false;
	}
	bool success = add_service_inst(name_desc, service_inst);
	pthread_rwlock_unlock(&(name_desc->rwlock));
	if (!success) {
		goto err;
	}
	return true;
}

// internal function
// cannot be called concurrently
static bool hashmap_set_cert_pkey(
	const char *scope,
	size_t scope_sz,

	X509 *x509,
	EVP_PKEY *pkey
) {
	// normalize scope
	scope = bdd_name(scope, &(scope_sz));
	if (scope == NULL) {
		return false;
	}

	// create or retrieve the name's description
	struct hashmap_key key;
	hashmap_key((void *)scope, scope_sz, &(key));
	struct bdd_name_desc *name_desc = wlock_name_desc(&(key));
	if (name_desc == NULL) {
		return false;
	}

	// set its certificate and private key
	set_cert_pkey(name_desc, x509, pkey);

	pthread_rwlock_unlock(&(name_desc->rwlock));
	return true;
}

// exposed function
// cannot be called concurrently
void bdd_name_descs_use_cert_pkey(
	X509 *x509,
	EVP_PKEY *pkey
) {
	// to-do: support for (owned/reserved) ip addresses?

	#define update() \
		if (hashmap_set_cert_pkey( \
			(const char *)asn1_str->data, \
			asn1_str->length, \
			x509, \
			pkey \
		)) { \
			printf("updated %.*s\n", asn1_str->length, asn1_str->data); \
			X509_up_ref(x509); \
			EVP_PKEY_up_ref(pkey); \
		}
	GENERAL_NAMES *dns_alt_names = X509_get_ext_d2i(x509, NID_subject_alt_name, 0, 0);
	X509_NAME *dns_subject_names = X509_get_subject_name(x509);
	if (dns_alt_names != NULL) {
		int n_dns_alt_names = sk_GENERAL_NAME_num(dns_alt_names);
		for (int idx = 0; idx < n_dns_alt_names; ++idx) {
			GENERAL_NAME *entry = sk_GENERAL_NAME_value(dns_alt_names, idx);
			if (entry->type != GEN_DNS) {
				continue;
			}
			ASN1_IA5STRING *asn1_str = entry->d.dNSName;
			update();
		}
		GENERAL_NAMES_free(dns_alt_names);
	} else if (dns_subject_names != NULL) {
		int n_dns_subject_names = X509_NAME_entry_count(dns_subject_names);
		for (int idx = 0; idx < n_dns_subject_names; ++idx) {
			X509_NAME_ENTRY *entry = X509_NAME_get_entry(dns_subject_names, idx);
			ASN1_OBJECT *asn1_obj = X509_NAME_ENTRY_get_object(entry);
			ASN1_STRING *asn1_str = X509_NAME_ENTRY_get_data(entry);
			if (
				asn1_obj == NULL || asn1_str == NULL ||
				OBJ_obj2nid(asn1_obj) != NID_commonName
			) {
				continue;
			}
			update();
		}
	}
	return;
}

static void acq(struct bdd_name_desc *name_desc, enum hashmap_callback_reason reason, uintptr_t md) {
	assert(name_desc != NULL && md <= 1);
	static_assert(sizeof(uintptr_t) >= sizeof(char) /* 1 */, "what");
	switch (reason) {
		case (hashmap_acquire): {
			if (md == 0) {
				pthread_rwlock_wrlock(&(name_desc->rwlock));
			} else {
				pthread_rwlock_rdlock(&(name_desc->rwlock));
			}
			break;
		}
		case (hashmap_drop_destroy): {
			free_name_desc(name_desc);
			break;
		}
		default: abort();
	}
	return;
}
bool bdd_name_descs_create(uint16_t n_threads) {
	HASHMAP = hashmap_create(n_threads, 64, 0.94, 2, (hashmap_callback)acq);
	if (HASHMAP != NULL) {
		AREA = hashmap_area(bdd_gv.name_descs);
		return true;
	}
	return false;
}

void bdd_name_descs_destroy(void) {
	if (HASHMAP != NULL) {
		hashmap_area_release(HASHMAP, AREA);
		hashmap_destroy(HASHMAP);
	}
	return;
}
