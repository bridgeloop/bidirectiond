#include "tls_put.h"
#include "core_settings.h"
#include <openssl/x509v3.h>
#include <string.h>

// hashmap_lock call makes it thread-safe
bool tls_put(struct locked_hashmap *ns, SSL_CTX **ctx_ref) {
	// take the ref
	SSL_CTX *ctx = *ctx_ref;
	*ctx_ref = NULL;

	bool should_up_rc = false;
	GENERAL_NAMES *dns_alt_names = X509_get_ext_d2i(SSL_CTX_get0_certificate(ctx), NID_subject_alt_name, 0, 0);
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
			if (bdd_name_descriptions_set_ssl_ctx(ns, (char *)asn1_str->data, data_length, ctx)) {
				if (should_up_rc) {
					SSL_CTX_up_ref(ctx);
				} else {
					should_up_rc = true;
				}
			}
		}
		GENERAL_NAMES_free(dns_alt_names);
	} else { // rfc6125
		X509_NAME *dns_subject_names = X509_get_subject_name(SSL_CTX_get0_certificate(ctx));
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
				if (bdd_name_descriptions_set_ssl_ctx(ns, (char *)asn1_str->data, data_length, ctx)) {
					if (should_up_rc) {
						SSL_CTX_up_ref(ctx);
					} else {
						should_up_rc = true;
					}
				}
			}
		}
	}

	if (!should_up_rc) /* if `ctx` is not referenced by any hashmap values, then free `ctx` */ {
		SSL_CTX_free(ctx);
		return false;
	}

	return true;
}
