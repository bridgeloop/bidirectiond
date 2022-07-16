#ifndef bidirectiond_core__name_descs__h
#define bidirectiond_core__name_descs__h

#include <openssl/ssl.h>

struct bdd_service_instance {
	const struct bdd_service *service;
	const void *instance_info;

	struct bdd_service_instance *next;
};
struct bdd_name_desc {
	X509 *x509;
	EVP_PKEY *pkey;
	struct bdd_service_instance *service_instances;
};

void bdd_name_trim(const unsigned char *name, size_t *name_sz);

#endif
