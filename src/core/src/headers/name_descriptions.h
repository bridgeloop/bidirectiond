#ifndef bidirectiond_core__name_descriptions__h
#define bidirectiond_core__name_descriptions__h

#include <openssl/ssl.h>

struct bdd_service_instance {
	const struct bdd_service *service;
	void *instance_info;

	struct bdd_service_instance *next;
};
struct bdd_name_description {
	X509 *x509;
	EVP_PKEY *pkey;
	struct bdd_service_instance *service_instances;
};

#endif
