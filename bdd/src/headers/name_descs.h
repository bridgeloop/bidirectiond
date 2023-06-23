#ifndef bidirectiond__name_descs__h
#define bidirectiond__name_descs__h

#include <openssl/ssl.h>

struct bdd_service_instance {
	const struct bdd_service *service;
	const void *instance_info;

	struct bdd_service_instance *next;
};
struct bdd_name_desc {
	// one writer, multiple readers
	// only protects this struct's members, obviously not the struct itself!
	pthread_rwlock_t rwlock;

	X509 *x509;
	EVP_PKEY *pkey;
	
	struct bdd_service_instance *service_instances;
};

const char *bdd_name(const char *name, size_t *name_sz);

#endif
