#ifndef bidirectiond_core__settings__h
#define bidirectiond_core__settings__h

#include <openssl/ssl.h>
#include <hashmap/hashmap.h>
#include <stdbool.h>
#include "src/headers/bdd_settings.h"
#include "src/headers/bdd_service.h"
#include "src/headers/bdd_stop.h"

struct bdd_instance;
struct bdd_instance *bdd_go(struct bdd_settings settings);
void bdd_wait(struct bdd_instance *instance);
void bdd_destroy(struct bdd_instance *instance);

bool bdd_name_descriptions_use_cert_pkey(
	struct locked_hashmap *name_descriptions,
	X509 **x509_ref,
	EVP_PKEY **pkey_ref
);

struct hashmap *bdd_name_descriptions_create(void);

#endif
