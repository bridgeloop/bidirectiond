#ifndef bidirectiond_core__settings__h
#define bidirectiond_core__settings__h

#include <openssl/ssl.h>
#include <stdbool.h>

#include "../src/headers/bdd_name_descs.h"
#include "../src/headers/bdd_settings.h"
#include "../src/headers/bdd_service.h"
#include "../src/headers/bdd_stop.h"

struct bdd_name_descs;
struct bdd_instance *bdd_go(struct bdd_settings settings);
void bdd_wait(void);
void bdd_destroy(void);

bool bdd_name_descs_use_cert_pkey(
	struct bdd_name_descs *name_descriptions,
	X509 **x509_ref,
	EVP_PKEY **pkey_ref
);

struct bdd_name_descs *bdd_name_descs_create(void);
void bdd_name_descs_destroy(struct bdd_name_descs **name_descs);

#endif
