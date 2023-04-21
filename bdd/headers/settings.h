#ifndef bidirectiond__settings__h
#define bidirectiond__settings__h

#include <openssl/ssl.h>
#include <stdbool.h>

#include "../src/headers/bdd_settings.h"
#include "../src/headers/bdd_service.h"
#include "../src/headers/bdd_stop.h"

struct bdd_name_descs;
struct bdd_instance *bdd_go(struct bdd_settings settings);
void bdd_wait(void);
void bdd_destroy(void);

void bdd_name_descs_use_cert_pkey(
	X509 *x509,
	EVP_PKEY *pkey
);

bool bdd_name_descs_create(uint16_t n_threads);
void bdd_name_descs_destroy(void);

#endif
