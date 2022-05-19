#include "input_processor.h"

#include "core_settings.h"
#include "cp_pwd.h"

#include <errno.h>
#include <fcntl.h>
#include <openssl/ssl.h>
#include <pthread.h>
#include <sys/stat.h>
#include <unistd.h>

struct buffered_read_ctx {
	unsigned int idx;
	unsigned int len;
	char byte;
};
#define BUFFERED_READ_CTX_INITALISER \
	{ \
		.idx = 0, .len = 0, .byte = 0, \
	}
static bool buffered_read(int fd, char *buf, int buf_sz, struct buffered_read_ctx *ctx) {
	if (buf_sz < 0) {
		return false;
	}
	if (ctx->idx == ctx->len) {
		for (;;) {
			int r = read(fd, buf, buf_sz);
			if (r < 0 && errno == EINTR) {
				continue;
			}
			if (r <= 0) {
				return false;
			}
			ctx->len = r;
			ctx->idx = 0;
			break;
		}
	}
	ctx->byte = buf[ctx->idx++];
	return true;
}

#define buffered_read() buffered_read(fd, br_buf, br_buf_sz, &(br_ctx))
void input_processor(int sfd, char *br_buf, int br_buf_sz) {
	int fd = accept(sfd, NULL, 0);
	struct buffered_read_ctx br_ctx = BUFFERED_READ_CTX_INITALISER;
	static struct {
		char *str;
		uint8_t str_sz;
	} match_list[] = {
		{
			.str = "TLS_PEM_LOAD",
			.str_sz = 12,
		},
		{
			.str = "PING",
			.str_sz = 4,
		},
	};

	process:;
	uint8_t n_matches = sizeof(match_list) / sizeof(match_list[0]);
	uint8_t match;
	bool matches[sizeof(match_list) / sizeof(match_list[0])];
	for (typeof(match) idx = 0; idx < n_matches; ++idx) {
		matches[idx] = true;
	}
	for (uint8_t it = 0;; ++it) {
		match = 0;
		if (it == 0xFF) {
			goto process;
		}
		if (!buffered_read()) {
			goto err;
		}
		if (br_ctx.byte == 1) {
			goto process;
		}
		if (br_ctx.byte == 0) {
			if (it == 0) {
				goto wait;
			}
			for (typeof(match) rmatch = 0; rmatch < n_matches; ++rmatch) {
				match = n_matches - 1 - rmatch;
				if (matches[match]) {
					goto matched;
				}
			}
			goto wait;
		}
		for (; match < n_matches; ++match) {
			if (it >= match_list[match].str_sz) {
				if ((n_matches = match) == 0) {
					goto process;
				}
				break;
			}
			if (match_list[match].str[it] != br_ctx.byte) {
				matches[match] = false;
			}
		}
	}

	matched:;
	if (match == 0 /* TLS_PEM_LOAD */) {
		uint8_t e = 0;

		BIO *bio = NULL;
		X509 *x509 = NULL;
		EVP_PKEY *pkey = NULL;

		bio = BIO_new(BIO_s_mem());
		if (bio == NULL) {
			goto tls_pem_load_err;
		}

		for (;;) {
			if (!buffered_read()) {
				e |= 0b1;
				goto tls_pem_load_err;
			}
			if (br_ctx.byte == 0) {
				break;
			}
			if (br_ctx.byte == 1 || BIO_write(bio, &(br_ctx.byte), 1) != 1) {
				goto tls_pem_load_err;
			}
		}

		// deserialize the certificate
		x509 = PEM_read_bio_X509(bio, NULL, NULL, "");
		if (x509 == NULL) {
			goto tls_pem_load_err;
		}

		BIO_free(bio);
		bio = BIO_new(BIO_s_mem());
		if (bio == NULL) {
			goto tls_pem_load_err;
		}

		for (;;) {
			if (!buffered_read()) {
				e |= 0b1;
				goto tls_pem_load_err;
			}
			if (br_ctx.byte == 0) {
				break;
			}
			if (br_ctx.byte == 1 || BIO_write(bio, &(br_ctx.byte), 1) != 1) {
				goto tls_pem_load_err;
			}
		}

		// optionally, get the passphrase
		if (!buffered_read()) {
			br_ctx.byte = 1;
		}
		struct cp_pwd_ctx cp_ctx = {
			.success = false,
			.password = NULL,
		};
		if (br_ctx.byte != 1) {
			char env_variable_name[0x100];
			for (size_t idx = 0;; ++idx) {
				if (idx == sizeof(env_variable_name)) {
					goto tls_pem_load_err;
				}
				env_variable_name[idx] = br_ctx.byte;
				if (br_ctx.byte == 0) {
					cp_ctx.password = getenv(env_variable_name);
					break;
				}
				if (br_ctx.byte == 1) {
					goto tls_pem_load_err;
				}
				if (!buffered_read()) {
					e |= 0b1;
					goto tls_pem_load_err;
				}
			}
		}

		// deserialize the private key
		pkey = PEM_read_bio_PrivateKey(bio, NULL, cp_pwd, &(cp_ctx));
		if (pkey == NULL) {
			goto tls_pem_load_err;
		}

		if (bdd_name_descs_use_cert_pkey(settings.name_descs, &(x509), &(pkey))) {
			e |= 0b10;
		}

		tls_pem_load_err:;
		if (bio != NULL) {
			BIO_free(bio);
		}
		if (x509 != NULL) {
			X509_free(x509);
		}
		if (pkey != NULL) {
			EVP_PKEY_free(pkey);
		}
		if (e & 0b10) {
			puts("added SSL_CTX");
		} else {
			puts("failed to add SSL_CTX");
		}
		if (e & 0b1) {
			goto err;
		}
	} else if (match == 1) {
		puts("input_processor got PING!");
	}

	wait:;
	while (br_ctx.byte != 1) {
		if (!buffered_read()) {
			goto err;
		}
		if (br_ctx.byte == 1) {
			break;
		}
		puts("extraneous byte sent to input_processor");
	}

	goto process;

	err:;
	shutdown(fd, SHUT_RDWR);
	close(fd);
	return;
}
