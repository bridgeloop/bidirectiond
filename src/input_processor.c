#include "input_processor.h"
#include "cp_pwd.h"
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <openssl/ssl.h>
#include <pthread.h>
#include <errno.h>
#include "tls_put.h"
#include "core_settings.h"

#ifndef BIDIRECTIOND_BUFFERED_READ_BUF_SIZE
#define BIDIRECTIOND_BUFFERED_READ_BUF_SIZE 0x200
#endif

struct buffered_read_ctx {
	unsigned int idx;
	unsigned int len;
	char byte;
};
#define BUFFERED_READ_CTX_INITALISER { .idx = 0, .len = 0, .byte = 0, }
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

	input_processor__process:;
	uint8_t n_matches = sizeof(match_list) / sizeof(match_list[0]);
	uint8_t match;
	bool matches[sizeof(match_list) / sizeof(match_list[0])];
	for (typeof(match) idx = 0; idx < n_matches; ++idx) {
		matches[idx] = true;
	}
	for (uint8_t it = 0;; ++it) {
		match = 0;
		if (it == 0xFF) {
			goto input_processor__process;
		}
		if (!buffered_read()) {
			goto input_processor__err;
		}
		if (br_ctx.byte == 1) {
			goto input_processor__process;
		}
		if (br_ctx.byte == 0) {
			if (it == 0) {
				goto input_processor__wait;
			}
			for (typeof(match) rmatch = 0; rmatch < n_matches; ++rmatch) {
				match = n_matches - 1 - rmatch;
				if (matches[match]) {
					goto input_processor__matched;
				}
			}
			goto input_processor__wait;
		}
		for (; match < n_matches; ++match) {
			if (it >= match_list[match].str_sz) {
				if ((n_matches = match) == 0) {
					goto input_processor__process;
				}
				break;
			}
			if (match_list[match].str[it] != br_ctx.byte) {
				matches[match] = false;
			}
		}
	}

	input_processor__matched:;
	if (match == 0 /* TLS_PEM_LOAD */) {
		SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
		BIO *bio = NULL;
		X509 *cert = NULL;
		EVP_PKEY *key = NULL;
		uint8_t e = 0;
		if (ctx == NULL) {
			goto input_processor__tls_pem_load_err;
		}
		if (SSL_CTX_set_cipher_list(ctx, "AES256-SHA256") == 0) {
			goto input_processor__tls_pem_load_err;
		}
		if ((bio = BIO_new(BIO_s_mem())) == NULL) {
			goto input_processor__tls_pem_load_err;
		}
		for (;;) {
			if (!buffered_read()) {
				e |= 0b1;
				goto input_processor__tls_pem_load_err;
			}
			if (br_ctx.byte == 0) {
				break;
			}
			if (br_ctx.byte == 1 || BIO_write(bio, &(br_ctx.byte), 1) != 1) {
				goto input_processor__tls_pem_load_err;
			}
		}
		if ((cert = PEM_read_bio_X509(bio, NULL, NULL, "")) == NULL) {
			goto input_processor__tls_pem_load_err;
		}
		BIO_free(bio);
		if ((bio = BIO_new(BIO_s_mem())) == NULL) {
			goto input_processor__tls_pem_load_err;
		}
		for (;;) {
			if (!buffered_read()) {
				e |= 0b1;
				goto input_processor__tls_pem_load_err;
			}
			if (br_ctx.byte == 0) {
				break;
			}
			if (br_ctx.byte == 1 || BIO_write(bio, &(br_ctx.byte), 1) != 1) {
				goto input_processor__tls_pem_load_err;
			}
		}
		if (!buffered_read()) {
			br_ctx.byte = 1;
		}
		struct bdd_cp_ctx cp_ctx = {
			.success = false,
			.password = NULL,
		};
		if (br_ctx.byte != 1) {
			char env_variable_name[0x100];
			for (size_t idx = 0;; ++idx) {
				if (idx == sizeof(env_variable_name)) {
					goto input_processor__tls_pem_load_err;
				}
				env_variable_name[idx] = br_ctx.byte;
				if (br_ctx.byte == 0) {
					cp_ctx.password = getenv(env_variable_name);
					break;
				}
				if (br_ctx.byte == 1) {
					goto input_processor__tls_pem_load_err;
				}
				if (!buffered_read()) {
					e |= 0b1;
					goto input_processor__tls_pem_load_err;
				}
			}
		}
		if ((key = PEM_read_bio_PrivateKey(bio, NULL, bdd_cp_pwd, &(cp_ctx))) == NULL) {
			goto input_processor__tls_pem_load_err;
		}
		if (SSL_CTX_use_certificate(ctx, cert) == 1 &&
			SSL_CTX_use_PrivateKey(ctx, key) == 1) {
			struct locked_hashmap *lh = hashmap_lock(settings.name_descriptions);
			if (tls_put(lh, &(ctx))) {
				e |= 0b10;
			}
			locked_hashmap_unlock(&(lh));
		}
		input_processor__tls_pem_load_err:;
		if (ctx != NULL) {
			SSL_CTX_free(ctx);
		}
		if (bio != NULL) {
			BIO_free(bio);
		}
		if (cert != NULL) {
			X509_free(cert);
		}
		if (key != NULL) {
			EVP_PKEY_free(key);
		}
		if (e & 0b10) {
			puts("added SSL_CTX");
		} else {
			puts("failed to add SSL_CTX");
		}
		if (e & 0b1) {
			goto input_processor__err;
		}
	} else if (match == 1) {
		puts("input_processor got PING!");
	}

	input_processor__wait:;
	while (br_ctx.byte != 1) {
		if (!buffered_read()) {
			goto input_processor__err;
		}
		if (br_ctx.byte == 1) {
			break;
		}
		puts("extraneous byte sent to input_processor");
	}
	
	goto input_processor__process;

	input_processor__err:;
	shutdown(fd, SHUT_RDWR);
	close(fd);
	return;
}
