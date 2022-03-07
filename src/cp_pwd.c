#include "cp_pwd.h"
#include <assert.h>
#include <string.h>

int bdd_cp_pwd(char *dest, int dest_sz, int rwflag, void *_ctx) {
	assert(rwflag == 0);
	struct bdd_cp_ctx *ctx = _ctx;
	ctx->success = false;
	char *src = ctx->password;
	if (src == NULL) {
		return 0;
	}
	int src_len = (int)strlen(src);
	if (dest_sz <= 0 || src_len <= 0 || src_len > dest_sz) {
		return 0;
	}
	memcpy(dest, src, src_len);
	ctx->success = true;
	return src_len;
}