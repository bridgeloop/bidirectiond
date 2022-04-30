#ifndef bidirectiond__cp_pwd__h
#define bidirectiond__cp_pwd__h
#include <stdbool.h>
struct cp_pwd_ctx {
	bool success;
	char *password;
};
int cp_pwd(char *dest, int dest_sz, int rwflag, void *_ctx /* get compiler warning to stfu */);
#endif
