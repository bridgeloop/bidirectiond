#ifndef bidirectiond__cp_pwd__h
#define bidirectiond__cp_pwd__h
#include <stdbool.h>
struct bdd_cp_ctx {
	bool success;
	char *password;
};
int bdd_cp_pwd(char *dest, int dest_sz, int rwflag, void *_ctx);
#endif