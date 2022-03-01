#ifndef bidirectiond__strtolli__h
#define bidirectiond__strtolli__h

#include <stdbool.h>
#include <stddef.h>

bool bdd_strtosll(char *str, size_t len, signed long long int *sll);
bool bdd_strtoull(char *str, size_t len, unsigned long long int *ull);
size_t bdd_strlene(char *str, char e);

#endif
