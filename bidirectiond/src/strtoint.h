#ifndef bidirectiond__strtolli__h
#define bidirectiond__strtolli__h

#include <stdbool.h>
#include <stddef.h>

bool strtolls(char *str, size_t len, signed long long int *sll);
bool strtollu(char *str, size_t len, unsigned long long int *ull);

#endif
