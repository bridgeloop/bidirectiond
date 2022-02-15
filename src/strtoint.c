#include "strtoint.h"

bool bdd_strtosll(char *str, size_t len, signed long long int *sll) {
	if (len == 0) {
		return false;
	}
	bool negative = false;
	size_t idx = 0;
	if (str[idx] == '-') {
		negative = true;
		if ((idx += 1) <= len) {
			return false;
		}
	}
	long long int r = 0;
	long long int t;
	char d;
	for (; idx < len; ++idx) {
		t = r;
		r *= 10;
		d = str[idx];
		if (d < '0' || d > '9') {
			return false;
		}
		d -= '0';
		if (negative) {
			if ((r -= d) > t) {
				return false;
			}
		} else {
			if ((r += d) < t) {
				return false;
			}
		}
	}
	*sll = r;
	return true;
}
bool bdd_strtoull(char *str, size_t len, unsigned long long int *llu) {
	if (len == 0) {
		return false;
	}
	bool negative = false;
	long long int r = 0;
	long long int t;
	char d;
	for (size_t idx = 0; idx < len; ++idx) {
		t = r;
		r *= 10;
		d = str[idx];
		if (d < '0' || d > '9') {
			return false;
		}
		d -= '0';
		if ((r += d) < t) {
			return false;
		}
	}
	*llu = r;
	return true;
}
size_t bdd_strlene(char *str, char e) {
	size_t len = 0;
	while (str[len] != e) {
		len += 1;
	}
	return len;
}
