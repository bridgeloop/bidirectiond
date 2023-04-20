#include "strtoint.h"

#include <limits.h>

bool strtolls(char *str, size_t len, signed long long int *sll) {
	if (len == 0) {
		return false;
	}
	static unsigned char nmpdigits = 0, nmndigits = 0;
	if (nmpdigits == 0) {
		for (signed long long int m = LLONG_MAX; m; m /= 10) {
			nmpdigits += 1;
		}
		for (signed long long int m = LLONG_MIN; m; m /= 10) {
			nmndigits += 1;
		}
	}
	bool negative = false;
	size_t idx = 0;
	if (str[0] == '-') {
		idx += 1;
		negative = true;
	}
	signed long long int r = 0;
	char d, ndigits = 0;
	bool f = false;
	for (; idx < len; ++idx) {
		d = str[idx];
		if (!f && d == '0') {
			continue;
		}
		f = true;
		ndigits += 1;
		if (negative) {
			if (ndigits > nmndigits) {
				return false;
			}
		} else if (ndigits > nmpdigits) {
			return false;
		}
		if (d < '0' || d > '9') {
			return false;
		}
		d -= '0';
		r *= 10;
		if (negative) {
			if ((r - d) > 0) {
				return false;
			}
			r -= d;
		} else {
			if (d > (LLONG_MAX - r)) {
				return false;
			}
			r += d;
		}
	}
	(*sll) = r;
	return true;
}
bool strtollu(char *str, size_t len, unsigned long long int *llu) {
	if (len == 0) {
		return false;
	}
	static unsigned char nmdigits = 0;
	if (nmdigits == 0) {
		for (unsigned long long int m = ULLONG_MAX; m; m /= 10) {
			nmdigits += 1;
		}
	}
	unsigned long long int r = 0;
	char d, ndigits = 0;
	bool f = false;
	for (size_t idx = 0; idx < len; ++idx) {
		d = str[idx];
		if (!f && d == '0') {
			continue;
		}
		f = true;
		ndigits += 1;
		if (ndigits > nmdigits) {
			return false;
		}
		if (d < '0' || d > '9') {
			return false;
		}
		d -= '0';
		r *= 10;
		if (d > (ULLONG_MAX - r)) {
			return false;
		}
		r += d;
	}
	*llu = r;
	return true;
}
