#ifndef bidriectiond__hashmap__h
#define bidriectiond__hashmap__h

#include <stdbool.h>
#include <stdint.h>

static bool chcd(char ch, uint8_t *cd) {
	if (ch >= '0' && ch <= '9') {
		*cd = ch - '0';
	} else if (ch >= 'a' && ch <= 'z') {
		*cd = ch - 'a' + 10;
	} else if (ch == '-') {
		*cd = 10 + 26;
	} else {
		return false;
	}
	return true;
}
static uint32_t HASHMAP_HASH_FUNCTION(char *input, uint32_t sz) {
	uint8_t bytes[4] = { 0, 0, 0, 0, };
	uint8_t prev[4] = { 0, 0, 0, 0, };
	uint8_t bytes_idx = 0, cd;
	for (uint32_t idx = 0; idx < sz; ++idx) {
		if (!chcd(input[idx], &(cd))) {
			*(uint32_t *)bytes *= 37;
			bytes_idx = 0;
			continue;
		}
		bytes[bytes_idx] += ((idx + cd) * (prev[bytes_idx] + 1));
		prev[bytes_idx] = cd;
		bytes_idx = (bytes_idx + 1) & 0b11;
	}
	return *(uint32_t *)bytes;
}
#include <hashmap.h>

#endif