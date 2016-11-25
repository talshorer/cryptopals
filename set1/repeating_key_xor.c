#include <stdio.h>

#include "set1.h"

void repeating_key_xor(const char *in, size_t in_len, const char *key,
		size_t key_len, char *out)
{
	unsigned i;

	for (i = 0; i < in_len; i++)
		out[i] = in[i] ^ key[i % key_len];
}
