#include <stdio.h>

#include <cryptopals/set1.h>

void repeating_key_xor(const unsigned char *in, size_t in_len,
		const unsigned char *key, size_t key_len, unsigned char *out)
{
	unsigned int i;

	for (i = 0; i < in_len; i++)
		out[i] = in[i] ^ key[i % key_len];
}
