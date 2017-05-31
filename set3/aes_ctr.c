#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <cryptopals/core.h>
#include <cryptopals/set1.h>
#include <cryptopals/set3.h>

void bigint_inc(char *x, size_t len, bool big_endian)
{
	int direction = big_endian ? -1 : 1;
	char *p = big_endian ? x + len - 1 : x;
	unsigned int i;

	for (i = 0; i < len; i++) {
		p[i * direction]++;
		if (p[i * direction])
			break;
	}
}

void aes_ctr_setup(AES_KEY *aes_key, unsigned int bits, const char *key,
		const char *nonce, char **ctr, char **keystream)
{
	unsigned int bytes = bits / 8;
	size_t halfblock = bytes / 2;

	*ctr = malloc(bytes);
	if (!*ctr) {
		perror("malloc ctr");
		return;
	}
	*keystream = malloc(bytes);
	if (!*keystream) {
		free(*ctr);
		perror("malloc keystream");
		return;
	}
	memcpy(*ctr, nonce, halfblock);
	memset(*ctr + halfblock, 0, halfblock);
	AES_set_encrypt_key((const void *)key, bits, aes_key);
}

void aes_ctr_do_crypt(const char *in, char *out, size_t len, unsigned int bits,
		AES_KEY *aes_key, bool big_endian, char *ctr, char *keystream)
{
	unsigned int i;
	unsigned int bytes = bits / 8;
	size_t halfblock = bytes / 2;

	for (i = 0; i < len; i += bytes) {
		AES_encrypt((void *)ctr, (void *)keystream, aes_key);
		fixed_xor(&in[i], keystream, min_t(size_t, len - i, bytes),
				&out[i]);
		bigint_inc(ctr + halfblock, halfblock, big_endian);
	}
}

void aes_ctr_crypt(const char *in, char *out, size_t len, unsigned int bits,
		const char *key, const char *nonce, bool big_endian)
{
	char *ctr;
	char *keystream;
	AES_KEY aes_key;

	aes_ctr_setup(&aes_key, bits, key, nonce, &ctr, &keystream);
	if (!keystream)
		return;
	aes_ctr_do_crypt(in, out, len, bits, &aes_key, big_endian, ctr,
			keystream);
	free(keystream);
	free(ctr);
}
