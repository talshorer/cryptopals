#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/aes.h>

#include <cryptopals/core.h>
#include <cryptopals/set1.h>
#include <cryptopals/set3.h>

static void bigint_inc(char *x, size_t len, bool big_endian)
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

void aes_ctr_crypt(const char *in, char *out, size_t len, unsigned int bits,
		const char *key, const char *nonce, bool big_endian)
{
	char *ctr;
	char *keystream;
	unsigned int i;
	AES_KEY aes_key;
	unsigned int bytes = bits / 8;
	size_t halfblock = bytes / 2;

	ctr = malloc(bytes);
	if (!ctr) {
		perror("malloc ctr");
		goto fail_malloc_ctr;
	}
	keystream = malloc(bytes);
	if (!keystream) {
		perror("malloc keystream");
		goto fail_malloc_keystream;
	}
	memcpy(ctr, nonce, halfblock);
	memset(ctr + halfblock, 0, halfblock);
	AES_set_encrypt_key((const void *)key, bits, &aes_key);
	for (i = 0; i < len; i += bytes) {
		AES_encrypt((void *)ctr, (void *)keystream, &aes_key);
		fixed_xor(&in[i], keystream, min_t(size_t, len - i, bytes),
				&out[i]);
		bigint_inc(ctr + halfblock, halfblock, big_endian);
	}

	free(keystream);
fail_malloc_keystream:
	free(ctr);
fail_malloc_ctr:
	;
}
