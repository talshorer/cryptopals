#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <cryptopals/core.h>
#include <cryptopals/set1.h>
#include <cryptopals/set2.h>
#include <cryptopals/set3.h>

#include "input20.c"

#define BITS 128

int main(int argc, char *argv[])
{
	int ret = 1;
	unsigned char *ciphers[ARRAY_SIZE(input)];
	unsigned char plain[0x100]; /* should be big enough */
	size_t size, base64_size;
	size_t min_size = (size_t)-1;
	unsigned int i, j;
	unsigned char *ctr_key;
	unsigned char *keystream;
	unsigned char *nonce;
	unsigned char *breaker_in;
	unsigned char *breaker_out;

	ctr_key = make_random_bytes(BITS / 8);
	if (!ctr_key) {
		perror("malloc ctr_key");
		goto fail_malloc_ctr_key;
	}
	nonce = make_random_bytes(AES_BLOCK_SIZE / 2);
	if (!nonce) {
		perror("malloc nonce");
		goto fail_malloc_nonce;
	}
	for (i = 0; i < ARRAY_SIZE(ciphers); i++) {
		base64_size = strlen(input[i]);
		size = base64_size_to_plain_size(input[i], base64_size);
		if (size > sizeof(plain)) {
			dprintf(2, "sizeof(plain) should be at least %zd\n",
					size);
			goto fail_malloc_cipher;
		}
		if (size < min_size)
			min_size = size;
		ciphers[i] = malloc(size);
		if (!ciphers[i]) {
			perror("malloc chiper");
			goto fail_malloc_cipher;
		}
		decode_base64(input[i], base64_size, plain);
		aes_ctr_crypt(plain, ciphers[i], size, BITS, ctr_key, nonce,
				false);
	}
	breaker_in = malloc(ARRAY_SIZE(ciphers) * 2);
	if (!breaker_in) {
		perror("malloc breaker_in");
		goto fail_malloc_breaker_in;
	}
	breaker_out = malloc(ARRAY_SIZE(ciphers) * 2);
	if (!breaker_out) {
		perror("malloc breaker_out");
		goto fail_malloc_breaker_out;
	}
	keystream = malloc(min_size);
	if (!keystream) {
		perror("malloc keystream");
		goto fail_malloc_keystream;
	}
	for (i = 0; i < min_size; i++) {
		for (j = 0; j < ARRAY_SIZE(ciphers); j++)
			breaker_in[j] = ciphers[j][i];
		keystream[i] = crack_single_byte_xor(breaker_in,
				ARRAY_SIZE(ciphers), breaker_out);
	}
	for (i = 0; i < ARRAY_SIZE(ciphers); i++) {
		repeating_key_xor(ciphers[i], min_size, keystream, min_size,
				plain);
		base64_size = strlen(input[i]);
		size = base64_size_to_plain_size(input[i], base64_size);
		plain[min_size] = 0;
		printf("partial message #%02d (%03zd/%03zd): %s\n",
				i, min_size, size, plain);
	}

	ret = 0;
	free(keystream);
fail_malloc_keystream:
	free(breaker_out);
fail_malloc_breaker_out:
	free(breaker_in);
fail_malloc_breaker_in:
	i = ARRAY_SIZE(ciphers);
fail_malloc_cipher:
	while (i--)
		free(ciphers[i]);
	free(nonce);
fail_malloc_nonce:
	free(ctr_key);
fail_malloc_ctr_key:
	return ret;
}
