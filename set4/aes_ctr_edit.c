#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/aes.h>

#include <cryptopals/core.h>
#include <cryptopals/set1.h>
#include <cryptopals/set3.h>
#include <cryptopals/set4.h>

void aes_ctr_edit(char *ciphertext, unsigned int bits, const char *key,
		const char *nonce,  bool big_endian, unsigned int offset,
		const char *newtext, size_t len)
{
	char *ctr;
	char *ctr_copy;
	char *keystream;
	char *plain;
	AES_KEY aes_key;
	unsigned int i;
	size_t halfblock = AES_BLOCK_SIZE / 2;
	unsigned int suboffset = offset % AES_BLOCK_SIZE;

	plain = malloc(len + suboffset);
	if (!plain) {
		perror("malloc plain");
		return;
	}
	ctr_copy = malloc(AES_BLOCK_SIZE);
	if (!ctr_copy) {
		perror("malloc ctr_copy");
		goto fail_malloc_ctr_copy;
	}
	aes_ctr_setup(&aes_key, bits, key, nonce, &ctr, &keystream);
	if (!keystream)
		goto fail_aes_ctr_setup;
		offset -= suboffset;
	for (i = 0; i < offset / AES_BLOCK_SIZE; i++)
		bigint_inc(ctr + halfblock, halfblock, big_endian);
	memcpy(ctr_copy, ctr, AES_BLOCK_SIZE);
	aes_ctr_do_crypt(ciphertext + offset, plain, len + suboffset, bits,
			&aes_key, big_endian, ctr, keystream);
	memcpy(plain + suboffset, newtext, len);
	aes_ctr_do_crypt(plain, ciphertext + offset, len + suboffset, bits,
			&aes_key, big_endian, ctr_copy, keystream);

	free(ctr);
	free(keystream);
fail_aes_ctr_setup:
	free(ctr_copy);
fail_malloc_ctr_copy:
	free(plain);
}

#define ATTACK_STEP 14 /* arbitrary */

void attack_random_access_aes_ctr(char *cipher, char *plain, size_t len,
		unsigned int bits, const char *key, const char *nonce,
		bool big_endian)
{
	char newtext[ATTACK_STEP];
	char buf[ATTACK_STEP];
	unsigned int offset;
	size_t step_len;

	memset(newtext, 0, sizeof(newtext));
	for (offset = 0; offset < len; offset += ATTACK_STEP) {
		step_len = min_t(size_t, ATTACK_STEP, len - offset);
		memcpy(buf, cipher + offset, step_len);
		aes_ctr_edit(cipher, bits, key, nonce, big_endian, offset,
				newtext, step_len);
		fixed_xor(buf, cipher + offset, step_len, plain + offset);
	}
}
