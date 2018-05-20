#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <cryptopals/core.h>
#include <cryptopals/set1.h>
#include <cryptopals/set3.h>

void bigint_inc(unsigned char *x, size_t len, bool big_endian)
{
	int direction = big_endian ? -1 : 1;
	unsigned char *p = big_endian ? x + len - 1 : x;
	unsigned int i;

	for (i = 0; i < len; i++) {
		p[i * direction]++;
		if (p[i * direction])
			break;
	}
}

void aes_ctr_setup(AES_KEY *aes_key, unsigned int bits,
		const unsigned char *key, const unsigned char *nonce,
		unsigned char *ctr, unsigned char *keystream)
{
	size_t halfblock = AES_BLOCK_SIZE / 2;

	memcpy(ctr, nonce, halfblock);
	memset(ctr + halfblock, 0, halfblock);
	AES_set_encrypt_key(key, bits, aes_key);
}

void aes_ctr_do_crypt(const unsigned char *in, unsigned char *out, size_t len,
		unsigned int bits, AES_KEY *aes_key, bool big_endian,
		unsigned char *ctr, unsigned char *keystream)
{
	unsigned int i;
	size_t halfblock = AES_BLOCK_SIZE / 2;

	for (i = 0; i < len; i += AES_BLOCK_SIZE) {
		AES_encrypt(ctr, keystream, aes_key);
		fixed_xor(&in[i], keystream, min_t(size_t, len - i,
				AES_BLOCK_SIZE), &out[i]);
		bigint_inc(ctr + halfblock, halfblock, big_endian);
	}
}

void aes_ctr_crypt(const unsigned char *in, unsigned char *out, size_t len,
		unsigned int bits, const unsigned char *key,
		const unsigned char *nonce, bool big_endian)
{
	unsigned char ctr[AES_BLOCK_SIZE];
	unsigned char keystream[AES_BLOCK_SIZE];
	AES_KEY aes_key;

	aes_ctr_setup(&aes_key, bits, key, nonce, ctr, keystream);
	aes_ctr_do_crypt(in, out, len, bits, &aes_key, big_endian, ctr,
			keystream);
}
