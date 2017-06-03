#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/aes.h>

#include <cryptopals/set1.h>

static void aes_ecb_crypt(const unsigned char *in, unsigned char *out,
		size_t len, unsigned int bits, const unsigned char *key,
		bool encrypt)
{
	unsigned int i;
	AES_KEY aes_key;

	if (encrypt)
		AES_set_encrypt_key(key, bits, &aes_key);
	else
		AES_set_decrypt_key(key, bits, &aes_key);
	for (i = 0; i < len; i += AES_BLOCK_SIZE) {
		if (encrypt)
			AES_encrypt(&in[i], &out[i], &aes_key);
		else
			AES_decrypt(&in[i], &out[i], &aes_key);
	}
}

void aes_ecb_encrypt(const unsigned char *in, unsigned char *out, size_t len,
		unsigned int bits, const unsigned char *key)
{
	aes_ecb_crypt(in, out, len, bits, key, true);
}

void aes_ecb_decrypt(const unsigned char *in, unsigned char *out, size_t len,
		unsigned int bits, const unsigned char *key)
{
	aes_ecb_crypt(in, out, len, bits, key, false);
}
