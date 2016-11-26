#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/aes.h>

#include <cryptopals/set1.h>

static void aes_ecb_crypt(const char *in, char *out, size_t len,
		unsigned int bits, const char *key, bool encrypt)
{
	unsigned int i;
	AES_KEY aes_key;
	unsigned int bytes = bits / 8;

	if (encrypt) {
		AES_set_encrypt_key((void *)key, bits, &aes_key);
	} else {
		AES_set_decrypt_key((void *)key, bits, &aes_key);
	}
	for (i = 0; i < len; i += bytes) {
		if (encrypt) {
			AES_encrypt((void *)&in[i], (void *)&out[i], &aes_key);
		} else {
			AES_decrypt((void *)&in[i], (void *)&out[i], &aes_key);
		}
	}
}

void aes_ecb_encrypt(const char *in, char *out, size_t len,
		unsigned int bits, const char *key)
{
	aes_ecb_crypt(in, out, len, bits, key, true);
}

void aes_ecb_decrypt(const char *in, char *out, size_t len,
		unsigned int bits, const char *key)
{
	aes_ecb_crypt(in, out, len, bits, key, false);
}
