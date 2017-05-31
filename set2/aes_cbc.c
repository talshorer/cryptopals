#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/aes.h>

#include <cryptopals/set1.h>
#include <cryptopals/set2.h>

static void aes_cbc_crypt(const char *in, char *out, size_t len,
		unsigned int bits, const char *key, const char *iv,
		bool encrypt)
{
	char *vect;
	unsigned int i;
	AES_KEY aes_key;

	vect = malloc(AES_BLOCK_SIZE);
	if (!vect) {
		perror("malloc vect");
		return;
	}
	if (iv)
		memcpy(vect, iv, AES_BLOCK_SIZE);
	else
		memset(vect, 0, AES_BLOCK_SIZE);

	if (encrypt)
		AES_set_encrypt_key((const void *)key, bits, &aes_key);
	else
		AES_set_decrypt_key((const void *)key, bits, &aes_key);
	for (i = 0; i < len; i += AES_BLOCK_SIZE) {
		if (encrypt) {
			fixed_xor(&in[i], vect, AES_BLOCK_SIZE, vect);
			AES_encrypt((void *)vect, (void *)&out[i], &aes_key);
			memcpy(vect, &out[i], AES_BLOCK_SIZE);
		} else {
			AES_decrypt((void *)&in[i], (void *)&out[i], &aes_key);
			fixed_xor(&out[i], vect, AES_BLOCK_SIZE, &out[i]);
			memcpy(vect, &in[i], AES_BLOCK_SIZE);
		}
	}

	free(vect);
}

void aes_cbc_encrypt(const char *in, char *out, size_t len,
		unsigned int bits, const char *key, const char *iv)
{
	aes_cbc_crypt(in, out, len, bits, key, iv, true);
}

void aes_cbc_decrypt(const char *in, char *out, size_t len,
		unsigned int bits, const char *key, const char *iv)
{
	aes_cbc_crypt(in, out, len, bits, key, iv, false);
}
