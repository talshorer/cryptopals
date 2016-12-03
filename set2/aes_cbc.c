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
	unsigned int bytes = bits / 8;

	vect = malloc(bytes);
	if (!vect) {
		perror("malloc vect");
		return;
	}
	if (iv)
		memcpy(vect, iv, bytes);
	else
		memset(vect, 0, bytes);

	if (encrypt)
		AES_set_encrypt_key((void *)key, bits, &aes_key);
	else
		AES_set_decrypt_key((void *)key, bits, &aes_key);
	for (i = 0; i < len; i += bytes) {
		if (encrypt) {
			fixed_xor(&in[i], vect, bytes, vect);
			AES_encrypt((void *)vect, (void *)&out[i], &aes_key);
			memcpy(vect, &out[i], bytes);
		} else {
			AES_decrypt((void *)&in[i], (void *)&out[i], &aes_key);
			fixed_xor(&out[i], vect, bytes, &out[i]);
			memcpy(vect, &in[i], bytes);
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
