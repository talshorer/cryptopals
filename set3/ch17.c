#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/aes.h>

#include <cryptopals/core.h>
#include <cryptopals/set1.h>
#include <cryptopals/set2.h>

#include "input17.c"

#define BITS 128

#define ITERATIONS 32

struct cookie {
	unsigned char *plaintext;
	unsigned char *iv;
	unsigned char *ciphertext;
	size_t size;
};

static unsigned char key[BITS / 8];

static void put_cookie(struct cookie *cookie)
{
	if (cookie->plaintext)
		free(cookie->plaintext);
	if (cookie->iv)
		free(cookie->iv);
	if (cookie->ciphertext)
		free(cookie->ciphertext);
}

static int init_cookie(struct cookie *cookie)
{
	const char *inputbuf;
	size_t base64_size;
	size_t plain_size;

	memset(cookie, 0, sizeof(*cookie));
	inputbuf = input[random() % ARRAY_SIZE(input)];
	base64_size = strlen(inputbuf);
	plain_size = base64_size_to_plain_size(inputbuf, base64_size);
	cookie->size = pkcs7_get_padded_size(plain_size, AES_BLOCK_SIZE);
	cookie->plaintext = malloc(cookie->size);
	if (!cookie->plaintext) {
		perror("malloc plain");
		goto fail;
	}
	cookie->iv = make_random_bytes(AES_BLOCK_SIZE);
	if (!cookie->iv) {
		perror("make_random_bytes cookie->iv");
		goto fail;
	}
	cookie->ciphertext = malloc(cookie->size);
	if (!cookie->ciphertext) {
		perror("malloc cookie->ciphertext");
		goto fail;
	}
	decode_base64(inputbuf, base64_size, cookie->plaintext);
	cookie->plaintext[plain_size] = 0;
	printf("%s:\t%s\n", __func__, cookie->plaintext);
	pkcs7_pad(cookie->plaintext, plain_size, cookie->size);
	aes_cbc_encrypt(cookie->plaintext, cookie->ciphertext, cookie->size,
			BITS, key, cookie->iv);
	return 0;
fail:
	put_cookie(cookie);
	return 1;
}

static bool verify_cookie(struct cookie *cookie)
{
	bool ret;

	aes_cbc_decrypt(cookie->ciphertext, cookie->plaintext, cookie->size,
			BITS, key, cookie->iv);
	ret = pkcs7_validate_padding(cookie->plaintext, cookie->size);
	return ret;
}

static void decipher_last_block(struct cookie *cookie, unsigned char *out)
{
	unsigned char *prev_block;
	unsigned char prev_block_copy[AES_BLOCK_SIZE];
	unsigned int i, padding;

	prev_block = cookie->size == AES_BLOCK_SIZE ? cookie->iv :
			cookie->ciphertext + cookie->size - AES_BLOCK_SIZE * 2;
	memcpy(prev_block_copy, prev_block, AES_BLOCK_SIZE);
	/* do we have valid padding to begin with? */
	if (verify_cookie(cookie)) {
		/* find how much padding we have */
		for (i = 0; i < AES_BLOCK_SIZE; i++) {
			prev_block[i] ^= 0xff;
			if (!verify_cookie(cookie))
				break;
		}
		padding = AES_BLOCK_SIZE - i;
		for (; i < AES_BLOCK_SIZE; i++)
			out[i] = padding;
		/* restore the block */
		memcpy(prev_block, prev_block_copy, AES_BLOCK_SIZE);
	} else {
		padding = 0;
	}
	for (; padding < AES_BLOCK_SIZE; padding++) {
		/* set the plaintext to the wanted padding */
		for (i = 0; i < padding; i++)
			prev_block[AES_BLOCK_SIZE - 1 - i] ^=
					padding ^ (padding + 1);
		/* find the next byte */
		for (i = 0; i < 0x100; i++) {
			prev_block[AES_BLOCK_SIZE - 1 - padding] = i ^
					prev_block_copy[AES_BLOCK_SIZE - 1 -
							padding];
			if (verify_cookie(cookie))
				break;
		}
		out[AES_BLOCK_SIZE - 1 - padding] = i ^ (padding + 1);
	}
	memcpy(prev_block, prev_block_copy, AES_BLOCK_SIZE);
}

int main(int argc, char *argv[])
{
	struct cookie cookie;
	unsigned int i;
	size_t size;
	unsigned char *plain;

	fill_random_bytes(key, sizeof(key));
	for (i = 0; i < ITERATIONS; i++) {
		if (i)
			printf("\n");
		if (init_cookie(&cookie)) {
			perror("init cookie");
			return 1;
		}
		size = cookie.size;
		plain = malloc(cookie.size);
		if (!plain) {
			perror("malloc plain");
		} else {
			for (; cookie.size; cookie.size -= AES_BLOCK_SIZE)
				decipher_last_block(&cookie,
						plain + cookie.size -
								AES_BLOCK_SIZE);
			plain[size - plain[size - 1]] = 0;
			printf("%s:\t\t%s\n", __func__, plain);
			free(plain);
		}
		put_cookie(&cookie);
	}
	return 0;
}
