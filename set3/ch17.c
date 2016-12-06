#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <cryptopals/core.h>
#include <cryptopals/set1.h>
#include <cryptopals/set2.h>

#include "input17.c"

#define BITS 128
#define BYTES (BITS / 8)

#define ITERATIONS 32

struct cookie {
	char *iv;
	char *ciphertext;
	size_t size;
};

static char key[BYTES];

static void init_cookie(struct cookie *cookie)
{
	memset(cookie, 0, sizeof(*cookie));
}

static int fill_cookie(struct cookie *cookie)
{
	const char *inputbuf;
	size_t base64_size;
	char *plain;
	size_t plain_size;
	int ret = -1;

	inputbuf = input[random() % ARRAY_SIZE(input)];
	base64_size = strlen(inputbuf);
	plain_size = base64_size_to_plain_size(inputbuf, base64_size);
	cookie->size = pkcs7_get_padded_size(plain_size, BYTES);
	plain = malloc(cookie->size);
	if (!plain) {
		perror("malloc plain");
		goto fail_malloc_plain;
	}
	cookie->iv = make_random_bytes(BYTES);
	if (!cookie->iv) {
		perror("make_random_bytes cookie->iv");
		goto fail_make_iv;
	}
	cookie->ciphertext = malloc(cookie->size);
	if (!cookie->ciphertext) {
		perror("malloc cookie->ciphertext");
		goto fail_malloc_ciphertext;
	}
	decode_base64(inputbuf, base64_size, plain);
	plain[plain_size] = 0;
	printf("%s:\t%s\n", __func__, plain);
	pkcs7_pad(plain, plain_size, cookie->size);
	aes_cbc_encrypt(plain, cookie->ciphertext, cookie->size,
			BITS, key, cookie->iv);
	ret = 0;
fail_malloc_ciphertext:
	if (ret)
		free(cookie->iv);
fail_make_iv:
	free(plain);
fail_malloc_plain:
	return ret;
}

static void put_cookie(struct cookie *cookie)
{
	if (cookie->iv)
		free(cookie->iv);
	if (cookie->ciphertext)
		free(cookie->ciphertext);
	init_cookie(cookie);
}

static bool verify_cookie(struct cookie *cookie)
{
	char *plain;
	bool ret;

	plain = malloc(cookie->size);
	if (!plain) {
		perror("malloc plain");
		return false;
	}
	aes_cbc_decrypt(cookie->ciphertext, plain, cookie->size,
			BITS, key, cookie->iv);
	ret = pkcs7_validate_padding(plain, cookie->size);
	free(plain);
	return ret;
}

static void decipher_last_block(struct cookie *cookie, char *out)
{
	char *prev_block;
	char *prev_block_copy;
	unsigned int i, padding;

	prev_block = cookie->size == BYTES ? cookie->iv :
			cookie->ciphertext + cookie->size - BYTES * 2;
	prev_block_copy = malloc(BYTES);
	if (!prev_block_copy) {
		perror("malloc prev_block_copy");
		return;
	}
	memcpy(prev_block_copy, prev_block, BYTES);
	/* do we have valid padding to begin with? */
	if (verify_cookie(cookie)) {
		/* find how much padding we have */
		for (i = 0; i < BYTES; i++) {
			prev_block[i] ^= 0xff;
			if (!verify_cookie(cookie))
				break;
		}
		padding = BYTES - i;
		for (; i < BYTES; i++)
			out[i] = padding;
		/* restore the block */
		memcpy(prev_block, prev_block_copy, BYTES);
	} else {
		padding = 0;
	}
	for (; padding < BYTES; padding++) {
		/* set the plaintext to the wanted padding */
		for (i = 0; i < padding; i++)
			prev_block[BYTES - 1 - i] ^= padding ^ (padding + 1);
		/* find the next byte */
		for (i = 0; i < 0x100; i++) {
			prev_block[BYTES - 1 - padding] = i ^
					prev_block_copy[BYTES - 1 - padding];
			if (verify_cookie(cookie))
				break;
		}
		out[BYTES - 1 - padding] = i ^ (padding + 1);
	}
	memcpy(prev_block, prev_block_copy, BYTES);
	free(prev_block_copy);
}

int main(int argc, char *argv[])
{
	struct cookie cookie;
	unsigned int i;
	size_t size;
	char *plain;

	fill_random_bytes(key, sizeof(key));
	init_cookie(&cookie);
	for (i = 0; i < ITERATIONS; i++) {
		if (i)
			printf("\n");
		fill_cookie(&cookie);
		size = cookie.size;
		plain = malloc(cookie.size);
		if (!plain) {
			perror("malloc plain");
		} else {
			for (; cookie.size; cookie.size -= BYTES)
				decipher_last_block(&cookie,
						plain + cookie.size - BYTES);
			plain[size - plain[size - 1]] = 0;
			printf("%s:\t\t%s\n", __func__, plain);
			free(plain);
		}
		put_cookie(&cookie);
	}
	return 0;
}
