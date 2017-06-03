#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/aes.h>

#include <cryptopals/set1.h>
#include <cryptopals/set2.h>

#define BITS (AES_BLOCK_SIZE * 8) /* so that we can use the key as an IV */

static unsigned char ch27_oracle_key[BITS / 8];

static void print_key(const char *func, const unsigned char *buf)
{
	unsigned int i;

	printf("%16s: key: ", func);
	for (i = 0; i < sizeof(ch27_oracle_key); i++)
		printf("%02x", buf[i]);
	printf("\n");
}

static void ch27_oracle_init(void)
{
	fill_random_bytes(ch27_oracle_key, sizeof(ch27_oracle_key));
	print_key(__func__, ch27_oracle_key);
}

#define ch27_oracle_encrypt(plain, cipher, len) aes_cbc_encrypt(plain, cipher, \
		len, BITS, ch27_oracle_key, ch27_oracle_key)

static bool ch27_oracle_decrypt(const unsigned char *cipher,
		unsigned char *plain, size_t len)
{
	aes_cbc_decrypt(cipher, plain, len, BITS, ch27_oracle_key,
			ch27_oracle_key);
	while (len--)
		if (plain[len] < 0x20 || plain[len] > 0x7f)
			return false;
	/* we accepted the cookie so the caller can't have it */
	memset(plain, 0, len);
	return true;
}

#define MSG_LEN (AES_BLOCK_SIZE * 3)

int main(int argc, char *argv[])
{
	unsigned char *cipher;
	unsigned char *plain;
	int ret = 1;

	ch27_oracle_init();

	plain = malloc(MSG_LEN);
	if (!plain) {
		perror("malloc plain");
		goto fail_malloc_plain;
	}
	memset(plain, 'A', MSG_LEN); /* arbitrary data */
	cipher = malloc(MSG_LEN);
	if (!cipher) {
		perror("malloc cipher");
		goto fail_malloc_cipher;
	}
	ch27_oracle_encrypt(plain, cipher, MSG_LEN);
	/* copy first block to third block */
	memcpy(cipher + AES_BLOCK_SIZE * 2, cipher, AES_BLOCK_SIZE);
	/* zero second block */
	memset(cipher + AES_BLOCK_SIZE, 0, AES_BLOCK_SIZE);
	printf("%16s: ch27_oracle_decrypt() returnd %d\n", __func__,
			ch27_oracle_decrypt(cipher, plain, MSG_LEN));
	/* we'll use cipher as the buffer for the key to not allocate again */
	/*
	 * XOR first and third block. since the second block of ciphertext was
	 * zeroed, this will give us the IV, which is also the key in this case
	 */
	fixed_xor(plain, plain + AES_BLOCK_SIZE * 2, AES_BLOCK_SIZE, cipher);
	print_key(__func__, cipher);
	ret = 0;

	free(cipher);
fail_malloc_cipher:
	free(plain);
fail_malloc_plain:
	return ret;
}
