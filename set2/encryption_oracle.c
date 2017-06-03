#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <openssl/aes.h>

#include <cryptopals/set1.h>
#include <cryptopals/set2.h>
#include <cryptopals/set3.h>

void fill_random_bytes(unsigned char *buf, unsigned int n)
{
	unsigned int i;

	for (i = 0; i < n; i++)
		buf[i] = random() & 0xff;
}

void *make_random_bytes(unsigned int n)
{
	unsigned char *ret;

	ret = malloc(n);
	if (ret)
		fill_random_bytes(ret, n);
	return ret;
}

int setup_oracle(struct oracle *oracle, size_t append_base,
		const unsigned char *prefix, size_t prefix_len,
		const unsigned char *suffix, size_t suffix_len,
		enum oracle_mode mode, unsigned int bits, bool constant_key,
		bool constant_iv, bool announce_encryption)
{
	int ret = 0;

	oracle->append_base = append_base;
	oracle->prefix = prefix;
	oracle->prefix_len = prefix_len;
	oracle->suffix = suffix;
	oracle->suffix_len = suffix_len;
	oracle->mode = mode;
	oracle->bits = bits;
	if (constant_key) {
		oracle->key = make_random_bytes(AES_BLOCK_SIZE);
		if (!oracle->key)
			ret = 1;
	} else {
		oracle->key = NULL;
	}
	if (constant_iv) {
		/* we use oracle->iv as the nonce in ctr mode */
		oracle->iv = make_random_bytes(mode == ORACLE_MODE_CTR ?
				AES_BLOCK_SIZE / 2 : AES_BLOCK_SIZE);
		if (!oracle->iv)
			ret = 1;
	} else {
		/* ctr requires a constant nonce */
		if (mode == ORACLE_MODE_CTR)
			ret = 1;
		oracle->iv = NULL;
	}
	oracle->announce_encryption = announce_encryption;
	if (ret) {
		if (oracle->key)
			free(oracle->key);
		if (oracle->iv)
			free(oracle->iv);
	}
	return ret;
}

void cleanup_oracle(struct oracle *oracle)
{
	if (oracle->key)
		free(oracle->key);
	if (oracle->iv)
		free(oracle->iv);
}

unsigned char *encryption_oracle(const unsigned char *in, size_t inlen,
		const struct oracle *oracle, size_t *outlen)
{
	size_t append_start = oracle->append_base +
			random() % (oracle->append_base + 1);
	size_t append_end = oracle->append_base +
			random() % (oracle->append_base + 1);
	unsigned char *out;
	unsigned char *padded_in;
	unsigned char *p;
	unsigned char *key = NULL;
	bool failed = true;

	*outlen = inlen + append_start + append_end +
			oracle->prefix_len + oracle->suffix_len;
	*outlen = pkcs7_get_padded_size(*outlen, AES_BLOCK_SIZE);
	out = malloc(*outlen);
	if (!out)
		goto fail_malloc_out;
	padded_in = malloc(*outlen);
	if (!padded_in)
		goto fail_malloc_padded_in;
	p = padded_in;
	fill_random_bytes(p, append_start);
	p += append_start;
	memcpy(p, oracle->prefix, oracle->prefix_len);
	p += oracle->prefix_len;
	memcpy(p, in, inlen);
	p += inlen;
	fill_random_bytes(p, append_end);
	p += append_end;
	memcpy(p, oracle->suffix, oracle->suffix_len);
	p += oracle->suffix_len;
	pkcs7_pad(padded_in, p - padded_in, *outlen);
	if (oracle->key) {
		key = oracle->key;
	} else {
		key = make_random_bytes(AES_BLOCK_SIZE);
		if (!key)
			goto fail_malloc_key;
	}
	if (oracle->mode == ORACLE_MODE_CTR) {
		aes_ctr_crypt(padded_in, out, *outlen, oracle->bits, key,
				oracle->iv, false);
	} else if (oracle->mode == ORACLE_MODE_CBC ||
			(oracle->mode == ORACLE_MODE_RAND && (random() & 1))) {
		unsigned char *iv;

		if (oracle->iv) {
			iv = oracle->iv;
		} else {
			iv = make_random_bytes(AES_BLOCK_SIZE);
			if (!iv)
				goto fail_malloc_iv;
		}
		if (oracle->announce_encryption)
			printf("oracle: encrypting with CBC\n");
		aes_cbc_encrypt(padded_in, out, *outlen, oracle->bits, key, iv);
		if (!oracle->iv)
			free(iv);
	} else {
		if (oracle->announce_encryption)
			printf("oracle: encrypting with ECB\n");
		aes_ecb_encrypt(padded_in, out, *outlen, oracle->bits, key);
	}
	failed = false;
fail_malloc_iv:
	if (key && !oracle->key)
		free(key);
fail_malloc_key:
	free(padded_in);
fail_malloc_padded_in:
	if (failed) {
		free(out);
		out = NULL;
	}
fail_malloc_out:
	return out;
}
