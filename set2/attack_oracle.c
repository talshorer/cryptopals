#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <cryptopals/set1.h>
#include <cryptopals/set2.h>

#define INITIAL_SHIFT 8 /* unlikely to attack larger blocks than 256 bytes */

static size_t discover_block_size(struct oracle *oracle, size_t *suffix_len)
{
	char *out;
	size_t outlen;
	size_t last_outlen = 0;
	char *in;
	size_t len;
	size_t ret;
	unsigned int shift = INITIAL_SHIFT;
	unsigned int i = 0;

	while (true) {
		len = 1 << shift;
		in = malloc(len);
		if (!in) {
			perror("malloc in");
			return 0;
		}
		memset(in, 0, len);
		for (; i < len; i++) {
			out = encryption_oracle(in, i, oracle, &outlen);
			if (!out) {
				ret = 0;
				goto out;
			}
			free(out);
			/* padding added an entire block */
			if (last_outlen && last_outlen < outlen) {
				ret = outlen - last_outlen;
				*suffix_len = last_outlen - i;
				goto out;
			}
			last_outlen = outlen;
		}
		free(in);
		shift++;
	}
out:
	free(in);
	return ret;
}

static bool assert_ecb(struct oracle *oracle, size_t bytes)
{
	char *in;
	char *out;
	size_t inlen;
	size_t outlen;
	bool ret;

	inlen = bytes * 3;
	in = malloc(inlen);
	if (!in) {
		perror("malloc in");
		return false;
	}
	memset(in, 0, inlen);
	out = encryption_oracle(in, inlen, oracle, &outlen);
	free(in);
	if (!out)
		return false;
	ret = detect_aes_ecb(out, outlen, bytes * 8, NULL, NULL);
	free(out);
	return ret;
}

static int get_full_prefix_blocks(struct oracle *oracle, size_t bytes)
{
	char *out1;
	char *out2;
	size_t outlen;
	int ret = -1;
	char x;
	unsigned int i;

	x = 0;
	out1 = encryption_oracle(&x, 1, oracle, &outlen);
	if (!out1)
		goto fail1;
	out2 = encryption_oracle(NULL, 0, oracle, &outlen);
	if (!out2)
		goto fail2;
	for (i = 0; i < outlen / bytes; i++) {
		if (memcmp(out1 + i * bytes, out2 + i * bytes, bytes))
			break;
	}
	ret = i;
	free(out2);
fail2:
	free(out1);
fail1:
	return ret;
}

static int get_prefix_size_mod_block_size(struct oracle *oracle, size_t bytes,
		int full_prefix_blocks)
{
	char *in;
	char *out;
	int ret = -1;
	unsigned int i;
	size_t outlen;
	char x, y;

	x = 0x00;
	y = 0xff;
	in = malloc(bytes * 4);
	if (!in) {
		perror("malloc in");
		goto fail_malloc_in;
	}
	memset(in, x, bytes * 2);
	out = encryption_oracle(in, bytes * 2, oracle, &outlen);
	if (!out)
		goto fail_oracle;
	/*
	 * if the last block of the prefix matches our first injected block,
	 * one of two things is true:
	 *	1. the prefix's size a multiple of the block size
	 *	2. the last block of the prefix is all the same arbitrary byte
	 *	   we chose
	 * change the byte and try again. if it matches again, the size is 0
	 */
	if (!memcmp(out + full_prefix_blocks * bytes,
			out + (full_prefix_blocks + 1) * bytes, bytes)) {
		x = 0x01;
		memset(in, x, bytes * 3);
		if (!memcmp(out + full_prefix_blocks * bytes,
				out + (full_prefix_blocks + 1) * bytes,
				bytes)) {
			ret = 0;
			goto out;
		}
	}
	for (i = 1; i < bytes; i++) {
		free(out);
		memset(in, x, bytes * 2 + i);
		memset(in + bytes * 2 + i, y, bytes);
		out = encryption_oracle(in, bytes * 3 + i, oracle, &outlen);
		if (!memcmp(out + (full_prefix_blocks + 1) * bytes,
				out + (full_prefix_blocks + 2) * bytes,
				bytes)) {
			ret = bytes - i;
			break;
		}
	}
out:
	free(out);
fail_oracle:
	free(in);
fail_malloc_in:
	return ret;
}

char *oracle_get_suffix(struct oracle *oracle, size_t *suffix_len)
{
	size_t bytes;
	size_t total_len;
	int full_prefix_blocks;
	int prefix_size_mod_block_size;
	size_t prefix_len;
	char *stimulus;
	char *buf;
	char *table[0x100];
	unsigned int i, j;
	char *suffix = NULL;
	size_t stimulus_len;
	size_t stimulus_prepend_len;
	size_t from_attacker;
	unsigned int offset;
	char *out;
	size_t outlen;

	bytes = discover_block_size(oracle, &total_len);
	if (!bytes) {
		printf("failed to discover block size\n");
		goto fail_early;
	}
	printf("block size: %zd bits\n", 8 * bytes);
	if (!assert_ecb(oracle, bytes)) {
		printf("can't attack CBC oracle\n");
		goto fail_early;
	}
	full_prefix_blocks = get_full_prefix_blocks(oracle, bytes);
	if (full_prefix_blocks < 0)
		goto fail_early;
	prefix_size_mod_block_size = get_prefix_size_mod_block_size(oracle,
				bytes, full_prefix_blocks);
	if (prefix_size_mod_block_size < 0)
		goto fail_early;
	prefix_len = full_prefix_blocks * bytes + prefix_size_mod_block_size;
	*suffix_len = total_len - prefix_len;
	printf("prefix length: %zd\n", prefix_len);
	printf("suffix length: %zd\n", *suffix_len);
	stimulus_prepend_len = pkcs7_get_padded_size(prefix_size_mod_block_size,
			bytes) - prefix_size_mod_block_size;
	stimulus_len = pkcs7_get_padded_size(*suffix_len + stimulus_prepend_len,
			bytes);
	stimulus = malloc(stimulus_len);
	if (!stimulus) {
		perror("malloc stimulus");
		goto fail_malloc_stimulus;
	}
	buf = malloc(bytes * 256);
	if (!buf) {
		perror("malloc buf");
		goto fail_malloc_buf;
	}
	for (i = 0; i < 0x100; i++)
		table[i] = buf + i * bytes;
	suffix = malloc(*suffix_len);
	if (!suffix) {
		goto fail_malloc_suffix;
		perror("malloc suffix");
	}
	for (i = 0; i < *suffix_len; i++) {
		stimulus_len = stimulus_prepend_len +
				pkcs7_get_padded_size(i + 1, bytes);
		from_attacker = stimulus_prepend_len + bytes - 1 - i % bytes;
		/* round for blocks */
		offset = pkcs7_get_padded_size(prefix_len, bytes) +
				i - i % bytes;
		memset(stimulus, 0, from_attacker);
		memcpy(stimulus + from_attacker, suffix, i);
		for (j = 0; j < 0x100; j++) {
			stimulus[from_attacker + i] = j;
			out = encryption_oracle(stimulus, stimulus_len, oracle,
					&outlen);
			memcpy(table[j], out + offset, bytes);
			free(out);
		}
		out = encryption_oracle(stimulus, from_attacker, oracle,
				&outlen);
		for (j = 0; j < 0x100; j++) {
			if (!memcmp(table[j], out + offset, bytes)) {
				suffix[i] = j;
				printf("found byte: [%d] = 0x%02x\n", i, j);
				break;
			}
		}
		free(out);
	}

fail_malloc_suffix:
	free(buf);
fail_malloc_buf:
	free(stimulus);
fail_malloc_stimulus:
fail_early:
	return suffix;
}
