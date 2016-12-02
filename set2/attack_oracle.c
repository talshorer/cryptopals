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
				*suffix_len = outlen - ret - i + 1;
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

char *oracle_get_suffix_no_prefix(struct oracle *oracle, size_t *suffix_len)
{
	size_t bytes;
	char *stimulus;
	char *buf;
	char *table[0x100];
	unsigned int i, j;
	char *suffix = NULL;
	size_t stimulus_len;
	size_t from_attacker;
	unsigned int offset;
	char *out;
	size_t outlen;

	bytes = discover_block_size(oracle, suffix_len);
	if (!bytes) {
		printf("failed to discover  block size\n");
		goto fail_early;
	}
	printf("block size: %zd bits\n", 8 * bytes);
	printf("suffix length: %zd bytes\n", *suffix_len);
	if (!assert_ecb(oracle, bytes)) {
		printf("can't attack CBC oracle\n");
		goto fail_early;
	}
	printf("asserted an ecb oracle\n");
	stimulus_len = get_padded_size(*suffix_len, bytes);
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
		stimulus_len = get_padded_size(i + 1, bytes);
		from_attacker = bytes - 1 - i % bytes;
		offset = i - i % bytes; /* round for blocks */
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
