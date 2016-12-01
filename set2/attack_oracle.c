#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

char *oracle_get_suffix_no_prefix(struct oracle *oracle, size_t *outlen)
{
	size_t bytes, suffix_len;

	bytes = discover_block_size(oracle, &suffix_len);
	printf("block size: %zd bits\n", 8 * bytes);
	printf("suffix length: %zd bytes\n", suffix_len);
	return NULL;
}
