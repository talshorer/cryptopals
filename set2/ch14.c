#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <cryptopals/set1.h>
#include <cryptopals/set2.h>

#include "input12.c"

#define PREFIX_MIN_LENGTH 54
#define PREFIX_MAX_LENGTH 84

int main(int argc, char *argv[])
{
	struct oracle oracle;
	char *prefix;
	size_t prefix_len;
	char *suffix;
	char *out;
	size_t len, outlen;
	int ret;
	unsigned int i;

	len = base64_size_to_plain_size(inputbuf,
			sizeof(inputbuf) - 1);
	suffix = malloc(len);
	if (!suffix) {
		perror("malloc suffix");
		ret = 1;
		goto fail_malloc_suffix;
	}
	prefix_len = PREFIX_MIN_LENGTH +
			random() % (1 + PREFIX_MAX_LENGTH - PREFIX_MIN_LENGTH);
	printf("main: prefix_len = %zd, suffix_len = %zd\n", prefix_len, len);
	prefix = make_random_bytes(prefix_len);
	if (!prefix) {
		perror("make_random_bytes prefix");
		ret = 1;
		goto fail_malloc_prefix;
	}
	decode_base64(inputbuf, sizeof(inputbuf) - 1, suffix);
	if (setup_oracle(&oracle, 0, prefix, prefix_len, suffix, len,
			ORACLE_MODE_ECB, 128, true, false, false))
		goto fail_setup_oracle;
	out = oracle_get_suffix(&oracle, &outlen);
	if (!out) {
		ret = 1;
		goto fail_get_suffix;
	}
	printf("============= decrypted message: =============\n");
	for (i = 0; i < outlen; i++)
		putchar(out[i]);
	ret = 0;
	free(out);
fail_get_suffix:
	cleanup_oracle(&oracle);
fail_setup_oracle:
	free(prefix);
fail_malloc_prefix:
	free(suffix);
fail_malloc_suffix:
	return ret;
}
