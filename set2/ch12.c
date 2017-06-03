#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <cryptopals/set1.h>
#include <cryptopals/set2.h>

#include "input12.c"

int main(int argc, char *argv[])
{
	struct oracle oracle;
	unsigned char *suffix;
	unsigned char *out;
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
	decode_base64(inputbuf, sizeof(inputbuf) - 1, suffix);
	if (setup_oracle(&oracle, 0, NULL, 0, suffix, len, ORACLE_MODE_ECB, 128,
			true, false, false))
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
	free(suffix);
fail_malloc_suffix:
	return ret;
}
