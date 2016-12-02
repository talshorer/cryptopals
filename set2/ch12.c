#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <cryptopals/set1.h>
#include <cryptopals/set2.h>

static const char suffix_base64[] =
	"Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg"
	"aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq"
	"dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg"
	"YnkK";

int main(int argc, char *argv[])
{
	struct oracle oracle;
	char *suffix;
	char *out;
	size_t len, outlen;
	int ret;
	unsigned int i;

	len = base64_size_to_plain_size(suffix_base64,
			sizeof(suffix_base64) - 1);
	suffix = malloc(len);
	if (!suffix) {
		perror("malloc suffix");
		ret = 1;
		goto fail_malloc_suffix;
	}
	decode_base64(suffix_base64, sizeof(suffix_base64) - 1, suffix);
	if (setup_oracle(&oracle, 0, NULL, 0, suffix, len, ORACLE_MODE_ECB, 128,
			true, false))
		goto fail_setup_oracle;
	out = oracle_get_suffix_no_prefix(&oracle, &outlen);
	printf("============= decrypted message: =============\n");
	for (i = 0; i < outlen; i++)
		putchar(out[i]);
	ret = 0;
	free(out);
	cleanup_oracle(&oracle);
fail_setup_oracle:
	free(suffix);
fail_malloc_suffix:
	return ret;
}
