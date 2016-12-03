#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <cryptopals/set1.h>
#include <cryptopals/set2.h>

#define PREFIX_MIN_LENGTH 54
#define PREFIX_MAX_LENGTH 84

static const char suffix_base64[] =
	"Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg"
	"aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq"
	"dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg"
	"YnkK";

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

	len = base64_size_to_plain_size(suffix_base64,
			sizeof(suffix_base64) - 1);
	suffix = malloc(len);
	if (!suffix) {
		perror("malloc suffix");
		ret = 1;
		goto fail_malloc_suffix;
	}
	prefix_len = PREFIX_MIN_LENGTH +
			random() % (1 + PREFIX_MAX_LENGTH - PREFIX_MIN_LENGTH);
	printf("main: prefix_len = %zd, suffix_len = %zd\n", prefix_len, len);
	prefix = malloc(prefix_len);
	if (!prefix) {
		perror("malloc prefix");
		ret = 1;
		goto fail_malloc_prefix;
	}
	for (i = 0; i < prefix_len; i++)
		prefix[i] = random() & 0xff;
	decode_base64(suffix_base64, sizeof(suffix_base64) - 1, suffix);
	if (setup_oracle(&oracle, 0, prefix, prefix_len, suffix, len,
			ORACLE_MODE_ECB, 128, true, false))
		goto fail_setup_oracle;
	out = oracle_get_suffix_rand_prefix(&oracle, &outlen);
	printf("============= decrypted message: =============\n");
	for (i = 0; i < outlen; i++)
		putchar(out[i]);
	ret = 0;
	free(out);
	cleanup_oracle(&oracle);
fail_setup_oracle:
	free(prefix);
fail_malloc_prefix:
	free(suffix);
fail_malloc_suffix:
	return ret;
}
