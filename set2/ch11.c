#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <cryptopals/set1.h>
#include <cryptopals/set2.h>

#define ITERATIONS 16

int main(int argc, char *argv[])
{
	char in[16 * 3];
	struct oracle oracle;
	size_t outlen;
	char *out;
	unsigned int i;

	memset(in, 0, sizeof(in));
	setup_oracle(&oracle, 5, NULL, 0, NULL, 0, ORACLE_MODE_RAND, 128, false,
			false, true);
	for (i = 0; i < ITERATIONS; i++) {
		out = encryption_oracle(in, sizeof(in), &oracle, &outlen);
		if (!out) {
			perror("encryption_oracle");
			break;
		}
		printf("main: detected %s\n",
				detect_aes_ecb(out, outlen, 128, NULL, NULL) ?
						"ECB" : "CBC");
		free(out);
	}
	cleanup_oracle(&oracle);

	return 0;
}
