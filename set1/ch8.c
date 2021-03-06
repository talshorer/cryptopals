#include <stdio.h>

#include <cryptopals/core.h>
#include <cryptopals/set1.h>

#include "input8.c"

int main(int argc, char *argv[])
{
	unsigned int i;
	unsigned int matches, maxmatches;

	for (i = 0; i < ARRAY_SIZE(input); i++) {
		if (detect_aes_ecb(input[i], INPUTLEN, 128, &matches,
				&maxmatches)) {
			printf("%d total %d max %d\n", i, matches, maxmatches);
		}
	}
	return 0;
}
