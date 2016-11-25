#include <stdio.h>

#include "set1.h"

#include "input8.c"

int main(int argc, char *argv[])
{
	unsigned int i;
	unsigned int matches, maxmatches;

	for (i = 0; i < sizeof(input) / sizeof(input[0]); i++) {
		if (detect_aes_ecb(input[i], INPUTLEN, 128, &matches,
				&maxmatches)) {
			printf("%d total %d max %d\n", i, matches, maxmatches);
		}
	}
	return 0;
}
