#include <stdio.h>

#include "single_byte_xor.h"

#include "detect_single_byte_xor_input.c"

int main(int argc, char *argv[])
{
	char buf[INPUTLEN + 1];
	int score, best_score = 0;
	unsigned i, best_i = 0;

	buf[INPUTLEN] = 0;
	for (i = 0; i < sizeof(input) / sizeof(input[0]); i++) {
		crack_single_byte_xor(input[i], INPUTLEN, buf, &score);
		if (score > best_score) {
			best_score = score;
			best_i = i;
		}
	}
	crack_single_byte_xor(input[best_i], INPUTLEN, buf, NULL);
	printf("%d\n", best_i);
	printf("%s\n", buf);
	return 0;
}
