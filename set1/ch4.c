#include <stdio.h>

#include <cryptopals/core.h>
#include <cryptopals/set1.h>

static int all_english(const unsigned char *buf, size_t len)
{
	while (len--)
		if (!char_english_score(buf[len]))
			return 0;
	return 1;
}

#include "input4.c"

int main(int argc, char *argv[])
{
	unsigned char buf[INPUTLEN + 1];
	unsigned int i;

	buf[INPUTLEN] = 0;
	for (i = 0; i < ARRAY_SIZE(input); i++) {
		crack_single_byte_xor(input[i], INPUTLEN, buf);
		if (all_english(buf, INPUTLEN)) {
			if (buf[INPUTLEN - 1] == '\n')
				buf[INPUTLEN - 1] = 0;
			printf("%d %s\n", i, buf);
		}
	}
	return 0;
}
