#include <stdio.h>

#include <cryptopals/set3.h>

#define SEED 7
#define OFFSET 3821 /* arbitrary, not divisible by MT19937_N */
#define TEST 2048 /* arbitrary */

int main(int argc, char *argv[])
{
	struct mt19937 source, clone;
	unsigned int i;
	int ret = 0;

	mt19937_seed(&source, SEED);
	for (i = 0; i < OFFSET; i++)
		mt19937_next(&source);
	mt19937_clone(&source, &clone);
	for (i = 0; i < TEST; i++)
		if (mt19937_next(&source) != mt19937_next(&clone)) {
			printf("mismatch at index %d\n", i);
			ret = 1;
		}
	if (!ret)
		printf("no mismatches\n");
	return ret;
}
