#include <stdio.h>

#include <cryptopals/set3.h>

static unsigned int faketime(void)
{
	static unsigned int time = 0xdeadbeef;

	time += 0x10;
	return time;
}

static mt19937_int_t mt19937_first(mt19937_int_t seed)
{
	struct mt19937 mt;

	mt19937_seed(&mt, seed);
	return mt19937_next(&mt);
}

static mt19937_int_t get_target(void)
{
	unsigned int finish;
	mt19937_int_t ret;

	finish = faketime() + (rand() % (1000 - 40)) + 40;
	while (faketime() < finish)
		;
	finish = faketime();
	printf("%10s: seed is %u\n", __func__, finish);
	ret = mt19937_first(finish);
	finish = faketime() + (rand() % (1000 - 40)) + 40;
	while (faketime() < finish)
		;
	return ret;
}

int main(int argc, char *argv[])
{
	mt19937_int_t target;
	unsigned int seed;

	target = get_target();
	for (seed = faketime(); seed; seed--)
		if (mt19937_first(seed) == target)
			break;
	printf("%10s: seed is %u\n", __func__, seed);
	return 0;
}
