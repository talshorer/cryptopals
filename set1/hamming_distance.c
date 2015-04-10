#include <stdio.h>

unsigned hamming_distance(const char *a, const char *b, size_t len)
{
	unsigned i, ret = 0;
	char tmp;

	while (len--) {
		tmp = a[len] ^ b[len];
		for (i = 0; i < 8; i++)
			if (tmp & (1 << i))
				ret++;
	}
	return ret;
}

static const char a[] = "this is a test";
static const char b[] = "wokka wokka!!!";

int main(int argc, char *argv[])
{
	printf("%u\n", hamming_distance(a, b, sizeof(a) - 1));
	return 0;
}
