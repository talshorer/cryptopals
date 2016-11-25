#include <stdio.h>

#include <cryptopals/set1.h>

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
