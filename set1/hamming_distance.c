#include <stdio.h>

#include <cryptopals/set1.h>

unsigned int hamming_distance(const unsigned char *a, const unsigned char *b,
		size_t len)
{
	unsigned int i, ret = 0;
	unsigned char tmp;

	while (len--) {
		tmp = a[len] ^ b[len];
		for (i = 0; i < 8; i++)
			if (tmp & (1 << i))
				ret++;
	}
	return ret;
}
