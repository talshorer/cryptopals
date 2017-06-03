#include <stdio.h>

#include <cryptopals/set1.h>

void fixed_xor(const unsigned char *a, const unsigned char *b, size_t len,
		unsigned char *buf)
{
	while (len--)
		buf[len] = a[len] ^ b[len];
}
