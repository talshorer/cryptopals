#include <stdio.h>

void fixed_xor(const char *a, const char *b, size_t len, char *buf)
{
	while (len--)
		buf[len] = a[len] ^ b[len];
}
