#include <stdio.h>

void fixed_xor(const char *a, const char *b, size_t len, char *buf)
{
	while (len--)
		buf[len] = a[len] ^ b[len];
}

static const char a[] =
"\x1c\x01\x11\x00\x1f\x01\x01\x00\x06\x1a\x02\x4b\x53\x53\x50\x09\x18\x1c";

static const char b[] =
"\x68\x69\x74\x20\x74\x68\x65\x20\x62\x75\x6c\x6c\x27\x73\x20\x65\x79\x65";

#define size (sizeof(a) - 1)

int main(int argc, char *argv[])
{
	char buf[size];
	unsigned i;

	fixed_xor(a, b, size, buf);
	for (i = 0; i < size; i++)
		printf("%02x", buf[i]);
	puts("");
	return 0;
}
