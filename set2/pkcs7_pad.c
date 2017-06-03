#include <stdio.h>
#include <string.h>

#include <cryptopals/set2.h>

void pkcs7_pad(unsigned char *buf, size_t inlen, size_t outlen)
{
	outlen -= inlen;
	memset(&buf[inlen], outlen, outlen);
}

size_t pkcs7_get_padded_size(size_t inlen, unsigned int bytes)
{
	return  inlen + bytes - inlen % bytes;
}

bool pkcs7_validate_padding(unsigned char *buf, size_t len)
{
	unsigned int i;
	unsigned int x = buf[len - 1];

	if (!x || x > len)
		return false;
	for (i = x; i > 1; i--)
		if (buf[len - i] != x)
			return false;
	return true;
}
