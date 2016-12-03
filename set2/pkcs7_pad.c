#include <stdio.h>
#include <string.h>

#include <cryptopals/set2.h>

void pkcs7_pad(char *buf, size_t inlen, size_t outlen)
{
	outlen -= inlen;
	memset(&buf[inlen], outlen, outlen);
}

size_t get_padded_size(size_t inlen, unsigned int bytes)
{
	return  inlen + bytes - inlen % bytes;
}
