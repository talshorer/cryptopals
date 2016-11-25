#include <stdio.h>
#include <string.h>

#include <cryptopals/set2.h>

void pkcs7_pad(char *buf, size_t inlen, size_t outlen)
{
	outlen -= inlen;
	memset(&buf[inlen], outlen, outlen);
}
