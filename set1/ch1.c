#include <stdio.h>
#include <string.h>

#include <cryptopals/set1.h>

static const unsigned char encodeme[] = "\x49\x27\x6d\x20\x6b\x69\x6c\x6c\x69"
		"\x6e\x67\x20\x79\x6f\x75\x72\x20\x62\x72\x61\x69\x6e\x20\x6c"
		"\x69\x6b\x65\x20\x61\x20\x70\x6f\x69\x73\x6f\x6e\x6f\x75\x73"
		"\x20\x6d\x75\x73\x68\x72\x6f\x6f\x6d";

int main(int argc, char *argv[])
{
	char out[1024];

	memset(out, 0, sizeof(out));
	encode_base64(encodeme, sizeof(encodeme) - 1, out);
	printf("%s\n", out);
	return 0;
}
