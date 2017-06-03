#include <stdio.h>

#include <cryptopals/set2.h>

#define print_padding_check(s) printf(#s " has %s padding\n", \
		pkcs7_validate_padding(s, sizeof(s) - 1) ? "good" : "bad")

int main(int argc, char *argv[])
{
	unsigned char s1[] = "ICE ICE BABY\x04\x04\x04\x04";
	unsigned char s2[] = "ICE ICE BABY\x05\x05\x05\x05";
	unsigned char s3[] = "ICE ICE BABY\x01\x02\x03\x04";

	print_padding_check(s1);
	print_padding_check(s2);
	print_padding_check(s3);
	return 0;
}
