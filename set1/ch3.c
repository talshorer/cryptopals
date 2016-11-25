#include <stdio.h>

#include <cryptopals/set1.h>

static const char crackme[] =
"\x1b\x37\x37\x33\x31\x36\x3f\x78\x15\x1b\x7f\x2b\x78\x34\x31\x33\x3d\x78\x39\x78\x28\x37\x2d\x36\x3c\x78\x37\x3e\x78\x3a\x39\x3b\x37\x36";

int main(int argc, char *argv[])
{
	char buf[sizeof(crackme)];
	char chiper;

	buf[sizeof(buf) - 1] = 0;
	chiper = crack_single_byte_xor(crackme, sizeof(crackme) - 1, buf);
	printf("0x%02x\n", chiper);
	printf("%s\n", buf);
	return 0;
}
