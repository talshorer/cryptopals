#include <stdio.h>

#include <cryptopals/set1.h>

static const unsigned char cryptme[] =
	"Burning 'em, if you ain't quick and nimble\n"
	"I go crazy when I hear a cymbal";

static const unsigned char withkey[] = "ICE";

int main(int argc, char *argv[])
{
	unsigned char buf[sizeof(cryptme) - 1];
	unsigned int i;

	repeating_key_xor(cryptme, sizeof(buf), withkey, sizeof(withkey) - 1,
			buf);
	for (i = 0; i < sizeof(buf); i++)
		printf("%02x", buf[i]);
	puts("");
	return 0;
}
