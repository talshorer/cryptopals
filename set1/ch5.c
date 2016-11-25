#include <stdio.h>

#include <cryptopals/set1.h>

static const char cryptme[] =
"Burning 'em, if you ain't quick and nimble\n"
"I go crazy when I hear a cymbal";

static const char withkey[] = "ICE";

int main(int argc, char *argv[])
{
	char buf[sizeof(cryptme) - 1];
	unsigned i;

	repeating_key_xor(cryptme, sizeof(buf),
			withkey, sizeof(withkey) - 1, buf);
	for (i = 0; i < sizeof(buf); i++)
		printf("%02x", buf[i]);
	puts("");
	return 0;
}
