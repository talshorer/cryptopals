#include <stdio.h>

void repeating_key_xor(const char *in, size_t in_len, const char *key,
		size_t key_len, char *out)
{
	unsigned i;

	for (i = 0; i < in_len; i++)
		out[i] = in[i] ^ key[i % key_len];
}

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
