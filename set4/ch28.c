#include <stdio.h>
#include <openssl/sha.h>

#include <cryptopals/set4.h>

static const unsigned char key[] = "foo";

static const unsigned char msg[] = "this is a message";

int main(int argc, char *argv[])
{
	unsigned char hmac[SHA_DIGEST_LENGTH];
	unsigned int i;

	sha1_keyed_mac(msg, sizeof(msg) - 1, key, sizeof(key) - 1, hmac);
	for (i = 0; i < sizeof(hmac); i++)
		printf("%02x", hmac[i]);
	printf("\n");
	return 0;
}
