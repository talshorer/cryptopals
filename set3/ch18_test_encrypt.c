#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <cryptopals/set3.h>

static const char message[] = "Hello, world!\n"
		"What a lovely day!\n"
		"Jibber Jabber this should be multiple blocks\n";

static const char key[] = "YELLOW SUBMARINE";

#define key_size (sizeof(key) - 1)

int main(int argc, char *argv[])
{
	char encrypted[sizeof(message)];
	char decrypted[sizeof(message)];
	char nonce[] = { 0xde, 0xea, 0xbe, 0xef, 'd', 'e', 'a', 'd' };

	strcpy(decrypted, message);
	aes_ctr_crypt(decrypted, encrypted, sizeof(message), key_size * 8, key,
			nonce, true);
	memset(decrypted, 0, sizeof(message));

	aes_ctr_crypt(encrypted, decrypted, sizeof(message), key_size * 8, key,
			nonce, true);
	printf("%s", decrypted);

	return 0;
}
