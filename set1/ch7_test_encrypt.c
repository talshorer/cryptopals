#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <cryptopals/set1.h>

static const unsigned char message[] = "Hello, world!\n"
		"What a lovely day!\n"
		"Jibber Jabber this should be multiple blocks\n";

static const unsigned char key[] = "YELLOW SUBMARINE";

#define key_size (sizeof(key) - 1)

#define padded_message_size (sizeof(message) + \
		((key_size - (sizeof(message) % key_size)) & (key_size - 1)))

int main(int argc, char *argv[])
{
	unsigned char encrypted[padded_message_size];
	unsigned char decrypted[padded_message_size];

	memset(decrypted, 0, sizeof(decrypted));
	memcpy(decrypted, message, sizeof(message));

	aes_ecb_encrypt(decrypted, encrypted, padded_message_size, key_size * 8,
			key);
	memset(decrypted, 0, padded_message_size);

	aes_ecb_decrypt(encrypted, decrypted, padded_message_size, key_size * 8,
			key);
	printf("%s", decrypted);

	return 0;
}
