#include <stdio.h>
#include <openssl/sha.h>

#include <cryptopals/core.h>
#include <cryptopals/set4.h>

#define DELAY_MS 15

static unsigned int ch31_breaker(
	const struct hmac_server *server, unsigned char *hmac)
{
	unsigned int i, j;
	unsigned long base;

	base = hmac_server_break_get_base_time(server, hmac);
	for (i = 0; i < SHA_DIGEST_LENGTH; i++) {
		hmac_server_break_enter_outer(i);
		for (j = 0; j < 0x100; j++) {
			hmac_server_break_enter_inner(j);
			hmac[i] = j;
			if ((hmac_server_break_verify_measure(
					server, hmac) - base) / DELAY_MS >
					i)
				break;
			hmac_server_break_reverse_inner();
		}
		if (j == 0x100) {
			printf("%sfailed to get hmac at offset %d\n",
					i ? "\n" : "", i);
			break;
		}
	}
	return i;
}

int main(int argc, char *argv[])
{
	return hmac_server_break_main(DELAY_MS, ch31_breaker);
}
