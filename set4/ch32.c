#include <stdio.h>
#include <unistd.h>
#include <openssl/sha.h>

#include <cryptopals/core.h>
#include <cryptopals/set4.h>

#define DELAY_MS 5

static unsigned int ch32_breaker(
	const struct hmac_server *server, unsigned char *hmac)
{
	unsigned int i, j, best;
	unsigned long last, curr, most;
	bool fail = false;

	last = hmac_server_break_get_base_time(server, hmac);
	for (i = 0; i < SHA_DIGEST_LENGTH; i++) {
		most = 0;
		hmac_server_break_enter_outer(i);
		for (j = 0; j < 0x100; j++) {
			hmac_server_break_enter_inner(j);
			hmac[i] = j;
			curr = hmac_server_break_verify_measure(server, hmac);
			if (curr < last) {
				last = curr;
			} else if (curr - last > DELAY_MS) {
				last = curr;
				break;
			} else if (curr > most) {
				best = j;
				most = curr;
			}
			hmac_server_break_reverse_inner();
		}
		if (j == 0x100) {
			if (fail || i == SHA_DIGEST_LENGTH - 1) {
				if (i) {
					dprintf(STDOUT_FILENO, "\b");
					if (i > 1) {
						dprintf(
							STDOUT_FILENO,
							"\b\b\b");
						if (i > 2) {
							dprintf(
								STDOUT_FILENO,
								"\b\b\b");
							i--;
						}
						i--;
					}
					i--;
				}
				fail = false;
			} else {
				hmac_server_break_enter_inner(best);
				hmac[i] = best;
				fail = true;
			}
		} else {
			fail = false;
		}
	}
	return i;
}

int main(int argc, char *argv[])
{
	return hmac_server_break_main(DELAY_MS, ch32_breaker);
}
