#include <stdio.h>
#include <unistd.h>
#include <sys/time.h>
#include <openssl/sha.h>

#include <cryptopals/core.h>
#include <cryptopals/set4.h>

#define DELAY_MS 10

static unsigned char msg[] = "hello, world!\n";

static unsigned long verify_measure(struct hmac_server *server,
		const unsigned char *hmac)
{
	struct timeval tv;
	long ms;

	gettimeofday(&tv, NULL);
	ms = tv.tv_sec * 1000 + tv.tv_usec / 1000;
	hmac_server_verify(server, msg, sizeof(msg), hmac);
	gettimeofday(&tv, NULL);
	ms = tv.tv_sec * 1000 + tv.tv_usec / 1000 - ms;
	return ms;
}

static unsigned long get_base_time(struct hmac_server *server,
		unsigned char *hmac)
{
	unsigned long ms0, ms1;

	hmac[0] = 0;
	ms0 = verify_measure(server, hmac);
	hmac[0] = 1;
	ms1 = verify_measure(server, hmac);
	return min_t(unsigned long, ms0, ms1);
}

int main(int argc, char *argv[])
{
	struct hmac_server server;
	unsigned char hmac[SHA_DIGEST_LENGTH];
	unsigned int i, j;
	unsigned long base;
	int ret = 1;

	if (hmac_server_init(&server, DELAY_MS)) {
		perror("hmac_server_init");
		goto fail_hmac_server_init;
	}
	sha1_keyed_mac(msg, sizeof(msg), server.key, server.keylen, hmac);
	for (i = 0; i < SHA_DIGEST_LENGTH; i++)
		printf("%s%02x", i ? "-" : "", hmac[i]);
	printf("\n");
	memset(hmac, 0, sizeof(hmac));
	base = get_base_time(&server, hmac);
	for (i = 0; i < SHA_DIGEST_LENGTH; i++) {
		if (i)
			dprintf(STDOUT_FILENO, "-");
		for (j = 0; j < 0x100; j++) {
			dprintf(STDOUT_FILENO, "%02x", hmac[i]);
			hmac[i] = j;
			if ((verify_measure(&server, hmac) - base) / DELAY_MS >
					i)
				break;
			dprintf(STDOUT_FILENO, "\b\b");
		}
		if (j == 0x100) {
			printf("%sfailed to get hmac at offset %d\n",
					i ? "\n" : "", i);
			break;
		}
		dprintf(STDOUT_FILENO, "\b\b%02x", hmac[i]);
	}
	if (i)
		printf("\n");
	if (i == SHA_DIGEST_LENGTH) {
		ret = !hmac_server_verify(&server, msg, sizeof(msg), hmac);
		printf("hmac_server_verify returnd %d\n", !ret);
	}

	hmac_server_cleanup(&server);
fail_hmac_server_init:
	return ret;
}
