#include <stdio.h>
#include <unistd.h>
#include <sys/time.h>
#include <openssl/sha.h>

#include <cryptopals/core.h>
#include <cryptopals/set4.h>

unsigned char hmac_server_break_msg[sizeof(hmac_server_break_msg)] =
	"hello, world!\n";

unsigned long hmac_server_break_verify_measure(
	const struct hmac_server *server, const unsigned char *hmac)
{
	struct timeval tv;
	long ms;

	gettimeofday(&tv, NULL);
	ms = tv.tv_sec * 1000 + tv.tv_usec / 1000;
	hmac_server_verify(
		server, hmac_server_break_msg,
		sizeof(hmac_server_break_msg), hmac);
	gettimeofday(&tv, NULL);
	ms = tv.tv_sec * 1000 + tv.tv_usec / 1000 - ms;
	return ms;
}

unsigned long hmac_server_break_get_base_time(
	const struct hmac_server *server, unsigned char *hmac)
{
	unsigned long ms0, ms1;

	hmac[0] = 0;
	ms0 = hmac_server_break_verify_measure(server, hmac);
	hmac[0] = 1;
	ms1 = hmac_server_break_verify_measure(server, hmac);
	return min_t(unsigned long, ms0, ms1);
}

void hmac_server_break_enter_outer(unsigned int i)
{
	if (i)
		dprintf(STDOUT_FILENO, "-");
}

void hmac_server_break_enter_inner(unsigned int j)
{
	dprintf(STDOUT_FILENO, "%02x", j);
}

void hmac_server_break_reverse_inner(void)
{
	dprintf(STDOUT_FILENO, "\b\b");
}

int hmac_server_break_main(unsigned int delay_ms, hmac_server_breaker_t breaker)
{
	struct hmac_server server;
	unsigned char hmac[SHA_DIGEST_LENGTH];
	unsigned int i;
	int ret = 1;

	if (hmac_server_init(&server, delay_ms)) {
		perror("hmac_server_init");
		goto fail_hmac_server_init;
	}
	sha1_keyed_mac(
		hmac_server_break_msg, sizeof(hmac_server_break_msg),
		server.key, server.keylen, hmac);
	for (i = 0; i < SHA_DIGEST_LENGTH; i++)
		printf("%s%02x", i ? "-" : "", hmac[i]);
	printf("\n");
	memset(hmac, 0, sizeof(hmac));
	i = breaker(&server, hmac);
	if (i)
		printf("\n");
	if (i == SHA_DIGEST_LENGTH) {
		ret = !hmac_server_verify(
			&server, hmac_server_break_msg,
			sizeof(hmac_server_break_msg), hmac);
		printf("hmac_server_verify returnd %d\n", !ret);
	}

	hmac_server_cleanup(&server);
fail_hmac_server_init:
	return ret;
}
