#include <stdlib.h>
#include <openssl/sha.h>

#include <cryptopals/set4.h>

#define KEYLEN_MIN (1 << 10) /* arbitrary */
#define KEYLEN_MAX (4 << 10) /* arbitrary */

int hmac_server_init(struct hmac_server *server, unsigned int delay_ms)
{
	server->req.tv_nsec = (delay_ms * 1000000) % 1000000000;
	server->req.tv_sec = delay_ms / 1000;
	server->keylen = KEYLEN_MIN + random() % (KEYLEN_MAX - KEYLEN_MIN);
	server->key = make_random_bytes(server->keylen);
	return !server->key;
}

bool hmac_server_verify(struct hmac_server *server, const unsigned char *msg,
		size_t msglen, const unsigned char *hmac)
{
	unsigned char calculated[SHA_DIGEST_LENGTH];
	unsigned int i;

	sha1_keyed_mac(msg, msglen, server->key, server->keylen, calculated);
	for (i = 0; i < sizeof(calculated); i++) {
		if (calculated[i] != hmac[i])
			return false;
		nanosleep(&server->req, NULL);
	}
	return true;
}

void hmac_server_cleanup(struct hmac_server *server)
{
	free(server->key);
}
