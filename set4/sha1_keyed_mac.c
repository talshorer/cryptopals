#include <openssl/sha.h>

#include <cryptopals/set4.h>

void sha1_keyed_mac(const unsigned char *msg, size_t msglen,
		const unsigned char *key, size_t keylen, unsigned char *out)
{
	SHA_CTX ctx;

	SHA1_Init(&ctx);
	SHA1_Update(&ctx, key, keylen);
	SHA1_Update(&ctx, msg, msglen);
	SHA1_Final(out, &ctx);
}
