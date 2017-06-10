#include <openssl/md4.h>

#include <cryptopals/set4.h>

void md4_keyed_mac(const unsigned char *msg, size_t msglen,
		const unsigned char *key, size_t keylen, unsigned char *out)
{
	MD4_CTX ctx;

	MD4_Init(&ctx);
	MD4_Update(&ctx, key, keylen);
	MD4_Update(&ctx, msg, msglen);
	MD4_Final(out, &ctx);
}
