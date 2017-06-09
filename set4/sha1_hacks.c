#include <string.h>
#include <endian.h>
#include <openssl/sha.h>

#include <cryptopals/set4.h>

void sha1_pad(unsigned char *pad, size_t len)
{
	uint64_t be_bitlen = htobe64(len * 8);
	size_t padlen = sha1_get_padded_size(len) - len;

	pad[0] = 0x80;
	memset(pad + 1, 0, padlen - sizeof(be_bitlen) - 1);
	memcpy(pad + padlen - sizeof(be_bitlen), &be_bitlen, sizeof(be_bitlen));
}

static uint32_t __read_be32(const unsigned char *buf)
{
	uint32_t be_val;

	memcpy(&be_val, buf, sizeof(be_val));
	return be32toh(be_val);
}

static void sha1_custom_init(SHA_CTX *ctx, const unsigned char *hash,
		size_t len)
{
	memset(ctx, 0, sizeof(*ctx));

	ctx->h0 = __read_be32(hash + sizeof(uint32_t) * 0);
	ctx->h1 = __read_be32(hash + sizeof(uint32_t) * 1);
	ctx->h2 = __read_be32(hash + sizeof(uint32_t) * 2);
	ctx->h3 = __read_be32(hash + sizeof(uint32_t) * 3);
	ctx->h4 = __read_be32(hash + sizeof(uint32_t) * 4);
	ctx->Nh = len >> 29;
	ctx->Nl = (len << 3) & 0xffffffff;
}

void sha1_append(const unsigned char *oldhash, size_t oldlen,
		const unsigned char *msg, size_t msglen, unsigned char *out)
{
	SHA_CTX ctx;

	sha1_custom_init(&ctx, oldhash,
			sha1_get_padded_size(oldlen - sizeof(uint64_t) - 1));
	SHA1_Update(&ctx, msg, msglen);
	SHA1_Final(out, &ctx);
}
