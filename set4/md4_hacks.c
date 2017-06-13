#include <string.h>
#include <endian.h>
#include <openssl/md4.h>

#include <cryptopals/set4.h>

void md4_pad(unsigned char *pad, size_t len)
{
	uint64_t le_bitlen = htole64(len * 8);
	size_t padlen = md4_get_padded_size(len) - len;

	pad[0] = 0x80;
	memset(pad + 1, 0, padlen - sizeof(le_bitlen) - 1);
	memcpy(pad + padlen - sizeof(le_bitlen), &le_bitlen, sizeof(le_bitlen));
}

static uint32_t __read_le32(const unsigned char *buf)
{
	uint32_t le_val;

	memcpy(&le_val, buf, sizeof(le_val));
	return le32toh(le_val);
}

static void md4_custom_init(MD4_CTX *ctx, const unsigned char *hash,
		size_t len)
{
	memset(ctx, 0, sizeof(*ctx));

	ctx->A = __read_le32(hash + sizeof(uint32_t) * 0);
	ctx->B = __read_le32(hash + sizeof(uint32_t) * 1);
	ctx->C = __read_le32(hash + sizeof(uint32_t) * 2);
	ctx->D = __read_le32(hash + sizeof(uint32_t) * 3);
	ctx->Nh = len >> 29;
	ctx->Nl = (len << 3) & 0xffffffff;
}

void md4_append(const unsigned char *oldhash, size_t oldlen,
		const unsigned char *msg, size_t msglen, unsigned char *out)
{
	MD4_CTX ctx;

	md4_custom_init(&ctx, oldhash,
			md4_get_padded_size(oldlen - sizeof(uint64_t) - 1));
	MD4_Update(&ctx, msg, msglen);
	MD4_Final(out, &ctx);
}
