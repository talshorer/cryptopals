#include <cryptopals/set3.h>

void mt19937_crypt(const char *in, char *out, size_t len,
		struct mt19937_crypt_ctx *ctx)
{
	while (len--) {
		if (ctx->index == MT19937_W / 8) {
			ctx->index = 0;
			ctx->value = mt19937_next(&ctx->mt);
		}
		*out++ = *in++ ^ (ctx->value & 0xff);
		ctx->value >>= 8;
		ctx->index++;
	}
}
