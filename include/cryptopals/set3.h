#ifndef _SET3_H
#define _SET3_H

#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>

#include <openssl/aes.h>

extern void bigint_inc(char *x, size_t len, bool big_endian);
extern void aes_ctr_setup(AES_KEY *aes_key, unsigned int bits, const char *key,
		const char *nonce, char **ctr, char **keystream);
extern void aes_ctr_do_crypt(const char *in, char *out, size_t len,
		unsigned int bits, AES_KEY *aes_key, bool big_endian, char *ctr,
		char *keystream);
extern void aes_ctr_crypt(const char *in, char *out, size_t len,
		unsigned int bits, const char *key, const char *nonce,
		bool big_endian);

#define MT19937_N 624
#define MT19937_W 32
#define MT19937_F 1812433253
#define MT19937_U 11
#define MT19937_D 0xFFFFFFFF
#define MT19937_S 7
#define MT19937_B 0x9D2C5680
#define MT19937_T 15
#define MT19937_C 0xEFC60000
#define MT19937_L 18
#define MT19937_A 0x9908B0DF
#define MT19937_M 397
#define MT19937_R 31
#define MT19937_MASK ((1UL << MT19937_W) - 1)
#define MT19937_MASK_LOWER ((1UL << MT19937_R) - 1)
#define MT19937_MASK_UPPER (((1UL << MT19937_W) - 1) & ~MT19937_MASK_LOWER)

#define ____mt19937_int_t(bits) uint##bits##_t
#define __mt19937_int_t(bits) ____mt19937_int_t(bits)
#define mt19937_int_t __mt19937_int_t(MT19937_W)

struct mt19937 {
	mt19937_int_t state[MT19937_N];
	unsigned int index;
};
extern void mt19937_seed(struct mt19937 *mt, mt19937_int_t seed);
extern mt19937_int_t mt19937_next(struct mt19937 *mt);

extern void mt19937_clone(struct mt19937 *source, struct mt19937 *clone);

struct mt19937_crypt_ctx {
	struct mt19937 mt;
	unsigned int index;
	mt19937_int_t value;
};
static inline void mt19937_crypt_seed(struct mt19937_crypt_ctx *ctx,
		mt19937_int_t seed)
{
	mt19937_seed(&ctx->mt, seed);
	ctx->index = MT19937_W / 8;
}
extern void mt19937_crypt(const char *in, char *out, size_t len,
		struct mt19937_crypt_ctx *ctx);
#endif /* _SET3_H */
