#ifndef _SET3_H
#define _SET3_H

#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>

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

#endif /* _SET3_H */
