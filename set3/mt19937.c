#include <cryptopals/set3.h>

void mt19937_seed(struct mt19937 *mt, mt19937_int_t seed)
{
	unsigned int i;
	mt19937_int_t prev;

	prev = mt->state[0] = seed;
	for (i = 1; i < MT19937_N; i++)
		prev = mt->state[i] = (MT19937_F * (prev ^ (prev >>
				(MT19937_W - 2))) + i) & MT19937_MASK;
	mt->index = MT19937_N;
}

mt19937_int_t mt19937_next(struct mt19937 *mt)
{
	mt19937_int_t y;

	if (mt->index == MT19937_N) { /* twist */
		mt19937_int_t x, xA;
		unsigned int i;

		for (i = 0; i < MT19937_N; i++) {
			x = (mt->state[i] & MT19937_MASK_UPPER) +
					(mt->state[(i + 1) % MT19937_N] &
							MT19937_MASK_LOWER);
			xA = x >> 1;
			if (x & 1)
				xA ^= MT19937_A;
			mt->state[i] = mt->state[(i + MT19937_M) % MT19937_N] ^
					xA;
		}
		mt->index = 0;
	}
	y = mt->state[mt->index++];
	y ^= (y >> MT19937_U) & MT19937_D;
	y ^= (y << MT19937_S) & MT19937_B;
	y ^= (y << MT19937_T) & MT19937_C;
	y ^= y >> MT19937_L;
	return y & MT19937_MASK;
}
