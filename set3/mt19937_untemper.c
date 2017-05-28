#include <cryptopals/set3.h>

typedef mt19937_int_t (*mt19937_shift_t)(mt19937_int_t a,
		unsigned int b);

static mt19937_int_t mt19937_shift_left(mt19937_int_t a, unsigned int b)
{
	return a << b;
}

static mt19937_int_t mt19937_shift_right(mt19937_int_t a, unsigned int b)
{
	return a >> b;
}

static mt19937_int_t __mt19937_untemper(mt19937_int_t y, unsigned int s,
		mt19937_int_t c, mt19937_shift_t shift, mt19937_shift_t unshift)
{
	unsigned int m = MT19937_W;
	mt19937_int_t x = 0;

	while (m > s) {
		m -= s;
		x = unshift(shift(y, m) ^ (shift(x, m + s) & shift(c, m)), m);
	}
	return y ^ (shift(x, s) & c);
}

static mt19937_int_t mt19937_untemper(mt19937_int_t y)
{
	y = __mt19937_untemper(y, MT19937_L, MT19937_MASK, mt19937_shift_right,
			mt19937_shift_left);
	y = __mt19937_untemper(y, MT19937_T, MT19937_C, mt19937_shift_left,
			mt19937_shift_right);
	y = __mt19937_untemper(y, MT19937_S, MT19937_B, mt19937_shift_left,
			mt19937_shift_right);
	y = __mt19937_untemper(y, MT19937_U, MT19937_D, mt19937_shift_right,
			mt19937_shift_left);
	return y;
}

void mt19937_clone(struct mt19937 *source, struct mt19937 *clone)
{
	unsigned int i;

	for (i = 0; i < MT19937_N; i++)
		clone->state[i] = mt19937_untemper(mt19937_next(source));
	clone->index = MT19937_N;
}
