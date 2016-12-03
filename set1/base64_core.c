#include <stdio.h>
#include <stdint.h>

#include <cryptopals/set1.h>

static const char base64_tbl[] = {
	[ 0] = 'A', [ 1] = 'B', [ 2] = 'C', [ 3] = 'D', [ 4] = 'E', [ 5] = 'F',
	[ 6] = 'G', [ 7] = 'H', [ 8] = 'I', [ 9] = 'J', [10] = 'K', [11] = 'L',
	[12] = 'M', [13] = 'N', [14] = 'O', [15] = 'P', [16] = 'Q', [17] = 'R',
	[18] = 'S', [19] = 'T', [20] = 'U', [21] = 'V', [22] = 'W', [23] = 'X',
	[24] = 'Y', [25] = 'Z', [26] = 'a', [27] = 'b', [28] = 'c', [29] = 'd',
	[30] = 'e', [31] = 'f', [32] = 'g', [33] = 'h', [34] = 'i', [35] = 'j',
	[36] = 'k', [37] = 'l', [38] = 'm', [39] = 'n', [40] = 'o', [41] = 'p',
	[42] = 'q', [43] = 'r', [44] = 's', [45] = 't', [46] = 'u', [47] = 'v',
	[48] = 'w', [49] = 'x', [50] = 'y', [51] = 'z', [52] = '0', [53] = '1',
	[54] = '2', [55] = '3', [56] = '4', [57] = '5', [58] = '6', [59] = '7',
	[60] = '8', [61] = '9', [62] = '+', [63] = '/',
};

#define BASE64_PAD '='

#define _low(value, _bits) \
({ \
	unsigned int __bits = (_bits); \
	(value & ((1 << __bits) - 1)) << (6 - __bits); \
})

#define _high(value, bits) ((value) >> (8 - (bits)))

#define index(first, second, _fbits) \
({ \
	unsigned int __fbits = (_fbits); \
	(_low(first, __fbits) | _high(second, 6 - (__fbits))); \
})

#define base64_byte(...) (base64_tbl[index(__VA_ARGS__)])

void encode_base64(const char *in, size_t len, char *out)
{
	unsigned int i, j = 0;

	for (i = 0; i < len - 2; i += 3) {
		out[j++] = base64_byte(0, in[i], 0);
		out[j++] = base64_byte(in[i], in[i + 1], 2);
		out[j++] = base64_byte(in[i + 1], in[i + 2], 4);
		out[j++] = base64_byte(in[i + 2], 0, 6);
	}

	switch (len % 3) {
	case 2:
		out[j++] = base64_byte(0, in[i], 0);
		out[j++] = base64_byte(in[i], in[i + 1], 2);
		out[j++] = base64_byte(in[i + 1], 0, 4);
		out[j++] = BASE64_PAD;
		break;
	case 1:
		out[j++] = base64_byte(0, in[i], 0);
		out[j++] = base64_byte(in[i], 0, 2);
		out[j++] = BASE64_PAD;
		out[j++] = BASE64_PAD;
		break;
	}
}

size_t base64_size_to_plain_size(const char *in, size_t len)
{
	size_t ret;

	ret = len / 4 * 3;
	while (in[--len] == BASE64_PAD)
		ret--;
	return ret;
}

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

int decode_base64(const char *in, size_t len, char *out)
{
	unsigned int i, o, j, k;
	unsigned int pad = 0;
	char c;
	uint32_t v;

	for (i = 0, o = 0; i < len; i += 4, o += 3) {
		v = 0;
		for (j = 0; j < 4; j++) {
			c = in[i + j];
			if (c == BASE64_PAD) {
				if (len - i - j > 2)
					return -1;
				pad++;
			} else {
				for (k = 0; k < ARRAY_SIZE(base64_tbl); k++)
					if (base64_tbl[k] == c)
						break;
				if (k == ARRAY_SIZE(base64_tbl))
					return -1;
				v = (v << 6) + k;
			}
		}
		if (pad)
			switch (pad) {
			case 1:
				v >>= 2;
				break;
			case 2:
				v >>= 4;
				break;
			}
		for (j = 0; j < 3 - pad; j++) {
			out[o + 2 - pad - j] = v & 0xff;
			v >>= 8;
		}
	}
	return 0;
}
