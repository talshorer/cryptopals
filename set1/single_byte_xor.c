#include <stdio.h>

#include <cryptopals/set1.h>

int char_english_score(unsigned char c)
{
	switch (c) {
	case 'a'...'z': /* fallthrough */
	case 'A'...'Z':
		return 4;
	case '0'...'9': /* fallthrough */
	case '\'': /* fallthrough */
	case '\n': /* fallthrough */
	case '\t': /* fallthrough */
	case ',': /* fallthrough */
	case '.': /* fallthrough */
	case ' ':
		return 2;
	case '!': /* fallthrough */
	case '?': /* fallthrough */
	case '-': /* fallthrough */
	case '/':
		return 1;
	default:
		return 0;
	}
}

static int english_score(const unsigned char *buf, size_t len)
{
	int score = 0;

	while (len--)
		score += char_english_score(buf[len]);
	return score;
}

static unsigned char *single_byte_xor(const unsigned char *in, size_t len,
		unsigned char *out, unsigned char cipher)
{
	while (len--)
		out[len] = in[len] ^ cipher;
	return out;
}

unsigned char crack_single_byte_xor(const unsigned char *in, size_t len,
		unsigned char *out)
{
	int cipher;
	int score;
	unsigned char best_cipher = 0;
	int best_score = 0;

	for (cipher = 0x00; cipher < 0x100; cipher++) {
		score = english_score(
			single_byte_xor(in, len, out, (unsigned char)cipher),
			len
		);
		if (score > best_score) {
			best_cipher = cipher;
			best_score = score;
		}
	}

	single_byte_xor(in, len, out, best_cipher);
	return best_cipher;
}
