#include <stdio.h>

#include <cryptopals/set1.h>

int char_english_score(char c)
{
	switch (c) {
	case 'a'...'z': /* fallthrough */
	case 'A'...'Z':
		return 2;
	case '0'...'9': /* fallthrough */
	case '\'': /* fallthrough */
	case '\n': /* fallthrough */
	case '\t': /* fallthrough */
	case ',': /* fallthrough */
	case '.': /* fallthrough */
	case ' ':
		return 1;
	default:
		return 0;
	}
}

static int english_score(const char *buf, size_t len)
{
	int score = 0;

	while (len--)
		score += char_english_score(buf[len]);
	return score;
}

static char *single_byte_xor(const char *in, size_t len, char *out,
		char cipher)
{
	while (len--)
		out[len] = in[len] ^ cipher;
	return out;
}

char crack_single_byte_xor(const char *in, size_t len, char *out)
{
	int cipher;
	int score;
	char best_cipher = 0;
	int best_score = 0;

	for (cipher = 0x00; cipher < 0x100; cipher++) {
		score = english_score(
			single_byte_xor(in, len, out, (char)cipher),
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
