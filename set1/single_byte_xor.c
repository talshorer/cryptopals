#include <stdio.h>

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
		char chiper)
{
	while (len--)
		out[len] = in[len] ^ chiper;
	return out;
}

char crack_single_byte_xor(const char *in, size_t len, char *out)
{
	int chiper;
	int score;
	char best_chiper = 0;
	int best_score = 0;

	for (chiper = 0x00; chiper < 0x100; chiper++) {
		score = english_score(
			single_byte_xor(in, len, out, (char)chiper),
			len
		);
		if (score > best_score) {
			best_chiper = chiper;
			best_score = score;
		}
	}

	single_byte_xor(in, len, out, best_chiper);
	return best_chiper;
}
