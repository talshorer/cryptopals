#include <stdio.h>

static int char_english_score(char c)
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

char crack_single_byte_xor(const char *in, size_t len, char *out, int *pscore)
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
	if (pscore)
		*pscore = best_score;
	return best_chiper;
}

static const char crackme[] =
"\x1b\x37\x37\x33\x31\x36\x3f\x78\x15\x1b\x7f\x2b\x78\x34\x31\x33\x3d\x78\x39\x78\x28\x37\x2d\x36\x3c\x78\x37\x3e\x78\x3a\x39\x3b\x37\x36";

int main(int argc, char *argv[])
{
	char buf[sizeof(crackme)];
	char chiper;

	buf[sizeof(buf) - 1] = 0;
	chiper = crack_single_byte_xor(crackme, sizeof(crackme) - 1, buf,
			NULL);
	printf("0x%02x\n", chiper);
	printf("%s\n", buf);
	return 0;
}
