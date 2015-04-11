#include <stdio.h>
#include <stdlib.h>

#include "hamming_distance.h"
#include "single_byte_xor.h"
#include "repeating_key_xor.h"

#define min_t(type, x, y) ({			\
	type __min1 = (x);			\
	type __min2 = (y);			\
	__min1 < __min2 ? __min1: __min2; })

#define GET_LEY_LEN_MINBLOCKS 4
#define GET_KEY_LEN_NOSCORE 0.0f
static unsigned get_key_len(const char *buf, size_t len, size_t key_max_len)
{
	unsigned key_len, best_key_len = 0;
	unsigned nblocks, block1, block2;
	unsigned hamming;
	float score, best_score = GET_KEY_LEN_NOSCORE;

	for (key_len = 2; key_len < key_max_len; key_len++) {
		hamming = 0;
		nblocks = len / key_len;
		if (nblocks < GET_LEY_LEN_MINBLOCKS)
			break;
		for (block1 = 0; block1 < nblocks; block1++)
			for (block2 = block1 + 1; block2 < nblocks; block2++)
				hamming += hamming_distance(
					&buf[key_len * block1],
					&buf[key_len * block2],
					key_len
				);
		score = (float)hamming /
				(key_len * (nblocks * (nblocks - 1) / 2));
		printf("%u %f\n", key_len, score);
		if (score < best_score || best_score == GET_KEY_LEN_NOSCORE) {
			best_score = score;
			best_key_len = key_len;
		}
	}
	return best_key_len;
}

void break_repeating_key_xor(const char *in, size_t in_len, char *key,
		size_t key_max_len, unsigned *key_len, char *out)
{
	unsigned i, j;
	unsigned base_limit, limit, leftover;
	char *buf;

	*key_len = get_key_len(in, in_len, key_max_len);
	base_limit = in_len / *key_len;
	leftover = in_len % *key_len;
	buf = malloc(base_limit + !!leftover);
	if (!buf)
		exit(1);
	for (i = 0; i < *key_len; i++) {
		limit = base_limit + (leftover > i);
		for (j = 0; j < limit; j++)
			out[j] = in[j * *key_len + i];
		key[i] = crack_single_byte_xor(out, limit, buf);
	}
	free(buf);
	repeating_key_xor(in, in_len, key, *key_len, out);
}

static const char crackme[] =
"\x0b\x36\x37\x27\x2a\x2b\x2e\x63\x62\x2c\x2e\x69\x69\x2a\x23\x69\x3a\x2a\x3c"
"\x63\x24\x20\x2d\x62\x3d\x63\x34\x3c\x2a\x26\x22\x63\x24\x27\x27\x65\x27\x2a"
"\x28\x2b\x2f\x20\x43\x0a\x65\x2e\x2c\x65\x2a\x31\x24\x33\x3a\x65\x3e\x2b\x20"
"\x27\x63\x0c\x69\x2b\x20\x28\x31\x65\x28\x63\x26\x30\x2e\x27\x28\x2f";

int main(int argc, char *argv[])
{
	char key[40];
	unsigned key_len = 0;
	char buf[sizeof(crackme)];

	buf[sizeof(buf) - 1] = 0;
	break_repeating_key_xor(crackme, sizeof(crackme) - 1, key, sizeof(key),
			&key_len, buf);
	key[key_len] = 0;
	printf("%d %s\n", key_len, key);
	printf("%s\n", buf);
	return 0;
}
