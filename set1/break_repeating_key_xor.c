#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

#include "hamming_distance.h"
#include "single_byte_xor.h"
#include "repeating_key_xor.h"
#include "base64_core.h"

#define INPUTFILE "6.gen.txt"

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

int main(int argc, char *argv[])
{
	char key[40];
	unsigned key_len = 0;
	int fd, err;
	size_t inputsize, outputsize;
	size_t left;
	char *inputbuf, *encoutputbuf, *decoutputbuf;

	fd = open(INPUTFILE, O_RDONLY);
	if (fd < 0) {
		perror("open");
		return 1;
	}
	lseek(fd, 0, SEEK_END);
	inputsize = lseek(fd, 0, SEEK_CUR);
	lseek(fd, 0, SEEK_SET);
	inputbuf = malloc(inputsize);
	if (!inputbuf) {
		perror("malloc");
		close(fd);
		return 1;
	}
	for (left = inputsize; left; left -= err) {
		err = read(fd, &inputbuf[inputsize - left], left);
		if (err < 0) {
			perror("read");
			free(inputbuf);
			close(fd);
			return 1;
		}
	}
	close(fd);

	/* might be a bit more than needed if the base64 input is padded */
	outputsize = base64_size_to_plain_size(inputbuf, inputsize) + 1;
	encoutputbuf = malloc(outputsize);
	if (!encoutputbuf) {
		perror("malloc");
		return 1;
	}
	memset(encoutputbuf, 0, outputsize);
	decode_base64(inputbuf, inputsize, encoutputbuf);
	free(inputbuf);

	decoutputbuf = malloc(outputsize);
	if (!decoutputbuf) {
		free(encoutputbuf);
		perror("malloc");
		return 1;
	}
	memset(decoutputbuf, 0, outputsize);

	break_repeating_key_xor(encoutputbuf, outputsize - 1, key, sizeof(key),
			&key_len, decoutputbuf);
	free(encoutputbuf);
	key[key_len] = 0;
	printf("%d %s\n", key_len, key);
	printf("%s\n", decoutputbuf);
	free(decoutputbuf);
	return 0;
}
