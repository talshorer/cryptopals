#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <cryptopals/set1.h>

bool detect_aes_ecb(const char *buf, size_t len, unsigned int bits,
		unsigned int *matches, unsigned int *maxmatches)
{
	unsigned int block = bits / 8;
	unsigned int i, j;
	bool ret = false;
	unsigned int block_matches;
	bool *skip;

	if (matches)
		*matches = 0;

	if (maxmatches)
		*maxmatches = 0;

	skip = malloc(sizeof(*skip) * len / block);
	if (!skip) {
		perror("malloc skip");
		return false;
	}
	memset(skip, 0, sizeof(*skip) * len / block);
	for (i = 0; i < len / block; i++) {
		if (skip[i])
			continue;
		block_matches = 1;
		for (j = i + 1; j < len / block; j++)
			if (!memcmp(&buf[i * block], &buf[j * block], block)) {
				block_matches++;
				skip[j] = true;
				ret = true;
			}
		if (matches)
			*matches += block_matches;
		if (maxmatches && *maxmatches < block_matches)
			*maxmatches = block_matches;
	}
	free(skip);
	return ret;
}
