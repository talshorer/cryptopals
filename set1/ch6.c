#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#include <cryptopals/set1.h>

#include "input6.c"

int main(int argc, char *argv[])
{
	char key[40];
	unsigned key_len = 0;
	size_t inputsize, outputsize;
	char *encoutputbuf, *decoutputbuf;

	inputsize = sizeof(inputbuf) - 1;

	/* might be a bit more than needed if the base64 input is padded */
	outputsize = base64_size_to_plain_size(inputbuf, inputsize) + 1;
	encoutputbuf = malloc(outputsize);
	if (!encoutputbuf) {
		perror("malloc");
		return 1;
	}
	memset(encoutputbuf, 0, outputsize);
	decode_base64(inputbuf, inputsize, encoutputbuf);

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
