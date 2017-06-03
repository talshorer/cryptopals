#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

#include <cryptopals/set1.h>

#include "input7.c"

int main(int argc, char *argv[])
{
	int ret;
	size_t inputsize, outputsize, mallocsize;
	unsigned char *encoutputbuf, *decoutputbuf;
	const unsigned char key[] = "YELLOW SUBMARINE";

	inputsize = sizeof(inputbuf) - 1;
	/* might be a bit more than needed if the base64 input is padded */
	outputsize = base64_size_to_plain_size(inputbuf, inputsize);
	mallocsize = outputsize + 1;
	mallocsize += (16 - (mallocsize % 16)) & 0xf;
	encoutputbuf = malloc(mallocsize);
	if (!encoutputbuf) {
		perror("malloc encoutput");
		ret = 1;
		goto fail_malloc_encoutput;
	}
	memset(encoutputbuf, 0, mallocsize);
	decode_base64(inputbuf, inputsize, encoutputbuf);
	decoutputbuf = malloc(mallocsize);
	if (!decoutputbuf) {
		perror("malloc decoutput");
		ret = 1;
		goto fail_malloc_decoutput;
	}

	aes_ecb_decrypt(encoutputbuf, decoutputbuf, mallocsize, 128, key);
	decoutputbuf[outputsize] = 0;

	printf("%s\n", decoutputbuf);
	ret = 0;

	free(decoutputbuf);
fail_malloc_decoutput:
	free(encoutputbuf);
fail_malloc_encoutput:
	return ret;
}
