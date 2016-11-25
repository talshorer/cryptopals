#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <cryptopals/set1.h>
#include <cryptopals/set2.h>

#include "input10.c"

int main(int argc, char *argv[])
{
	int ret;
	size_t inputsize, outputsize, mallocsize;
	char *encoutputbuf, *decoutputbuf;
	const char *key = "YELLOW SUBMARINE";

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
	decode_base64(inputbuf, inputsize, (void *)encoutputbuf);
	decoutputbuf = malloc(mallocsize);
	if (!decoutputbuf) {
		perror("malloc decoutput");
		ret = 1;
		goto fail_malloc_decoutput;
	}

	aes_cbc_decrypt(encoutputbuf, decoutputbuf, outputsize, 128, key, NULL);
	decoutputbuf[outputsize] = 0;

	printf("%s\n", decoutputbuf);
	ret = 0;

	free(decoutputbuf);
fail_malloc_decoutput:
	free(encoutputbuf);
fail_malloc_encoutput:
	return ret;
}
