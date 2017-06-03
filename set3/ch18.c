#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <cryptopals/set1.h>
#include <cryptopals/set3.h>

#include "input18.c"

int main(int argc, char *argv[])
{
	int ret;
	size_t inputsize, outputsize;
	unsigned char *encoutputbuf, *decoutputbuf;
	const unsigned char key[] = "YELLOW SUBMARINE";
	const unsigned char nonce[8] = { 0 };

	inputsize = sizeof(inputbuf) - 1;
	outputsize = base64_size_to_plain_size(inputbuf, inputsize);
	encoutputbuf = malloc(outputsize);
	if (!encoutputbuf) {
		perror("malloc encoutput");
		ret = 1;
		goto fail_malloc_encoutput;
	}
	decode_base64(inputbuf, inputsize, encoutputbuf);
	decoutputbuf = malloc(outputsize);
	if (!decoutputbuf) {
		perror("malloc decoutput");
		ret = 1;
		goto fail_malloc_decoutput;
	}

	aes_ctr_crypt(encoutputbuf, decoutputbuf, outputsize, 128, key, nonce,
			false);
	decoutputbuf[outputsize - 1] = 0;

	printf("%s\n", decoutputbuf);
	ret = 0;

	free(decoutputbuf);
fail_malloc_decoutput:
	free(encoutputbuf);
fail_malloc_encoutput:
	return ret;
}
