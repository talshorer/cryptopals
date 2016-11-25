#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <openssl/aes.h>

#include <cryptopals/set1.h>

#include "input7.c"

int main(int argc, char *argv[])
{
	int ret;
	size_t inputsize, outputsize, mallocsize;
	size_t left;
	unsigned char *encoutputbuf, *decoutputbuf;
	const unsigned char *key = (const void *)"YELLOW SUBMARINE";
	AES_KEY dec_key;

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

	AES_set_decrypt_key(key, 128, &dec_key);
	for (left = 0; left < mallocsize; left += 16)
		AES_decrypt(&encoutputbuf[left], &decoutputbuf[left], &dec_key);
	decoutputbuf[outputsize] = 0;

	printf("%s\n", decoutputbuf);
	ret = 0;

	free(decoutputbuf);
fail_malloc_decoutput:
	free(encoutputbuf);
fail_malloc_encoutput:
	return ret;
}
