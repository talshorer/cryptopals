#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <openssl/aes.h>

#include "base64_core.h"

#define INPUTFILE "7.gen.txt"

int main(int argc, char *argv[])
{
	int fd, ret;
	struct stat stat;
	size_t outputsize, mallocsize;
	size_t left;
	char *inputbuf;
	unsigned char *encoutputbuf, *decoutputbuf;
	const unsigned char *key = (const void *)"YELLOW SUBMARINE";
	AES_KEY dec_key;

	fd = open(INPUTFILE, O_RDONLY);
	if (fd < 0) {
		perror("open");
		ret = 1;
		goto fail_open;
	}
	if (fstat(fd, &stat)) {
		perror("fstat");
		ret = 1;
		goto fail_fstat;
	}
	inputbuf = malloc(stat.st_size);
	if (!inputbuf) {
		perror("malloc input");
		ret = 1;
		goto fail_malloc_input;
	}
	for (left = stat.st_size; left; left -= ret) {
		ret = read(fd, &inputbuf[stat.st_size - left], left);
		if (ret < 0) {
			perror("read");
			ret = 1;
			goto fail_read;
		}
	}
	close(fd);
	fd = -1;

	/* might be a bit more than needed if the base64 input is padded */
	outputsize = base64_size_to_plain_size(inputbuf, stat.st_size);
	mallocsize = outputsize + 1;
	mallocsize += (16 - (mallocsize % 16)) & 0xf;
	encoutputbuf = malloc(mallocsize);
	if (!encoutputbuf) {
		perror("malloc encoutput");
		ret = 1;
		goto fail_malloc_encoutput;
	}
	memset(encoutputbuf, 0, mallocsize);
	decode_base64(inputbuf, stat.st_size, (void *)encoutputbuf);
	free(inputbuf);
	inputbuf = NULL;
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
fail_read:
	if (inputbuf)
		free(inputbuf);
fail_malloc_input:
fail_fstat:
	if (fd >= 0)
		close(fd);
fail_open:
	return ret;
}
