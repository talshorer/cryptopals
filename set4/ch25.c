#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <libgen.h>
#include <unistd.h>
#include <sys/stat.h>

#include <cryptopals/set2.h>
#include <cryptopals/set3.h>
#include <cryptopals/set4.h>

#define CTR_BIG_ENDIAN false

#define BITS 256

static void *read_input(const char *argv0, size_t *len)
{
	int fd;
	char path[0x100];
	struct stat buf;
	void *data;

	strcpy(path, argv0);
	dirname(path);
	strcpy(path + strlen(path), "/input25.gen.txt");
	fd = open(path, O_RDONLY);
	if (fd < 0) {
		perror("open");
		return NULL;
	}
	fstat(fd, &buf);
	*len = buf.st_size;
	data = malloc(*len + 1);
	if (data)
		read(fd, data, *len);
	else
		perror("malloc data");
	close(fd);
	return data;
}

int main(int argc, char *argv[])
{
	size_t len;
	unsigned char *plain;
	unsigned char *cipher;
	unsigned char key[BITS / 8];
	unsigned char nonce[AES_BLOCK_SIZE / 2];
	int ret = 1;

	plain = read_input(argv[0], &len);
	if (!plain)
		goto fail_read_input;
	cipher = malloc(len);
	if (!cipher) {
		perror("malloc cipher");
		goto fail_malloc_cipher;
	}
	fill_random_bytes(key, sizeof(key));
	fill_random_bytes(nonce, sizeof(nonce));
	aes_ctr_crypt(plain, cipher, len, BITS, key, nonce, CTR_BIG_ENDIAN);
	memset(plain, 0, len); /* destroy plaintext */
	attack_random_access_aes_ctr(cipher, plain, len, BITS, key, nonce,
			CTR_BIG_ENDIAN);
	plain[len] = 0;
	printf("%s\n", plain);
	ret = 0;

	free(cipher);
fail_malloc_cipher:
	free(plain);
fail_read_input:
	return ret;
}
