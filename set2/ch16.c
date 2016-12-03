#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <cryptopals/set1.h>
#include <cryptopals/set2.h>

static const char prefix[] = "comment1=cooking%20MCs;userdata=";
#define prefix_len (sizeof(prefix) - 1)
static const char suffix[] = ";comment2=%20like%20a%20pound%20of%20bacon";
#define suffix_len (sizeof(suffix) - 1)
static const char target[] = ";admin=true;";
#define target_len (sizeof(target) - 1)

static bool is_admin(struct oracle *oracle, const char *ciphertext, size_t len)
{
	char *plain;
	void *ret;

	plain = malloc(len);
	if (!plain) {
		perror("malloc plain");
		return false;
	}
	aes_cbc_decrypt(ciphertext, plain, len, oracle->bits,
			oracle->key, oracle->iv);
	ret = memmem(plain, len, target, target_len);
	free(plain);
	return !!ret;
}

int main(int argc, char *argv[])
{
	struct oracle oracle;
	char *in;
	size_t inlen;
	char *out;
	size_t outlen;
	char *outtarget;
	int ret = 1;

	if (setup_oracle(&oracle, 0, prefix, prefix_len, suffix, suffix_len,
			ORACLE_MODE_CBC, 128, true, true, false))
		goto fail_setup_oracle;
	inlen = pkcs7_get_padded_size(prefix_len - 1, oracle.bytes) +
			oracle.bytes * 2;
	in = malloc(inlen);
	if (!in) {
		perror("malloc in");
		goto fail_malloc_in;
	}
	memset(in, 0, inlen);
	out = encryption_oracle(in, inlen, &oracle, &outlen);
	if (!out)
		goto fail_encryption_oracle;
	outtarget = out + inlen - oracle.bytes * 2;
	fixed_xor(outtarget, target, target_len, outtarget);
	printf("is_admin returned %d\n", is_admin(&oracle, out, outlen));
	ret = 0;
	free(out);
fail_encryption_oracle:
	free(in);
fail_malloc_in:
	cleanup_oracle(&oracle);
fail_setup_oracle:
	return ret;
}
