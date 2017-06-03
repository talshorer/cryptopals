#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <cryptopals/set1.h>
#include <cryptopals/set2.h>

static const unsigned char admin_prefix[] = "comment1=cooking%20MCs;userdata=";
const size_t admin_prefix_len = sizeof(admin_prefix) - 1;
static const unsigned char admin_suffix[] =
		";comment2=%20like%20a%20pound%20of%20bacon";
static const size_t admin_suffix_len = sizeof(admin_suffix) - 1;
static const unsigned char admin_target[] = ";admin=true;";
const size_t admin_target_len = sizeof(admin_target) - 1;

static bool is_admin(struct oracle *oracle, const unsigned char *cipher,
		size_t len, admin_decrypt_t decrypt)
{
	unsigned char *plain;
	void *ret;

	plain = malloc(len);
	if (!plain) {
		perror("malloc plain");
		return false;
	}
	decrypt(oracle, cipher, plain, len);
	ret = memmem(plain, len, admin_target, admin_target_len);
	free(plain);
	return !!ret;
}

int admin_attack(size_t inlen, enum oracle_mode mode, admin_decrypt_t decrypt)
{
	struct oracle oracle;
	unsigned char *in;
	unsigned char *out;
	size_t outlen;
	unsigned char *outtarget;
	int ret = 1;

	if (setup_oracle(&oracle, 0, admin_prefix, admin_prefix_len,
			admin_suffix, admin_suffix_len, mode, 128, true, true,
			false))
		goto fail_setup_oracle;
	in = malloc(inlen);
	if (!in) {
		perror("malloc in");
		goto fail_malloc_in;
	}
	memset(in, 0, inlen);
	out = encryption_oracle(in, inlen, &oracle, &outlen);
	if (!out)
		goto fail_encryption_oracle;
	outtarget = out + admin_prefix_len;
	fixed_xor(outtarget, admin_target, admin_target_len, outtarget);
	printf("is_admin returned %d\n", is_admin(&oracle, out, outlen,
			decrypt));
	ret = 0;
	free(out);
fail_encryption_oracle:
	free(in);
fail_malloc_in:
	cleanup_oracle(&oracle);
fail_setup_oracle:
	return ret;
}
