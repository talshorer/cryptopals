#include <stdio.h>
#include <string.h>

#include <cryptopals/set2.h>
#include <cryptopals/set3.h>

#define CH24_ORACLE_RANDLEN_MIN 0x10
#define CH24_ORACLE_RANDLEN_MAX 0x40
#define SEED_MAX (1 << 16)

static const unsigned char known[] = "AAAAAAAAAAAAAA";
#define known_len (sizeof(known) - 1)

static unsigned char *ch24_oracle(size_t *outlen)
{
	size_t randlen;
	unsigned char *in;
	unsigned char *out = NULL;
	struct mt19937_crypt_ctx ctx;
	mt19937_int_t seed;

	randlen = CH24_ORACLE_RANDLEN_MIN + rand() % (CH24_ORACLE_RANDLEN_MAX -
			CH24_ORACLE_RANDLEN_MIN);
	*outlen = randlen + known_len;
	in = malloc(*outlen);
	if (!in) {
		perror("malloc in");
		goto out;
	}
	out = malloc(*outlen);
	if (!out) {
		perror("malloc out");
		goto out_free_in;
	}
	fill_random_bytes(in, randlen);
	memcpy(in + randlen, known, known_len);
	seed = rand() % SEED_MAX;
	printf("%11s: seed is 0x%04x\n", __func__, seed);
	mt19937_crypt_seed(&ctx, seed);
	mt19937_crypt(in, out, *outlen, &ctx);
out_free_in:
	free(in);
out:
	return out;
}

int main(int argc, char *argv[])
{
	unsigned char *cipher;
	unsigned char *plain;
	size_t len;
	unsigned int i;
	int ret = 1;
	struct mt19937_crypt_ctx ctx;

	cipher = ch24_oracle(&len);
	if (!cipher)
		goto fail_ch24_oracle;
	plain = malloc(len);
	if (!plain) {
		perror("malloc plain");
		goto fail_malloc_plain;
	}
	for (i = 0; i < SEED_MAX; i++) {
		mt19937_crypt_seed(&ctx, i);
		mt19937_crypt(cipher, plain, len, &ctx);
		if (!memcmp(plain + len - known_len, known, known_len)) {
			printf("%11s: seed is 0x%04x\n", __func__, i);
			ret = 0;
			break;
		}
	}
	if (i == SEED_MAX)
		printf("%s: seed not found\n", __func__);
	free(plain);
fail_malloc_plain:
	free(cipher);
fail_ch24_oracle:
	return ret;
}
