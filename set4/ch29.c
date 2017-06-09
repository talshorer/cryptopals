#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>

#include <cryptopals/set2.h>
#include <cryptopals/set4.h>

static unsigned char *key;
#define MIN_KEYLEN (1 << 10) /* arbitrary */
#define MAX_KEYLEN (4 << 10) /* arbitrary */
static size_t keylen;

static unsigned char userdata[] = "foo";
static size_t userdata_len = sizeof(userdata) - 1;

static bool validate_message(const unsigned char *msg, size_t len,
		const unsigned char *hmac)
{
	unsigned char calculated[SHA_DIGEST_LENGTH];

	sha1_keyed_mac(msg, len, key, keylen, calculated);
	return !memcmp(hmac, calculated, sizeof(calculated));
}

int main(int argc, char *argv[])
{
	int ret = 1;
	unsigned char *msg;
	unsigned int i;
	size_t base_msglen;
	size_t padded_msglen;
	unsigned char base_hmac[SHA_DIGEST_LENGTH];
	unsigned char hmac[SHA_DIGEST_LENGTH];

	keylen = MIN_KEYLEN + random() % (MAX_KEYLEN - MIN_KEYLEN);
	printf("keylen is %zd\n", keylen);
	key = make_random_bytes(keylen);
	if (!key) {
		perror("make_random_bytes key");
		goto fail_make_key;
	}
	base_msglen = admin_prefix_len + userdata_len + admin_suffix_len;
	/* enough for any needed padding */
	msg = malloc(base_msglen + sizeof(uint64_t) + 1 + SHA_CBLOCK +
			admin_target_len);
	if (!msg) {
		perror("malloc msg");
		goto fail_malloc_msg;
	}
	memcpy(msg, admin_prefix, admin_prefix_len);
	i = admin_prefix_len;
	memcpy(msg + i, userdata, userdata_len);
	i += userdata_len;
	memcpy(msg + i, admin_suffix, admin_suffix_len);
	sha1_keyed_mac(msg, base_msglen, key, keylen, base_hmac);

	/* begin the attack */
	for (i = MIN_KEYLEN; i < MAX_KEYLEN; i++) {
		padded_msglen = sha1_get_padded_size(base_msglen + i) - i;
		sha1_pad(msg + base_msglen, base_msglen + i);
		memcpy(msg + padded_msglen, admin_target, admin_target_len);
		sha1_append(base_hmac, padded_msglen + i, admin_target,
				admin_target_len, hmac);
		if (validate_message(msg, padded_msglen + admin_target_len,
				hmac))
			break;
	}
	if (i == MAX_KEYLEN) {
		printf("failed to validate with any keylen in range\n");
	} else {
		printf("successfully validated with keylen %u\n", i);
		ret = 0;
	}

	free(msg);
fail_malloc_msg:
	free(key);
fail_make_key:
	return ret;
}
