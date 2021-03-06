#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/aes.h>

#include <cryptopals/set1.h>
#include <cryptopals/set2.h>

#define KEY_BITS 128
#define PROFILE_MAX_EMAIL_LENGTH 64

enum role {
	ROLE_USER,
	ROLE_ADMIN,
	NUM_ROLES,
};

static char *role_strings[] = {
	[ROLE_USER] = "user",
	[ROLE_ADMIN] = "admin",
};

struct profile {
	char email[PROFILE_MAX_EMAIL_LENGTH + 1];
	unsigned int uid;
	enum role role;
};

static struct profile *profile_for(const char *email)
{
	size_t len;
	struct profile *ret;

	len = strlen(email);
	if (len > PROFILE_MAX_EMAIL_LENGTH) {
		printf("invalid length\n");
		return NULL;
	}
	if (strchr(email, '&') || strchr(email, '=')) {
		printf("invalid unsigned characters\n");
		return NULL;
	}
	ret = malloc(sizeof(*ret));
	if (!ret) {
		perror("malloc");
		return NULL;
	}
	strcpy(ret->email, email);
	ret->uid = 0x10;
	ret->role = ROLE_USER;
	return ret;
}

static unsigned char key[KEY_BITS / 8];

static unsigned char *encrypt_profile(struct profile *profile, size_t *outlen)
{
	unsigned char *in;
	unsigned char *out;
	size_t len;
	size_t unpadded_len;

	len = strlen("email=") + strlen(profile->email) +
			strlen("&uid=xx&role=") +
			strlen(role_strings[profile->role]) + 1;
	len = pkcs7_get_padded_size(len, AES_BLOCK_SIZE);
	in = malloc(len);
	if (!in) {
		perror("malloc");
		return NULL;
	}
	out = malloc(len);
	if (!out) {
		perror("malloc");
		free(in);
		return NULL;
	}
	unpadded_len = sprintf((char *)in, "email=%s&uid=%02x&role=%s",
			profile->email, profile->uid,
			role_strings[profile->role]);
	pkcs7_pad(in, unpadded_len, len);
	aes_ecb_encrypt(in, out, len, KEY_BITS, key);
	free(in);
	*outlen = len;
	return out;
}

static struct profile *decrypt_profile(const unsigned char *in, size_t len)
{
	unsigned char *buf;
	char *plain;
	char *p;
	struct profile *profile = NULL;
	struct profile *ret = NULL;
	unsigned int uid;

	buf = malloc(len);
	if (!buf) {
		perror("malloc");
		return NULL;
	}
	aes_ecb_decrypt(in, buf, len, KEY_BITS, key);
	profile = malloc(sizeof(*profile));
	if (!profile) {
		perror("malloc");
		goto out;
	}
	plain = (char *)buf;
	if (strncmp(plain, "email=", 6))
		goto out;
	plain += 6;
	p = strchr(plain, '&');
	if (!p || (p - plain) > PROFILE_MAX_EMAIL_LENGTH)
		goto out;
	memcpy(profile->email, plain, p - plain);
	profile->email[p - plain] = 0;
	plain = p + 1;
	if (strncmp(plain, "uid=", 4))
		goto out;
	plain += 4;
	uid = strtoul(plain, &p, 16);
	if (p != plain + 2)
		goto out;
	plain = p;
	profile->uid = uid;
	if (strncmp(plain, "&role=", 6))
		goto out;
	plain += 6;
	for (profile->role = 0; profile->role < NUM_ROLES; profile->role++)
		if (!strncmp(plain, role_strings[profile->role],
				strlen(role_strings[profile->role])))
			break;
	if (profile->role == NUM_ROLES)
		goto out;
	ret = profile;
out:
	free(buf);
	if (ret != profile)
		free(profile);
	return ret;
}

static unsigned char *encrypt_profile_for(const char *email, size_t *outlen)
{
	struct profile *profile;
	unsigned char *ret;

	profile = profile_for(email);
	if (!profile)
		return NULL;
	ret = encrypt_profile(profile, outlen);
	free(profile);
	return ret;
}

#define normal_email "fooxy@bar.com"
#define hack_suffix \
	"_____________admin\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11"

int main(int argc, char *argv[])
{
	unsigned char *e1;
	unsigned char *e2;
	unsigned char *e3;
	size_t len;
	struct profile *profile;
	int ret = 1;

	fill_random_bytes(key, sizeof(key));
	e1 = encrypt_profile_for(normal_email, &len);
	if (!e1) {
		printf("fail to create e1\n");
		goto fail_e1;
	}
	e2 = encrypt_profile_for(normal_email hack_suffix, &len);
	if (!e2) {
		printf("fail to create e2\n");
		goto fail_e2;
	}
	e3 = malloc(len);
	if (!e3) {
		perror("malloc e3");
		goto fail_e3;
	}
	memcpy(e3, e1, 32);
	memcpy(e3 + 32, e2 + 32, len - 32);
	free(e1);
	free(e2);
	profile = decrypt_profile(e3, len);
	if (!profile) {
		free(e3);
		return 1;
	}
	printf("email=%s\nuid=%02x\nrole=%s\n", profile->email, profile->uid,
			role_strings[profile->role]);
	ret = 0;
	free(profile);
	free(e3);
fail_e3:
	if (ret)
		free(e2);
fail_e2:
	if (ret)
		free(e1);
fail_e1:
	return ret;
}
