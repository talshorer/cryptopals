#ifndef _SET2_H
#define _SET2_H

#include <stdbool.h>

extern void pkcs7_pad(char *buf, size_t inlen, size_t outlen);
extern size_t pkcs7_get_padded_size(size_t inlen, unsigned int bytes);
extern bool pkcs7_validate_padding(char *buf, size_t len);

extern void aes_cbc_encrypt(const char *in, char *out, size_t len,
		unsigned int bits, const char *key, const char *iv);
extern void aes_cbc_decrypt(const char *in, char *out, size_t len,
		unsigned int bits, const char *key, const char *iv);

enum oracle_mode {
	ORACLE_MODE_ECB,
	ORACLE_MODE_CBC,
	ORACLE_MODE_RAND,
};
struct oracle {
	size_t append_base;
	char *prefix;
	size_t prefix_len;
	char *suffix;
	size_t suffix_len;
	enum oracle_mode mode;
	unsigned int bits;
	unsigned int bytes;
	char *key;
	bool announce_encryption;
};
extern int setup_oracle(struct oracle *oracle, size_t append_base, char *prefix,
		size_t prefix_len, char *suffix, size_t suffix_len,
		enum oracle_mode mode, unsigned int bits, bool constant_key,
		bool announce_encryption);
extern void cleanup_oracle(struct oracle *oracle);
extern char *encryption_oracle(const char *in, size_t inlen,
		const struct oracle *oracle, size_t *outlen);

extern char *oracle_get_suffix(struct oracle *oracle, size_t *suffix_len);

#endif /* _SET2_H */
