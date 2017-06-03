#ifndef _SET2_H
#define _SET2_H

#include <stdbool.h>

extern void pkcs7_pad(unsigned char *buf, size_t inlen, size_t outlen);
extern size_t pkcs7_get_padded_size(size_t inlen, unsigned int bytes);
extern bool pkcs7_validate_padding(unsigned char *buf, size_t len);

extern void aes_cbc_encrypt(const unsigned char *in, unsigned char *out,
		size_t len, unsigned int bits, const unsigned char *key,
		const unsigned char *iv);
extern void aes_cbc_decrypt(const unsigned char *in, unsigned char *out,
		size_t len, unsigned int bits, const unsigned char *key,
		const unsigned char *iv);

extern void fill_random_bytes(unsigned char *buf, unsigned int n);
extern void *make_random_bytes(unsigned int n);
enum oracle_mode {
	ORACLE_MODE_ECB,
	ORACLE_MODE_CBC,
	ORACLE_MODE_RAND,
	ORACLE_MODE_CTR,
};
struct oracle {
	size_t append_base;
	const unsigned char *prefix;
	size_t prefix_len;
	const unsigned char *suffix;
	size_t suffix_len;
	enum oracle_mode mode;
	unsigned int bits;
	unsigned char *key;
	unsigned char *iv;
	bool announce_encryption;
};
extern int setup_oracle(struct oracle *oracle, size_t append_base,
		const unsigned char *prefix, size_t prefix_len,
		const unsigned char *suffix, size_t suffix_len,
		enum oracle_mode mode, unsigned int bits, bool constant_key,
		bool constant_iv, bool announce_encryption);
extern void cleanup_oracle(struct oracle *oracle);
extern unsigned char *encryption_oracle(const unsigned char *in, size_t inlen,
		const struct oracle *oracle, size_t *outlen);

extern unsigned char *oracle_get_suffix(struct oracle *oracle,
		size_t *suffix_len);

typedef void (*admin_decrypt_t)(struct oracle *oracle,
		const unsigned char *cipher, unsigned char *plain, size_t len);
extern const size_t admin_prefix_len;
extern const size_t admin_target_len;
extern int admin_attack(size_t inlen, enum oracle_mode mode,
		admin_decrypt_t decrypt);

#endif /* _SET2_H */
