#ifndef _SET4_H
#define _SET4_H

#include <stdbool.h>
#include <stdint.h>

#include <cryptopals/set2.h>

extern void aes_ctr_edit(unsigned char *ciphertext, unsigned int bits,
		const unsigned char *key, const unsigned char *nonce,
		bool big_endian, unsigned int offset,
		const unsigned char *newtext, size_t len);
extern void attack_random_access_aes_ctr(unsigned char *cipher,
		unsigned char *plain, size_t len, unsigned int bits,
		const unsigned char *key, const unsigned char *nonce,
		bool big_endian);

extern void sha1_keyed_mac(const unsigned char *msg, size_t msglen,
		const unsigned char *key, size_t keylen, unsigned char *out);

#define sha1_get_padded_size(len) \
	pkcs7_get_padded_size((len) + sizeof(uint64_t), SHA_CBLOCK)
extern void sha1_pad(unsigned char *buf, size_t len);
extern void sha1_append(const unsigned char *oldhash, size_t oldlen,
		const unsigned char *msg, size_t msglen, unsigned char *out);

#endif /* _SET4_H */
