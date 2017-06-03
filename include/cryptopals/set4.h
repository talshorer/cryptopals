#ifndef _SET4_H
#define _SET4_H

#include <stdbool.h>

extern void aes_ctr_edit(unsigned char *ciphertext, unsigned int bits,
		const unsigned char *key, const unsigned char *nonce,
		bool big_endian, unsigned int offset,
		const unsigned char *newtext, size_t len);
extern void attack_random_access_aes_ctr(unsigned char *cipher,
		unsigned char *plain, size_t len, unsigned int bits,
		const unsigned char *key, const unsigned char *nonce,
		bool big_endian);

#endif /* _SET4_H */
