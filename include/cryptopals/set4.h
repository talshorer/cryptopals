#ifndef _SET4_H
#define _SET4_H

#include <stdbool.h>

extern void aes_ctr_edit(char *ciphertext, unsigned int bits, const char *key,
		const char *nonce,  bool big_endian, unsigned int offset,
		const char *newtext, size_t len);
extern void attack_random_access_aes_ctr(char *cipher, char *plain, size_t len,
		unsigned int bits, const char *key, const char *nonce,
		bool big_endian);

#endif /* _SET4_H */
