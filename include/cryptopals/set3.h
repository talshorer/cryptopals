#ifndef _SET3_H
#define _SET3_H

#include <stdbool.h>

extern void aes_ctr_crypt(const char *in, char *out, size_t len,
		unsigned int bits, const char *key, const char *nonce,
		bool big_endian);

#endif /* _SET3_H */
