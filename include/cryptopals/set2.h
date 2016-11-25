#ifndef _SET2_H
#define _SET2_H

extern void pkcs7_pad(char *buf, size_t inlen, size_t outlen);

extern void aes_cbc_encrypt(const char *in, char *out, size_t len,
		unsigned int bits, const char *key, const char *iv);
extern void aes_cbc_decrypt(const char *in, char *out, size_t len,
		unsigned int bits, const char *key, const char *iv);

#endif /* _SET2_H */
