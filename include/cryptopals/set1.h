#ifndef _SET1_H
#define _SET1_H

#include <stdbool.h>

extern void encode_base64(const char *in, size_t len, char *out);
extern int decode_base64(const char *in, size_t len, char *out);
extern size_t base64_size_to_plain_size(const char *in, size_t len);

extern void fixed_xor(const char *a, const char *b, size_t len, char *buf);

extern int char_english_score(char c);
extern char crack_single_byte_xor(const char *in, size_t len, char *out);

extern void repeating_key_xor(const char *, size_t, const char *, size_t,
		char *);

extern unsigned int hamming_distance(const char *a, const char *b, size_t len);

extern void break_repeating_key_xor(const char *in, size_t in_len, char *key,
		size_t key_max_len, unsigned int *key_len, char *out);

extern void aes_ecb_encrypt(const char *in, char *out, size_t len,
		unsigned int bits, const char *key);
extern void aes_ecb_decrypt(const char *in, char *out, size_t len,
		unsigned int bits, const char *key);

extern bool detect_aes_ecb(const char *buf, size_t len, unsigned int bits,
		unsigned int *matches, unsigned int *maxmatches);

#endif /* _SET1_H */
