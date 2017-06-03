#ifndef _SET1_H
#define _SET1_H

#include <stdbool.h>

extern void encode_base64(const unsigned char *in, size_t len, char *out);
extern int decode_base64(const char *in, size_t len, unsigned char *out);
extern size_t base64_size_to_plain_size(const char *in, size_t len);

extern void fixed_xor(const unsigned char *a, const unsigned char *b,
		size_t len, unsigned char *buf);

extern int char_english_score(unsigned char c);
extern unsigned char crack_single_byte_xor(const unsigned char *in, size_t len,
		unsigned char *out);

extern void repeating_key_xor(const unsigned char *in, size_t in_len,
		const unsigned char *key, size_t key_len, unsigned char *out);

extern unsigned int hamming_distance(const unsigned char *a,
		const unsigned char *b, size_t len);

extern void break_repeating_key_xor(const unsigned char *in, size_t in_len,
		unsigned char *key, size_t key_max_len, unsigned int *key_len,
		unsigned char *out);

extern void aes_ecb_encrypt(const unsigned char *in, unsigned char *out,
		size_t len, unsigned int bits, const unsigned char *key);
extern void aes_ecb_decrypt(const unsigned char *in, unsigned char *out,
		size_t len, unsigned int bits, const unsigned char *key);

extern bool detect_aes_ecb(const unsigned char *buf, size_t len,
		unsigned int bits, unsigned int *matches,
		unsigned int *maxmatches);

#endif /* _SET1_H */
