#ifndef _SET4_H
#define _SET4_H

#include <stdbool.h>
#include <stdint.h>
#include <time.h>

#include <cryptopals/set2.h>

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

extern void md4_keyed_mac(const unsigned char *msg, size_t msglen,
		const unsigned char *key, size_t keylen, unsigned char *out);

#define md4_get_padded_size(len) \
	pkcs7_get_padded_size((len) + sizeof(uint64_t), MD4_CBLOCK)
extern void md4_pad(unsigned char *buf, size_t len);
extern void md4_append(const unsigned char *oldhash, size_t oldlen,
		const unsigned char *msg, size_t msglen, unsigned char *out);

struct hmac_server {
	unsigned char *key;
	size_t keylen;
	struct timespec req;
};
extern int hmac_server_init(struct hmac_server *server, unsigned int delay_ms);
extern bool hmac_server_verify(const struct hmac_server *server,
	const unsigned char *msg, size_t msglen, const unsigned char *hmac);
extern void hmac_server_cleanup(struct hmac_server *server);

extern unsigned char hmac_server_break_msg[32];
extern unsigned long hmac_server_break_verify_measure(
	const struct hmac_server *server, const unsigned char *hmac);
extern unsigned long hmac_server_break_get_base_time(
	const struct hmac_server *server, unsigned char *hmac);
extern void hmac_server_break_enter_outer(unsigned int i);
extern void hmac_server_break_enter_inner(unsigned int j);
extern void hmac_server_break_reverse_inner(void);
typedef unsigned int (*hmac_server_breaker_t)(
	const struct hmac_server *server, unsigned char *hmac);
extern int hmac_server_break_main(
	unsigned int delay_ms, hmac_server_breaker_t breaker);

#endif /* _SET4_H */
