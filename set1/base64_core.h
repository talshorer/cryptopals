#ifndef _BASE64_CORE_H
#define _BASE64_CORE_H

extern void encode_base64(const char *, size_t, char *);

extern int decode_base64(const char *, size_t, char *);

#endif /* _BASE64_CORE_H */

