#ifndef __CRYPTOPALS_CORE_H_
#define __CRYPTOPALS_CORE_H_

#define ARRAY_SIZE(a) (sizeof(a) / /**/ sizeof(a[0]))

#define min_t(type, x, y) ({                    \
	type __min1 = (x);                      \
	type __min2 = (y);                      \
	__min1 < __min2 ? __min1 : __min2; })

#endif /* __CRYPTOPALS_CORE_H_ */
