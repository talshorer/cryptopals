#include <stdio.h>
#include <string.h>

#include <cryptopals/set2.h>

#define orig_str "YELLOW SUBMARINE"

int main(int argc, char *argv[])
{
	unsigned char buf[21] = orig_str;

	pkcs7_pad(buf, strlen(orig_str), sizeof(buf) - 1);
	buf[sizeof(buf) - 1] = 0;
	printf("%s\n", buf);
	return 0;
}
