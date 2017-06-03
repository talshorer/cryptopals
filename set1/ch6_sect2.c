#include <stdio.h>

#include <cryptopals/set1.h>

static const unsigned char a[] = "this is a test";
static const unsigned char b[] = "wokka wokka!!!";

int main(int argc, char *argv[])
{
	printf("%u\n", hamming_distance(a, b, sizeof(a) - 1));
	return 0;
}
