#include <stdio.h>

#include <cryptopals/set1.h>

static const char a[] = "this is a test";
static const char b[] = "wokka wokka!!!";

int main(int argc, char *argv[])
{
	printf("%u\n", hamming_distance(a, b, sizeof(a) - 1));
	return 0;
}
