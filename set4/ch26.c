#include <stdlib.h>
#include <openssl/aes.h>

#include <cryptopals/set2.h>
#include <cryptopals/set3.h>

void decrypt_ctr(struct oracle *oracle, const unsigned char *cipher,
		unsigned char *plain, size_t len)
{
	aes_ctr_crypt(cipher, plain, len, oracle->bits, oracle->key,
			oracle->iv, false);
}

int main(int argc, char *argv[])
{
	return admin_attack(admin_target_len, ORACLE_MODE_CTR, decrypt_ctr);
}
