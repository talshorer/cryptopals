#include <stdlib.h>
#include <openssl/aes.h>

#include <cryptopals/set2.h>

void decrypt_cbc(struct oracle *oracle, const unsigned char *cipher,
		unsigned char *plain, size_t len)
{
	aes_cbc_decrypt(cipher, plain, len, oracle->bits, oracle->key,
			oracle->iv);
}

int main(int argc, char *argv[])
{
	return admin_attack(pkcs7_get_padded_size(admin_prefix_len - 1,
			AES_BLOCK_SIZE) - admin_prefix_len +
			pkcs7_get_padded_size(admin_target_len - 1,
					AES_BLOCK_SIZE) + AES_BLOCK_SIZE,
			ORACLE_MODE_CBC, decrypt_cbc);
}
