#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

int encrypt(unsigned char *plain_text, int plain_text_len, unsigned char *aad,
			int aad_len, unsigned char *key, unsigned char *iv,
			unsigned char *cipher_text, unsigned char *tag);

int decrypt(unsigned char *cipher_text, int cipher_text_len, unsigned char *aad,
			int aad_len, unsigned char *tag, unsigned char *key, unsigned char *iv,
			unsigned char *plain_text);