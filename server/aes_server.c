/*
* Thanks: https://github.com/bawejakunal/AES-GCM-256
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rand.h>
#include <openssl/evp.h>

void print_error()
{
    printf("Some error occured\n");
}

int encrypt(unsigned char *plain_text, int plain_text_len, unsigned char *aad,
            int aad_len, unsigned char *key, unsigned char *iv,
            unsigned char *cipher_text, unsigned char *tag)
{
    EVP_CIPHER_CTX *ctx;

    int len = 0, cipher_text_len = 0;

    /* Create and initialise the context */
    if (!(ctx = EVP_CIPHER_CTX_new()))
        print_error();

    /* Initialise the encryption operation. */
    if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
        print_error();

    /* Set IV length if default 12 bytes (96 bits) is not appropriate */
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 16, NULL))
        print_error();

    /* Initialise key and IV */
    if (!EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv))
        print_error();

    /* Provide any AAD data. This can be called zero or more times as
	 * required
	 */
    if (!EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len))
        print_error();

    /* Provide the message to be encrypted, and obtain the encrypted output.
	 * EVP_EncryptUpdate can be called multiple times if necessary
	 */
    /* encrypt in block lengths of 16 bytes */
    while (cipher_text_len <= plain_text_len - 16)
    {
        if (!EVP_EncryptUpdate(ctx, cipher_text + cipher_text_len, &len, plain_text + cipher_text_len, 16))
            print_error();
        cipher_text_len += len;
    }
    if (!EVP_EncryptUpdate(ctx, cipher_text + cipher_text_len, &len, plain_text + cipher_text_len, plain_text_len - cipher_text_len))
        print_error();
    cipher_text_len += len;

    /* Finalise the encryption. Normally cipher_text bytes may be written at
	 * this stage, but this does not occur in GCM mode
	 */
    if (!EVP_EncryptFinal_ex(ctx, cipher_text + cipher_text_len, &len))
        print_error();
    cipher_text_len += len;

    /* Get the tag */
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag))
        print_error();

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return cipher_text_len;
}

int decrypt(unsigned char *cipher_text, int cipher_text_len, unsigned char *aad,
            int aad_len, unsigned char *tag, unsigned char *key, unsigned char *iv,
            unsigned char *plain_text)
{
    EVP_CIPHER_CTX *ctx;
    int len = 0, plain_text_len = 0, ret;

    /* Create and initialise the context */
    if (!(ctx = EVP_CIPHER_CTX_new()))
        print_error();

    /* Initialise the decryption operation. */
    if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
        print_error();

    /* Set IV length. Not necessary if this is 12 bytes (96 bits) */
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 16, NULL))
        print_error();

    /* Initialise key and IV */
    if (!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv))
        print_error();

    /* Provide any AAD data. This can be called zero or more times as
	 * required
	 */
    if (!EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len))
        print_error();

    /* Provide the message to be decrypted, and obtain the plain_text output.
	 * EVP_DecryptUpdate can be called multiple times if necessary
	 */
    while (plain_text_len <= cipher_text_len - 16)
    {
        if (!EVP_DecryptUpdate(ctx, plain_text + plain_text_len, &len, cipher_text + plain_text_len, 16))
            print_error();
        plain_text_len += len;
    }
    if (!EVP_DecryptUpdate(ctx, plain_text + plain_text_len, &len, cipher_text + plain_text_len, cipher_text_len - plain_text_len))
        print_error();
    plain_text_len += len;

    /* Set expected tag value. Works in OpenSSL 1.0.1d and later */
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag))
        print_error();

    /* Finalise the decryption. A positive return value indicates success,
	 * anything else is a failure - the plain_text is not trustworthy.
	 */
    ret = EVP_DecryptFinal_ex(ctx, plain_text + plain_text_len, &len);

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    if (ret > 0)
    {
        /* Success */
        plain_text_len += len;
        return plain_text_len;
    }
    else
    {
        /* Verify failed */
        return -1;
    }
}
