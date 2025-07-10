
// NIST Example from SP 800-38C, F.2.5
unsigned char key[16]   = {0xc0,0xc1,0xc2,0xc3,0xc4,0xc5,0xc6,0xc7,0xc8,0xc9,0xca,0xcb,0xcc,0xcd,0xce,0xcf};
unsigned char nonce[13] = {0x00,0x03,0x02,0x01,0x00,0xa0,0xa1,0xa2,0xa3,0xa4,0xa5,0xa6,0xa7};
unsigned char aad[8]    = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07};
unsigned char pt[23]    = {0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e};
unsigned char expected_ct[23] = {0x58,0x8c,0x97,0x9a,0x61,0xc6,0x63,0xd2,0xf0,0x66,0xd0,0xc2,0xc0,0xf9,0x89,0x80,0x6d,0x5f,0x6b,0x61,0xda,0xc3,0x84};
unsigned char expected_tag[16] = {0x17,0xe8,0xd1,0x2c,0xfd,0xf9,0x26,0xe0,0x8c,0xd0,0x8b,0xef,0x7f,0x42,0x97,0x6d};
// Set lengths accordingly.

#include <openssl/evp.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

void handleErrors(const char *msg) {
    fprintf(stderr, "Error: %s\n", msg);
    ERR_print_errors_fp(stderr);
    exit(1);
}

int main() {
    // Key and IV (nonce)
    unsigned char key[16] = "0123456789abcdef";
    unsigned char nonce[12] = "uniqueNonce12"; // CCM: 7-13 bytes

    // Plaintext and AAD
    unsigned char plaintext[] = "This is secret data!";
    unsigned char aad[] = "AAD Data";

    // Buffers for ciphertext, decrypted text, and tag
    unsigned char ciphertext[128], decryptedtext[128], tag[16];
    int ciphertext_len, decryptedtext_len, len;

    // Encryption
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) handleErrors("EVP_CIPHER_CTX_new failed");

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_ccm(), NULL, NULL, NULL))
        handleErrors("EncryptInit");

    // Set IV length and tag length *before* key/iv!
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IVLEN, sizeof(nonce), NULL))
        handleErrors("IV len");
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG, 16, NULL))
        handleErrors("TAG len");

    // Set key and IV (nonce)
    if (1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce))
        handleErrors("EncryptInit key/iv");

    // Provide total plaintext length (required for CCM)
    if (1 != EVP_EncryptUpdate(ctx, NULL, &len, NULL, sizeof(plaintext)-1))
        handleErrors("Set ptlen");

    // Provide AAD
    if (1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, sizeof(aad)-1))
        handleErrors("AAD");

    // Encrypt plaintext
    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, sizeof(plaintext)-1))
        handleErrors("EncryptUpdate");
    ciphertext_len = len;

    // Get the tag
    if (1 != EVP_EncryptFinal_ex(ctx, NULL, &len))
        handleErrors("EncryptFinal");
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_GET_TAG, 16, tag))
        handleErrors("Get TAG");

    EVP_CIPHER_CTX_free(ctx);

    printf("Ciphertext: ");
    for(int i = 0; i < ciphertext_len; i++)
        printf("%02x", ciphertext[i]);
    printf("\nTag: ");
    for(int i = 0; i < 16; i++)
        printf("%02x", tag[i]);
    printf("\n");

    // Decryption
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) handleErrors("EVP_CIPHER_CTX_new (dec)");

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_ccm(), NULL, NULL, NULL))
        handleErrors("DecryptInit");

    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IVLEN, sizeof(nonce), NULL))
        handleErrors("IV len dec");
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG, 16, tag))
        handleErrors("Set tag dec");

    if (1 != EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce))
        handleErrors("DecryptInit key/iv");

    if (1 != EVP_DecryptUpdate(ctx, NULL, &len, NULL, ciphertext_len))
        handleErrors("Set ptlen dec");

    if (1 != EVP_DecryptUpdate(ctx, NULL, &len, aad, sizeof(aad)-1))
        handleErrors("AAD dec");

    if (1 != EVP_DecryptUpdate(ctx, decryptedtext, &len, ciphertext, ciphertext_len))
        handleErrors("DecryptUpdate");
    decryptedtext_len = len;

    if (1 != EVP_DecryptFinal_ex(ctx, NULL, &len)) {
        printf("Tag verification failed!\n");
        EVP_CIPHER_CTX_free(ctx);
        return 1;
    }
    EVP_CIPHER_CTX_free(ctx);

    decryptedtext[decryptedtext_len] = '\0';

    printf("Decrypted text: %s\n", decryptedtext);
    return 0;
}
