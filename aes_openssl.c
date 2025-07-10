```c
/* AES-CCM chunk-based encryption and decryption example using OpenSSL */
#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#define KEY_LEN 16
#define IV_LEN 12
#define TAG_LEN 16
#define CHUNK_SIZE 8

void handleErrors() {
    ERR_print_errors_fp(stderr);
    abort();
}

int main() {
    EVP_CIPHER_CTX *ctx;
    unsigned char key[KEY_LEN] = "0123456789abcdef";
    unsigned char iv[IV_LEN] = "nonce12345678";
    unsigned char tag[TAG_LEN];
    unsigned char aad[] = "HeaderAADData";
    unsigned char plaintext[] = "This is a longer plaintext message split into chunks.";
    unsigned char ciphertext[128] = {0};
    unsigned char decrypted[128] = {0};
    int len, ciphertext_len = 0, decrypted_len = 0;

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) handleErrors();

    if (!EVP_EncryptInit_ex(ctx, EVP_aes_128_ccm(), NULL, NULL, NULL)) handleErrors();
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IVLEN, IV_LEN, NULL)) handleErrors();
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG, TAG_LEN, NULL)) handleErrors();

    if (!EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv)) handleErrors();
    if (!EVP_EncryptUpdate(ctx, NULL, &len, NULL, sizeof(plaintext) - 1)) handleErrors();
    if (!EVP_EncryptUpdate(ctx, NULL, &len, aad, sizeof(aad) - 1)) handleErrors();

    for (size_t i = 0; i < sizeof(plaintext) - 1; i += CHUNK_SIZE) {
        size_t chunk = (i + CHUNK_SIZE > sizeof(plaintext) - 1) ? (sizeof(plaintext) - 1 - i) : CHUNK_SIZE;
        if (!EVP_EncryptUpdate(ctx, ciphertext + ciphertext_len, &len, plaintext + i, chunk)) handleErrors();
        ciphertext_len += len;
    }

    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_GET_TAG, TAG_LEN, tag)) handleErrors();

    EVP_CIPHER_CTX_free(ctx);

    printf("Ciphertext: ");
    for (int i = 0; i < ciphertext_len; i++) printf("%02x", ciphertext[i]);
    printf("\nTag: ");
    for (int i = 0; i < TAG_LEN; i++) printf("%02x", tag[i]);
    printf("\n");

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) handleErrors();

    if (!EVP_DecryptInit_ex(ctx, EVP_aes_128_ccm(), NULL, NULL, NULL)) handleErrors();
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IVLEN, IV_LEN, NULL)) handleErrors();
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG, TAG_LEN, tag)) handleErrors();

    if (!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv)) handleErrors();
    if (!EVP_DecryptUpdate(ctx, NULL, &len, NULL, ciphertext_len)) handleErrors();
    if (!EVP_DecryptUpdate(ctx, NULL, &len, aad, sizeof(aad) - 1)) handleErrors();

    for (size_t i = 0; i < ciphertext_len; i += CHUNK_SIZE) {
        size_t chunk = (i + CHUNK_SIZE > ciphertext_len) ? (ciphertext_len - i) : CHUNK_SIZE;
        if (!EVP_DecryptUpdate(ctx, decrypted + decrypted_len, &len, ciphertext + i, chunk)) {
            printf("Decryption failed, tag mismatch.\n");
            EVP_CIPHER_CTX_free(ctx);
            return 1;
        }
        decrypted_len += len;
    }

    EVP_CIPHER_CTX_free(ctx);

    printf("Decrypted: %.*s\n", decrypted_len, decrypted);
    return 0;
}
```
