#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

// Utility hex print
void print_hex(const char *label, const unsigned char *data, int len) {
    printf("%s: ", label);
    for (int i = 0; i < len; i++)
        printf("%02X", data[i]);
    printf("\n");
}

int aes_ccm_encrypt(
    const unsigned char *key, int keylen,
    const unsigned char *nonce, int noncelen,
    const unsigned char *aad, int aadlen,
    const unsigned char *pt, int ptlen,
    unsigned char *ct,
    unsigned char *tag, int taglen
) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len, ret = -1;
    size_t offset;

    if (!ctx) return -1;

    if (!EVP_EncryptInit_ex(ctx, EVP_aes_128_ccm(), NULL, NULL, NULL))
        goto end;

    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IVLEN, noncelen, NULL))
        goto end;

    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG, taglen, NULL))
        goto end;

    if (!EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce))
        goto end;

    if (!EVP_EncryptUpdate(ctx, NULL, &len, NULL, ptlen))
        goto end;

    // Feed AAD in chunks
    offset = 0;
    while (offset < aadlen) {
        size_t chunk = (aadlen - offset > 8) ? 8 : (aadlen - offset);
        if (!EVP_EncryptUpdate(ctx, NULL, &len, aad + offset, chunk))
            goto end;
        offset += chunk;
    }

    // Feed plaintext in chunks
    offset = 0;
    while (offset < ptlen) {
        size_t chunk = (ptlen - offset > 16) ? 16 : (ptlen - offset);
        if (!EVP_EncryptUpdate(ctx, ct + offset, &len, pt + offset, chunk))
            goto end;
        offset += chunk;
    }

    if (!EVP_EncryptFinal_ex(ctx, NULL, &len))
        goto end;

    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_GET_TAG, taglen, tag))
        goto end;

    ret = 0; // success

end:
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

int aes_ccm_decrypt(
    const unsigned char *key, int keylen,
    const unsigned char *nonce, int noncelen,
    const unsigned char *aad, int aadlen,
    const unsigned char *ct, int ctlen,
    const unsigned char *tag, int taglen,
    unsigned char *pt
) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len, ret = -1;
    size_t offset;

    if (!ctx) return -1;

    if (!EVP_DecryptInit_ex(ctx, EVP_aes_128_ccm(), NULL, NULL, NULL))
        goto end;

    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IVLEN, noncelen, NULL))
        goto end;

    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG, taglen, (void *)tag))
        goto end;

    if (!EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce))
        goto end;

    if (!EVP_DecryptUpdate(ctx, NULL, &len, NULL, ctlen))
        goto end;

    // Feed AAD in chunks
    offset = 0;
    while (offset < aadlen) {
        size_t chunk = (aadlen - offset > 8) ? 8 : (aadlen - offset);
        if (!EVP_DecryptUpdate(ctx, NULL, &len, aad + offset, chunk))
            goto end;
        offset += chunk;
    }

    // Feed ciphertext in chunks
    offset = 0;
    while (offset < ctlen) {
        size_t chunk = (ctlen - offset > 16) ? 16 : (ctlen - offset);
        if (!EVP_DecryptUpdate(ctx, pt + offset, &len, ct + offset, chunk))
            goto end;
        offset += chunk;
    }

    ret = 0; // success

end:
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

int main() {
    unsigned char key[16] = "thisisakey123456";
    unsigned char nonce[12] = "uniqueNonce12";
    unsigned char aad[20] = "ThisIsAdditionalD";
    unsigned char pt[32] = "PlaintextDataToEncryptInBlocks!!";
    unsigned char ct[sizeof(pt)] = {0};
    unsigned char decpt[sizeof(pt)] = {0};
    unsigned char tag[16] = {0};
    int taglen = 16;

    printf("===== AES-CCM Multiblock Test with OpenSSL =====\n");

    print_hex("Key", key, 16);
    print_hex("Nonce", nonce, 12);
    print_hex("AAD", aad, 20);
    print_hex("Plaintext", pt, 32);

    if (aes_ccm_encrypt(key, 16, nonce, 12, aad, 20, pt, 32, ct, tag, taglen) == 0) {
        print_hex("Ciphertext", ct, 32);
        print_hex("Tag", tag, taglen);
    } else {
        printf("Encryption failed.\n");
        return 1;
    }

    if (aes_ccm_decrypt(key, 16, nonce, 12, aad, 20, ct, 32, tag, taglen, decpt) == 0) {
        print_hex("Decrypted", decpt, 32);
    } else {
        printf("Decryption failed (tag mismatch or input error).\n");
        return 1;
    }

    if (memcmp(pt, decpt, 32) == 0) {
        printf("✅ AES-CCM multiblock encryption/decryption successful.\n");
    } else {
        printf("❌ Decryption output does not match plaintext.\n");
    }

    return 0;
}
