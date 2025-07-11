#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>

#define KEY_LEN    16
#define IV_LEN     12
#define TAG_LEN    16
#define AAD_LEN    20
#define PT_LEN     40
#define CHUNK_SIZE 8

unsigned char key[KEY_LEN] = {0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81};
unsigned char iv[IV_LEN]   = {0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb};
unsigned char aad[AAD_LEN] = "0123456789abcdefghij";
unsigned char pt[PT_LEN]   = {
    'T','h','e',' ','q','u','i','c','k',' ',
    'b','r','o','w','n',' ','f','o','x',' ',
    'j','u','m','p','s',' ','o','v','e','r',' ',
    '1','2','3','4','5','6','7','8','9','0'
};

void print_hex(const char *label, const unsigned char *data, int len) {
    printf("%s:", label);
    for (int i = 0; i < len; i++) printf(" %02x", data[i]);
    printf("\n");
}

int aes_ccm_encrypt(
    const unsigned char *key, const unsigned char *iv,
    const unsigned char *aad, int aad_len,
    const unsigned char *pt, int pt_len,
    unsigned char *ct, unsigned char *tag,
    int chunk_size // If 0, do single-shot
) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len, tmplen = 0, outlen = 0, ret = -1;
    if (!ctx) return -1;
    if (!EVP_EncryptInit_ex(ctx, EVP_aes_128_ccm(), NULL, NULL, NULL)) goto done;
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IVLEN, IV_LEN, NULL)) goto done;
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG, TAG_LEN, NULL)) goto done;
    if (!EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv)) goto done;
    if (!EVP_EncryptUpdate(ctx, NULL, &len, NULL, pt_len)) goto done;
    // Feed AAD all at once
    if (!EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len)) goto done;

    if (chunk_size <= 0) {
        // Single-shot PT
        if (!EVP_EncryptUpdate(ctx, ct, &len, pt, pt_len)) goto done;
        outlen = len;
    } else {
        // Chunked PT
        int offset = 0;
        outlen = 0;
        while (offset < pt_len) {
            int chunk = (pt_len - offset > chunk_size) ? chunk_size : (pt_len - offset);
            if (!EVP_EncryptUpdate(ctx, ct + offset, &tmplen, pt + offset, chunk)) goto done;
            outlen += tmplen;
            offset += chunk;
        }
    }
    if (!EVP_EncryptFinal_ex(ctx, ct + outlen, &len)) goto done;
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_GET_TAG, TAG_LEN, tag)) goto done;
    ret = outlen;
done:
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

int aes_ccm_decrypt(
    const unsigned char *key, const unsigned char *iv,
    const unsigned char *aad, int aad_len,
    const unsigned char *ct, int ct_len,
    const unsigned char *tag,
    unsigned char *pt,
    int chunk_size
) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len, tmplen = 0, outlen = 0, ret = -1;
    if (!ctx) return -1;
    if (!EVP_DecryptInit_ex(ctx, EVP_aes_128_ccm(), NULL, NULL, NULL)) goto done;
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IVLEN, IV_LEN, NULL)) goto done;
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG, TAG_LEN, (void*)tag)) goto done;
    if (!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv)) goto done;
    if (!EVP_DecryptUpdate(ctx, NULL, &len, NULL, ct_len)) goto done;
    // Feed AAD all at once
    if (!EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len)) goto done;

    if (chunk_size <= 0) {
        // Single-shot CT
        if (!EVP_DecryptUpdate(ctx, pt, &len, ct, ct_len)) goto done;
        outlen = len;
    } else {
        // Chunked CT
        int offset = 0;
        outlen = 0;
        while (offset < ct_len) {
            int chunk = (ct_len - offset > chunk_size) ? chunk_size : (ct_len - offset);
            if (!EVP_DecryptUpdate(ctx, pt + offset, &tmplen, ct + offset, chunk)) goto done;
            outlen += tmplen;
            offset += chunk;
        }
    }
    ret = outlen;
done:
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

int main() {
    unsigned char ct1[PT_LEN], tag1[TAG_LEN], dec1[PT_LEN+1];
    unsigned char ct2[PT_LEN], tag2[TAG_LEN], dec2[PT_LEN+1];
    int chunk = CHUNK_SIZE;

    printf("\n--- AES-CCM Single-shot ---\n");
    int enc_len1 = aes_ccm_encrypt(key, iv, aad, AAD_LEN, pt, PT_LEN, ct1, tag1, 0);
    print_hex("CT", ct1, enc_len1);
    print_hex("TAG", tag1, TAG_LEN);

    printf("\n--- AES-CCM Chunked (PT in %d-byte chunks) ---\n", chunk);
    int enc_len2 = aes_ccm_encrypt(key, iv, aad, AAD_LEN, pt, PT_LEN, ct2, tag2, chunk);
    print_hex("CT", ct2, enc_len2);
    print_hex("TAG", tag2, TAG_LEN);

    printf("\nCiphertext match: %s\n", (memcmp(ct1, ct2, PT_LEN) == 0) ? "YES" : "NO");
    printf("Tag match:        %s\n", (memcmp(tag1, tag2, TAG_LEN) == 0) ? "YES" : "NO");

    int dec_len1 = aes_ccm_decrypt(key, iv, aad, AAD_LEN, ct1, enc_len1, tag1, dec1, 0);
    int dec_len2 = aes_ccm_decrypt(key, iv, aad, AAD_LEN, ct2, enc_len2, tag2, dec2, chunk);
    dec1[PT_LEN] = '\0'; dec2[PT_LEN] = '\0';

    printf("\n--- Decrypt (single-shot CT) ---\n");
    printf("Decrypted: \"%.*s\"\n", dec_len1, dec1);
    printf("--- Decrypt (chunked CT) ---\n");
    printf("Decrypted: \"%.*s\"\n", dec_len2, dec2);

    printf("\nDecryption match: %s\n", (memcmp(pt, dec1, PT_LEN) == 0 && memcmp(pt, dec2, PT_LEN) == 0) ? "YES" : "NO");
    return 0;
}
