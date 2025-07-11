#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>

#define KEY_LEN    16
#define IV_LEN     12
#define TAG_LEN    16
#define PT_LEN     32
#define AAD_LEN    20

void print_hex(const char *label, const unsigned char *data, int len) {
    printf("%s:", label);
    for (int i = 0; i < len; i++) printf(" %02x", data[i]);
    printf("\n");
}

int aes_ccm_encrypt(
    const unsigned char *key,
    const unsigned char *iv,
    const unsigned char *aad, int aad_len,
    const unsigned char *pt, int pt_len,
    unsigned char *ct, unsigned char *tag,
    int chunk // if 0: single-shot, if >0: chunk size for updates
) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len, outlen = 0, tmplen = 0, ret = 0;

    if (!ctx) return -1;
    if (!EVP_EncryptInit_ex(ctx, EVP_aes_128_ccm(), NULL, NULL, NULL)) goto done;
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IVLEN, IV_LEN, NULL)) goto done;
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG, TAG_LEN, NULL)) goto done;
    if (!EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv)) goto done;
    if (!EVP_EncryptUpdate(ctx, NULL, &len, NULL, pt_len)) goto done; // must set PT length before AAD
    if (!EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len)) goto done; // add AAD

    if (chunk == 0) {
        // Single-shot: all plaintext at once
        if (!EVP_EncryptUpdate(ctx, ct, &outlen, pt, pt_len)) goto done;
    } else {
        // Chunk-based: process PT in blocks
        int offset = 0;
        outlen = 0;
        while (offset < pt_len) {
            int block = (pt_len - offset > chunk) ? chunk : (pt_len - offset);
            if (!EVP_EncryptUpdate(ctx, ct + offset, &tmplen, pt + offset, block)) goto done;
            outlen += tmplen;
            offset += block;
        }
    }

    if (!EVP_EncryptFinal_ex(ctx, ct + outlen, &len)) goto done;
    outlen += len;
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_GET_TAG, TAG_LEN, tag)) goto done;
    ret = outlen;

done:
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

int aes_ccm_decrypt(
    const unsigned char *key,
    const unsigned char *iv,
    const unsigned char *aad, int aad_len,
    const unsigned char *ct, int ct_len,
    const unsigned char *tag,
    unsigned char *pt,
    int chunk // if 0: single-shot, if >0: chunk size for updates
) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len, outlen = 0, tmplen = 0, ret = -1;

    if (!ctx) return -1;
    if (!EVP_DecryptInit_ex(ctx, EVP_aes_128_ccm(), NULL, NULL, NULL)) goto done;
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IVLEN, IV_LEN, NULL)) goto done;
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG, TAG_LEN, (void*)tag)) goto done;
    if (!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv)) goto done;
    if (!EVP_DecryptUpdate(ctx, NULL, &len, NULL, ct_len)) goto done; // must set CT length before AAD
    if (!EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len)) goto done; // add AAD

    if (chunk == 0) {
        // Single-shot: all ciphertext at once
        if (!EVP_DecryptUpdate(ctx, pt, &outlen, ct, ct_len)) goto done;
    } else {
        // Chunk-based: process CT in blocks
        int offset = 0;
        outlen = 0;
        while (offset < ct_len) {
            int block = (ct_len - offset > chunk) ? chunk : (ct_len - offset);
            if (!EVP_DecryptUpdate(ctx, pt + offset, &tmplen, ct + offset, block)) goto done;
            outlen += tmplen;
            offset += block;
        }
    }

    // In CCM, tag is checked during the final update, so no EVP_DecryptFinal_ex needed
    ret = outlen;
done:
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

int main() {
    unsigned char key[KEY_LEN] =   {0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81};
    unsigned char iv[IV_LEN] =     {0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb};
    unsigned char aad[AAD_LEN] =   "0123456789abcdefghij";
    unsigned char pt[PT_LEN]  =    "The quick brown fox jumps over lazy.";
    unsigned char ct1[PT_LEN], tag1[TAG_LEN];
    unsigned char ct2[PT_LEN], tag2[TAG_LEN];
    unsigned char dec1[PT_LEN], dec2[PT_LEN];
    int enc_len, dec_len;

    printf("\nAES-CCM, PT = \"%s\"\n", pt);
    print_hex("Key", key, KEY_LEN);
    print_hex("IV", iv, IV_LEN);
    print_hex("AAD", aad, AAD_LEN);

    // Encrypt, single-shot
    enc_len = aes_ccm_encrypt(key, iv, aad, AAD_LEN, pt, PT_LEN, ct1, tag1, 0);
    print_hex("CT (single-shot)", ct1, enc_len);
    print_hex("TAG (single-shot)", tag1, TAG_LEN);

    // Encrypt, chunked
    enc_len = aes_ccm_encrypt(key, iv, aad, AAD_LEN, pt, PT_LEN, ct2, tag2, 8);
    print_hex("CT (chunked)", ct2, enc_len);
    print_hex("TAG (chunked)", tag2, TAG_LEN);

    // Compare outputs
    printf("CT match: %s\n", (memcmp(ct1, ct2, PT_LEN)==0) ? "YES":"NO");
    printf("TAG match: %s\n", (memcmp(tag1, tag2, TAG_LEN)==0) ? "YES":"NO");

    // Decrypt, single-shot
    dec_len = aes_ccm_decrypt(key, iv, aad, AAD_LEN, ct1, PT_LEN, tag1, dec1, 0);
    printf("DEC (single-shot): %.*s\n", dec_len, dec1);

    // Decrypt, chunked
    dec_len = aes_ccm_decrypt(key, iv, aad, AAD_LEN, ct2, PT_LEN, tag2, dec2, 8);
    printf("DEC (chunked): %.*s\n", dec_len, dec2);

    // Compare decrypted outputs
    printf("Decryption match: %s\n", (memcmp(pt, dec1, PT_LEN)==0 && memcmp(pt, dec2, PT_LEN)==0) ? "YES":"NO");

    return 0;
}
