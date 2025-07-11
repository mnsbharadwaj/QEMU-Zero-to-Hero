#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>

#define KEY_LEN    16
#define IV_LEN     12
#define TAG_LEN    16
#define PT_LEN     40
#define AAD_LEN    20
#define CHUNK_SIZE 8

void print_hex(const char *label, const unsigned char *data, int len) {
    printf("%s:", label);
    for (int i = 0; i < len; i++) printf(" %02x", data[i]);
    printf("\n");
}

// Single-shot CCM encryption
int aes_ccm_encrypt_singleshot(
    const unsigned char *key, const unsigned char *iv,
    const unsigned char *aad, int aad_len,
    const unsigned char *pt, int pt_len,
    unsigned char *ct, unsigned char *tag
) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len, ret = 0;
    if (!ctx) return -1;
    if (!EVP_EncryptInit_ex(ctx, EVP_aes_128_ccm(), NULL, NULL, NULL)) goto done;
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IVLEN, IV_LEN, NULL)) goto done;
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG, TAG_LEN, NULL)) goto done;
    if (!EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv)) goto done;
    if (!EVP_EncryptUpdate(ctx, NULL, &len, NULL, pt_len)) goto done;  // Set expected PT length
    if (!EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len)) goto done;
    if (!EVP_EncryptUpdate(ctx, ct, &len, pt, pt_len)) goto done;
    if (!EVP_EncryptFinal_ex(ctx, ct + len, &len)) goto done;  // CCM: no-op
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_GET_TAG, TAG_LEN, tag)) goto done;
    ret = pt_len;
done:
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

// Multi-block (chunked) CCM encryption (chunk both AAD and PT)
int aes_ccm_encrypt_chunked(
    const unsigned char *key, const unsigned char *iv,
    const unsigned char *aad, int aad_len,
    const unsigned char *pt, int pt_len,
    unsigned char *ct, unsigned char *tag,
    int chunk_size
) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len, tmplen = 0, outlen = 0, ret = 0;
    if (!ctx) return -1;
    if (!EVP_EncryptInit_ex(ctx, EVP_aes_128_ccm(), NULL, NULL, NULL)) goto done;
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IVLEN, IV_LEN, NULL)) goto done;
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG, TAG_LEN, NULL)) goto done;
    if (!EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv)) goto done;
    if (!EVP_EncryptUpdate(ctx, NULL, &len, NULL, pt_len)) goto done;

    // Chunk AAD
    int aad_offset = 0;
    while (aad_offset < aad_len) {
        int chunk = (aad_len - aad_offset > chunk_size) ? chunk_size : (aad_len - aad_offset);
        if (!EVP_EncryptUpdate(ctx, NULL, &tmplen, aad + aad_offset, chunk)) goto done;
        aad_offset += chunk;
    }

    // Chunk PT
    int pt_offset = 0;
    outlen = 0;
    while (pt_offset < pt_len) {
        int chunk = (pt_len - pt_offset > chunk_size) ? chunk_size : (pt_len - pt_offset);
        if (!EVP_EncryptUpdate(ctx, ct + pt_offset, &tmplen, pt + pt_offset, chunk)) goto done;
        outlen += tmplen;
        pt_offset += chunk;
    }

    if (!EVP_EncryptFinal_ex(ctx, ct + outlen, &len)) goto done;
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_GET_TAG, TAG_LEN, tag)) goto done;
    ret = outlen;
done:
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

// CCM decryption (supports both single-shot and chunked; just choose chunk_size)
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

    // Chunk AAD
    int aad_offset = 0;
    while (aad_offset < aad_len) {
        int chunk = (aad_len - aad_offset > chunk_size) ? chunk_size : (aad_len - aad_offset);
        if (!EVP_DecryptUpdate(ctx, NULL, &tmplen, aad + aad_offset, chunk)) goto done;
        aad_offset += chunk;
    }

    // Chunk CT
    int ct_offset = 0;
    outlen = 0;
    while (ct_offset < ct_len) {
        int chunk = (ct_len - ct_offset > chunk_size) ? chunk_size : (ct_len - ct_offset);
        if (!EVP_DecryptUpdate(ctx, pt + ct_offset, &tmplen, ct + ct_offset, chunk)) goto done;
        outlen += tmplen;
        ct_offset += chunk;
    }

    // For CCM, tag is checked during update, no final needed.
    ret = outlen;
done:
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

int main() {
    unsigned char key[KEY_LEN] = {0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81};
    unsigned char iv[IV_LEN]   = {0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb};
    unsigned char aad[AAD_LEN] = "0123456789abcdefghij";
    unsigned char pt[PT_LEN]   = "The quick brown fox jumps over lazy d0gs!";

    unsigned char ct_single[PT_LEN], tag_single[TAG_LEN];
    unsigned char ct_chunk[PT_LEN], tag_chunk[TAG_LEN];
    unsigned char dec_single[PT_LEN+1], dec_chunk[PT_LEN+1];

    int ctlen1 = 0, ctlen2 = 0, declen1 = 0, declen2 = 0;

    printf("\n===== AES-CCM Demo: Single-shot vs Chunked =====\n");
    printf("Plaintext: \"%.*s\"\n", PT_LEN, pt);
    print_hex("Key", key, KEY_LEN);
    print_hex("IV", iv, IV_LEN);
    print_hex("AAD", aad, AAD_LEN);

    // Single-shot encryption
    ctlen1 = aes_ccm_encrypt_singleshot(key, iv, aad, AAD_LEN, pt, PT_LEN, ct_single, tag_single);
    print_hex("\nCiphertext (single-shot)", ct_single, ctlen1);
    print_hex("Tag (single-shot)", tag_single, TAG_LEN);

    // Chunked encryption
    ctlen2 = aes_ccm_encrypt_chunked(key, iv, aad, AAD_LEN, pt, PT_LEN, ct_chunk, tag_chunk, CHUNK_SIZE);
    print_hex("\nCiphertext (chunked)", ct_chunk, ctlen2);
    print_hex("Tag (chunked)", tag_chunk, TAG_LEN);

    // Verify ciphertext and tag equality
    printf("\nCiphertext match: %s\n", (memcmp(ct_single, ct_chunk, PT_LEN) == 0) ? "YES" : "NO");
    printf("Tag match:        %s\n", (memcmp(tag_single, tag_chunk, TAG_LEN) == 0) ? "YES" : "NO");

    // Decrypt and check
    declen1 = aes_ccm_decrypt(key, iv, aad, AAD_LEN, ct_single, ctlen1, tag_single, dec_single, PT_LEN); // singleshot
    declen2 = aes_ccm_decrypt(key, iv, aad, AAD_LEN, ct_chunk, ctlen2, tag_chunk, dec_chunk, CHUNK_SIZE); // chunked
    dec_single[PT_LEN] = '\0'; dec_chunk[PT_LEN] = '\0';

    printf("\nDecrypted (from single-shot CT): \"%.*s\"\n", declen1, dec_single);
    printf("Decrypted (from chunked CT):     \"%.*s\"\n", declen2, dec_chunk);

    printf("\nDecryption match: %s\n", (memcmp(pt, dec_single, PT_LEN) == 0 && memcmp(pt, dec_chunk, PT_LEN) == 0) ? "YES" : "NO");
    return 0;
}
