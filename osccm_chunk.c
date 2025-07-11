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

int aes_ccm_encrypt_chunked(
    const unsigned char *key, const unsigned char *iv,
    const unsigned char *aad, int aad_len,
    const unsigned char *pt, int pt_len,
    unsigned char *ct, unsigned char *tag,
    int chunk_size
) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len, tmplen = 0, outlen = 0, ret = -1;
    if (!ctx) return -1;
    if (!EVP_EncryptInit_ex(ctx, EVP_aes_128_ccm(), NULL, NULL, NULL)) goto done;
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IVLEN, IV_LEN, NULL)) goto done;
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG, TAG_LEN, NULL)) goto done;
    if (!EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv)) goto done;
    // Tell OpenSSL how many PT bytes to expect
    if (!EVP_EncryptUpdate(ctx, NULL, &len, NULL, pt_len)) goto done;
    // Feed all AAD in one call
    if (!EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len)) goto done;
    // Now feed PT in N chunks
    int offset = 0;
    outlen = 0;
    while (offset < pt_len) {
        int chunk = (pt_len - offset > chunk_size) ? chunk_size : (pt_len - offset);
        printf("  Encrypt chunk offset %2d, len %2d\n", offset, chunk);
        if (!EVP_EncryptUpdate(ctx, ct + offset, &tmplen, pt + offset, chunk)) goto done;
        outlen += tmplen;
        offset += chunk;
    }
    if (!EVP_EncryptFinal_ex(ctx, ct + outlen, &len)) goto done;
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_GET_TAG, TAG_LEN, tag)) goto done;
    ret = outlen;
done:
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

int aes_ccm_decrypt_chunked(
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
    // Tell OpenSSL how many CT bytes to expect
    if (!EVP_DecryptUpdate(ctx, NULL, &len, NULL, ct_len)) goto done;
    // Feed all AAD in one call (just like encryption)
    if (!EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len)) goto done;
    // Now feed CT in N chunks
    int offset = 0;
    outlen = 0;
    while (offset < ct_len) {
        int chunk = (ct_len - offset > chunk_size) ? chunk_size : (ct_len - offset);
        printf("  Decrypt chunk offset %2d, len %2d\n", offset, chunk);
        if (!EVP_DecryptUpdate(ctx, pt + offset, &tmplen, ct + offset, chunk)) goto done;
        outlen += tmplen;
        offset += chunk;
    }
    ret = outlen;
done:
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

int main() {
    unsigned char ct[PT_LEN], tag[TAG_LEN], dec[PT_LEN+1];
    int chunk = CHUNK_SIZE;

    printf("\n--- AES-CCM Chunked Encrypt/Decrypt, chunk size = %d ---\n", chunk);
    int enc_len = aes_ccm_encrypt_chunked(key, iv, aad, AAD_LEN, pt, PT_LEN, ct, tag, chunk);
    print_hex("CT", ct, enc_len);
    print_hex("TAG", tag, TAG_LEN);

    int dec_len = aes_ccm_decrypt_chunked(key, iv, aad, AAD_LEN, ct, enc_len, tag, dec, chunk);
    dec[dec_len] = '\0';

    printf("Decrypted: \"%.*s\"\n", dec_len, dec);
    printf("\nDecryption match: %s\n", (dec_len == PT_LEN && memcmp(pt, dec, PT_LEN) == 0) ? "YES" : "NO");
    return 0;
}
