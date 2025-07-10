
// NIST Example from SP 800-38C, F.2.5
unsigned char key[16]   = {0xc0,0xc1,0xc2,0xc3,0xc4,0xc5,0xc6,0xc7,0xc8,0xc9,0xca,0xcb,0xcc,0xcd,0xce,0xcf};
unsigned char nonce[13] = {0x00,0x03,0x02,0x01,0x00,0xa0,0xa1,0xa2,0xa3,0xa4,0xa5,0xa6,0xa7};
unsigned char aad[8]    = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07};
unsigned char pt[23]    = {0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e};
unsigned char expected_ct[23] = {0x58,0x8c,0x97,0x9a,0x61,0xc6,0x63,0xd2,0xf0,0x66,0xd0,0xc2,0xc0,0xf9,0x89,0x80,0x6d,0x5f,0x6b,0x61,0xda,0xc3,0x84};
unsigned char expected_tag[16] = {0x17,0xe8,0xd1,0x2c,0xfd,0xf9,0x26,0xe0,0x8c,0xd0,0x8b,0xef,0x7f,0x42,0x97,0x6d};
// Set lengths accordingly.

#include <tomcrypt.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int aes_ccm_encrypt_chunked(
    const unsigned char *key, unsigned long keylen,
    const unsigned char *nonce, unsigned long noncelen,
    const unsigned char *aad, unsigned long aadlen,
    const unsigned char *pt, unsigned long ptlen,
    unsigned char *ct,
    unsigned char *tag, unsigned long taglen)
{
    int err, idx;
    ccm_state ccm;
    unsigned long offset, chunk;

    if ((idx = find_cipher("aes")) < 0) return CRYPT_INVALID_CIPHER;

    // 1. CCM init
    if ((err = ccm_init(&ccm, idx, key, keylen, ptlen, taglen, aadlen)) != CRYPT_OK) return err;

    // 2. Feed nonce
    if ((err = ccm_add_nonce(&ccm, nonce, noncelen)) != CRYPT_OK) return err;

    // 3. Feed AAD in chunks
    offset = 0;
    while (offset < aadlen) {
        chunk = (aadlen - offset > 16) ? 16 : (aadlen - offset);
        if ((err = ccm_add_aad(&ccm, aad + offset, chunk)) != CRYPT_OK) return err;
        offset += chunk;
    }

    // 4. Encrypt in chunks
    offset = 0;
    while (offset < ptlen) {
        chunk = (ptlen - offset > 16) ? 16 : (ptlen - offset);
        if ((err = ccm_process(&ccm, pt + offset, ct + offset, chunk, CCM_ENCRYPT)) != CRYPT_OK) return err;
        offset += chunk;
    }

    // 5. Finish, get tag
    if ((err = ccm_done(&ccm, tag, &taglen)) != CRYPT_OK) return err;

    return CRYPT_OK;
}

int aes_ccm_decrypt_chunked(
    const unsigned char *key, unsigned long keylen,
    const unsigned char *nonce, unsigned long noncelen,
    const unsigned char *aad, unsigned long aadlen,
    const unsigned char *ct, unsigned long ctlen,
    unsigned char *pt,
    const unsigned char *tag, unsigned long taglen)
{
    int err, idx;
    ccm_state ccm;
    unsigned long offset, chunk;
    unsigned long tag_stat = 0;

    if ((idx = find_cipher("aes")) < 0) return CRYPT_INVALID_CIPHER;

    if ((err = ccm_init(&ccm, idx, key, keylen, ctlen, taglen, aadlen)) != CRYPT_OK) return err;

    if ((err = ccm_add_nonce(&ccm, nonce, noncelen)) != CRYPT_OK) return err;

    offset = 0;
    while (offset < aadlen) {
        chunk = (aadlen - offset > 16) ? 16 : (aadlen - offset);
        if ((err = ccm_add_aad(&ccm, aad + offset, chunk)) != CRYPT_OK) return err;
        offset += chunk;
    }

    offset = 0;
    while (offset < ctlen) {
        chunk = (ctlen - offset > 16) ? 16 : (ctlen - offset);
        if ((err = ccm_process(&ccm, ct + offset, pt + offset, chunk, CCM_DECRYPT)) != CRYPT_OK) return err;
        offset += chunk;
    }

    // Tag verification
    if ((err = ccm_done(&ccm, (unsigned char*)tag, &tag_stat)) != CRYPT_OK) return err;
    if (tag_stat != 1) return CRYPT_ERROR;

    return CRYPT_OK;
}

int main(void)
{
    unsigned char key[16]   = {0};
    unsigned char nonce[12] = {0};
    const char *aad_data = "CCM multi-block AAD test";
    const char *pt_data  = "Hello CCM chunked world!";
    unsigned long aadlen = strlen(aad_data);
    unsigned long ptlen  = strlen(pt_data);
    unsigned char *ct = calloc(ptlen, 1), *pt2 = calloc(ptlen, 1), tag[16];
    int err;

    if ((err = aes_ccm_encrypt_chunked(key, sizeof(key), nonce, sizeof(nonce),
            (unsigned char*)aad_data, aadlen, (unsigned char*)pt_data, ptlen, ct, tag, sizeof(tag))) != CRYPT_OK) {
        printf("Encryption error: %s\n", error_to_string(err));
        return 1;
    }

    printf("Ciphertext: "); for (unsigned long i = 0; i < ptlen; i++) printf("%02X ", ct[i]);
    printf("\nTag: "); for (unsigned long i = 0; i < sizeof(tag); i++) printf("%02X ", tag[i]); printf("\n");

    if ((err = aes_ccm_decrypt_chunked(key, sizeof(key), nonce, sizeof(nonce),
            (unsigned char*)aad_data, aadlen, ct, ptlen, pt2, tag, sizeof(tag))) != CRYPT_OK) {
        printf("Decryption error: %s\n", error_to_string(err));
        free(ct); free(pt2); return 1;
    }

    printf("Decrypted: %.*s\n", (int)ptlen, pt2);

    free(ct); free(pt2);
    return 0;
}
