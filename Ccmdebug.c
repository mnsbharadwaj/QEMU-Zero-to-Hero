#include <tomcrypt.h>
#include <stdio.h>
#include <string.h>

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
    if ((err = ccm_init(&ccm, idx, key, keylen, ptlen, taglen, aadlen)) != CRYPT_OK) return err;
    if ((err = ccm_add_nonce(&ccm, nonce, noncelen)) != CRYPT_OK) return err;

    offset = 0;
    while (offset < aadlen) {
        chunk = (aadlen - offset > 16) ? 16 : (aadlen - offset);
        if ((err = ccm_add_aad(&ccm, aad + offset, chunk)) != CRYPT_OK) return err;
        offset += chunk;
    }

    offset = 0;
    while (offset < ptlen) {
        chunk = (ptlen - offset > 16) ? 16 : (ptlen - offset);
        if ((err = ccm_process(&ccm, (unsigned char*)(pt + offset), chunk, ct + offset, CCM_ENCRYPT)) != CRYPT_OK) return err;
        offset += chunk;
    }

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
        if ((err = ccm_process(&ccm, (unsigned char*)(ct + offset), chunk, pt + offset, CCM_DECRYPT)) != CRYPT_OK) return err;
        offset += chunk;
    }

    err = ccm_done(&ccm, (unsigned char*)tag, &tag_stat);
    printf("Tag stat: %lu\n", tag_stat);
    if (err != CRYPT_OK) return err;
    if (tag_stat != 1) {
        printf("Tag verification failed!\n");
        return CRYPT_ERROR;
    }

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

    printf("Encrypted tag: ");
    for (int i = 0; i < sizeof(tag); i++) {
        printf("%02X ", tag[i]);
    }
    printf("\n");

    if ((err = aes_ccm_decrypt_chunked(key, sizeof(key), nonce, sizeof(nonce),
            (unsigned char*)aad_data, aadlen, ct, ptlen, pt2, tag, sizeof(tag))) != CRYPT_OK) {
        printf("Decryption error: %s\n", error_to_string(err));
        free(ct); free(pt2); return 1;
    }

    printf("Decrypted text: %.*s\n", (int)ptlen, pt2);

    free(ct); free(pt2);
    return 0;
}
