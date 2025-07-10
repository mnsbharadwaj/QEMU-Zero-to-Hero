#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tomcrypt.h>

int aes_ccm_encrypt_chunked(
    const unsigned char *key,   unsigned long keylen,
    const unsigned char *nonce, unsigned long noncelen,
    const unsigned char *aad,   unsigned long aadlen,
    const unsigned char *pt,    unsigned long ptlen,
    unsigned char       *ct,
    unsigned char       *tag,   unsigned long taglen)
{
    int         err, idx;
    ccm_state   ccm;
    unsigned long left, chunk, outlen;

    /* 1) find the AES cipher */
    if ((idx = find_cipher("aes")) < 0) return CRYPT_INVALID_CIPHER;

    /* 2) init: (ccm, cipher_idx, key, keylen, ptlen, taglen, aadlen) */
    if ((err = ccm_init(&ccm, idx,
                        key,   (int)keylen,
                        (int)ptlen,
                        (int)taglen,
                        (int)aadlen)) != CRYPT_OK) {
        return err;
    }

    /* 3) supply the nonce/IV */
    if ((err = ccm_add_nonce(&ccm, nonce, noncelen)) != CRYPT_OK) {
        return err;
    }

    /* 4) feed AAD in 16-byte chunks */
    left = aadlen;
    while (left) {
        chunk = left > 16 ? 16 : left;
        if ((err = ccm_add_aad(&ccm, aad + (aadlen - left), chunk)) != CRYPT_OK) {
            return err;
        }
        left -= chunk;
    }

    /* 5) encrypt plaintext in 16-byte chunks */
    left = ptlen;
    while (left) {
        chunk  = left > 16 ? 16 : left;
        outlen = chunk;
        if ((err = ccm_process(&ccm,
                               pt + (ptlen - left),
                               ct + (ptlen - left),
                               &outlen)) != CRYPT_OK) {
            return err;
        }
        left -= outlen;
    }

    /* 6) finalize & get tag */
    outlen = taglen;
    if ((err = ccm_done(&ccm, tag, &outlen)) != CRYPT_OK) {
        return err;
    }

    /* 7) if you need to reuse this context, you can call ccm_reset(&ccm) */
    return CRYPT_OK;
}

/* Example driver */
int main(void)
{
    unsigned char key[16]   = {0};
    unsigned char nonce[12] = {0};
    const char *aad_data = "Hello AAD, feed me in pieces!";
    const char *pt_data  = "The quick brown fox...";
    unsigned long aadlen = strlen(aad_data), ptlen = strlen(pt_data);
    unsigned char *ct = malloc(ptlen), tag[16];
    int err;

    if ((err = aes_ccm_encrypt_chunked(
             key, sizeof(key),
             nonce, sizeof(nonce),
             (unsigned char*)aad_data, aadlen,
             (unsigned char*)pt_data,  ptlen,
             ct, tag, sizeof(tag))) != CRYPT_OK) {
        printf("AES-CCM error: %s\n", error_to_string(err));
        return 1;
    }

    printf("Ciphertext + tag generated successfully.\n");
    free(ct);
    return 0;
}
