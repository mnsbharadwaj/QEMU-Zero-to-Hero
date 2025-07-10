#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tomcrypt.h>

/*
 * AES-CCM encryption in multiple chunks (e.g. DMA or register-sized transfers)
 */
int aes_ccm_encrypt_chunked(const unsigned char *key, unsigned long keylen,
                            const unsigned char *nonce, unsigned long noncelen,
                            const unsigned char *aad, unsigned long aadlen,
                            const unsigned char *pt, unsigned long ptlen,
                            unsigned char *ct,
                            unsigned char *tag, unsigned long taglen)
{
    int err, idx;
    ccm_state ccm;

    /* 1. Find AES cipher index */
    if ((idx = find_cipher("aes")) < 0) {
        return CRYPT_INVALID_CIPHER;
    }

    /* 2. Initialize CCM (new API) */
    if ((err = ccm_init(&ccm, idx,
                        key,   keylen,
                        nonce, noncelen,
                        aadlen, ptlen,
                        taglen)) != CRYPT_OK) {
        return err;
    }

    /* 3. Feed AAD in chunks */
    unsigned long remaining = aadlen;
    const unsigned char *pa = aad;
    while (remaining) {
        unsigned long chunk = remaining > 16 ? 16 : remaining;
        if ((err = ccm_add_aad(&ccm, pa, chunk)) != CRYPT_OK) {
            return err;
        }
        pa        += chunk;
        remaining -= chunk;
    }

    /* 4. Encrypt plaintext in chunks */
    remaining = ptlen;
    const unsigned char *pin = pt;
    unsigned char *cout = ct;
    while (remaining) {
        unsigned long chunk = remaining > 16 ? 16 : remaining;
        unsigned long outlen = chunk;
        if ((err = ccm_encrypt(&ccm, pin, cout, &outlen)) != CRYPT_OK) {
            return err;
        }
        pin        += outlen;
        cout       += outlen;
        remaining  -= outlen;
    }

    /* 5. Finalize and get tag */
    unsigned long outlen = taglen;
    if ((err = ccm_done(&ccm, tag, &outlen)) != CRYPT_OK) {
        return err;
    }

    /* 6. Wipe key schedule */
    cipher_descriptor[idx].done(&ccm.key);

    return CRYPT_OK;
}

/*
 * AES-CCM decryption in multiple chunks
 */
int aes_ccm_decrypt_chunked(const unsigned char *key, unsigned long keylen,
                            const unsigned char *nonce, unsigned long noncelen,
                            const unsigned char *aad, unsigned long aadlen,
                            const unsigned char *ct, unsigned long ctlen,
                            unsigned char *pt,
                            const unsigned char *tag, unsigned long taglen)
{
    int err, idx;
    ccm_state ccm;

    /* 1. Find AES cipher index */
    if ((idx = find_cipher("aes")) < 0) {
        return CRYPT_INVALID_CIPHER;
    }

    /* 2. Initialize CCM for decryption */
    if ((err = ccm_init(&ccm, idx,
                        key,   keylen,
                        nonce, noncelen,
                        aadlen, ctlen,
                        taglen)) != CRYPT_OK) {
        return err;
    }

    /* 3. Feed AAD in chunks */
    unsigned long remaining = aadlen;
    const unsigned char *pa = aad;
    while (remaining) {
        unsigned long chunk = remaining > 16 ? 16 : remaining;
        if ((err = ccm_add_aad(&ccm, pa, chunk)) != CRYPT_OK) {
            return err;
        }
        pa        += chunk;
        remaining -= chunk;
    }

    /* 4. Decrypt ciphertext in chunks */
    remaining = ctlen;
    const unsigned char *cin = ct;
    unsigned char *pout = pt;
    while (remaining) {
        unsigned long chunk = remaining > 16 ? 16 : remaining;
        unsigned long outlen = chunk;
        if ((err = ccm_decrypt(&ccm, cin, pout, &outlen)) != CRYPT_OK) {
            return err;
        }
        cin        += outlen;
        pout       += outlen;
        remaining  -= outlen;
    }

    /* 5. Verify tag */
    unsigned long stat = 0;
    if ((err = ccm_done(&ccm, (unsigned char *)tag, &stat)) != CRYPT_OK) {
        return err;
    }
    if (stat != 1) {
        return CRYPT_INVALID_PACKET;
    }

    /* 6. Wipe key schedule */
    cipher_descriptor[idx].done(&ccm.key);

    return CRYPT_OK;
}

int main(void)
{
    /* Example key, nonce, AAD, and plaintext */
    unsigned char key[16]   = { 0x00,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15 };
    unsigned char nonce[12] = { 0xA0,1,2,3,4,5,6,7,8,9,10,11 };
    const char *aad_data = "Example AAD for AES-CCM in multiple chunks.";
    const char *pt_data  = "Hello, AES-CCM chunked encryption!";

    unsigned long aadlen = strlen(aad_data);
    unsigned long ptlen  = strlen(pt_data);

    unsigned char *ct  = malloc(ptlen);
    unsigned char *pt2 = malloc(ptlen);
    unsigned char  tag[16];
    int err;

    /* Encrypt */
    if ((err = aes_ccm_encrypt_chunked(key, sizeof key,
                                       nonce, sizeof nonce,
                                       (unsigned char*)aad_data, aadlen,
                                       (unsigned char*)pt_data, ptlen,
                                       ct, tag, sizeof tag)) != CRYPT_OK) {
        printf("Encryption error: %s\n", error_to_string(err));
        return 1;
    }

    /* Print ciphertext + tag */
    printf("Ciphertext: ");
    for (unsigned long i = 0; i < ptlen; i++) printf("%02X ", ct[i]);
    printf("\nTag: ");
    for (unsigned long i = 0; i < sizeof tag; i++) printf("%02X ", tag[i]);
    printf("\n\n");

    /* Decrypt */
    if ((err = aes_ccm_decrypt_chunked(key, sizeof key,
                                       nonce, sizeof nonce,
                                       (unsigned char*)aad_data, aadlen,
                                       ct, ptlen,
                                       pt2, tag, sizeof tag)) != CRYPT_OK) {
        printf("Decryption failed: %s\n", error_to_string(err));
        free(ct); free(pt2);
        return 1;
    }

    /* Print decrypted text */
    printf("Decrypted: %.*s\n", (int)ptlen, pt2);

    free(ct);
    free(pt2);
    return 0;
}
