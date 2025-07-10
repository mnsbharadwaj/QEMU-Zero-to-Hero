#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tomcrypt.h>

/* 
 * Chunked AES-CCM encrypt:
 *  - key:        raw AES key
 *  - keylen:     length of key in bytes (16/24/32)
 *  - nonce:      unique nonce/IV
 *  - noncelen:   length of nonce (7..13 bytes per RFC 3610)
 *  - aad:        pointer to AAD
 *  - aadlen:     total AAD length
 *  - pt:         pointer to plaintext
 *  - ptlen:      total plaintext length
 *  - ct:         buffer for ciphertext (same length as pt)
 *  - tag:        output buffer for authentication tag
 *  - taglen:     desired tag length (e.g. 8 or 16)
 */
int aes_ccm_encrypt_chunked(const unsigned char *key,  unsigned long keylen,
                            const unsigned char *nonce, unsigned long noncelen,
                            const unsigned char *aad,  unsigned long aadlen,
                            const unsigned char *pt,   unsigned long ptlen,
                            unsigned char *ct,
                            unsigned char *tag,        unsigned long taglen) 
{
    int err, idx;
    symmetric_CCM ccm;
    unsigned long x;

    /* 1. Find & setup AES cipher */
    if ((err = cipher_descriptor[idx = find_cipher("aes")].setup(
             key, keylen, 0, &ccm.key)) != CRYPT_OK) {
        return err;
    }

    /* 2. Initialize CCM state */
    if ((err = ccm_start(&ccm, idx, nonce, noncelen, taglen, ptlen, aadlen))
        != CRYPT_OK) {
        return err;
    }

    /* 3. Feed AAD in chunks */
    {
        const unsigned char *p = aad;
        unsigned long remaining = aadlen, chunk;
        while (remaining) {
            chunk = remaining > 16 ? 16 : remaining;
            if ((err = ccm_add_aad(&ccm, p, chunk)) != CRYPT_OK) {
                return err;
            }
            p        += chunk;
            remaining -= chunk;
        }
    }

    /* 4. Encrypt plaintext in chunks */
    {
        const unsigned char *pin = pt;
        unsigned char *cout = ct;
        unsigned long remaining = ptlen, chunk;
        while (remaining) {
            chunk = remaining > 16 ? 16 : remaining;
            x = chunk;
            if ((err = ccm_encrypt(&ccm, pin, cout, &x)) != CRYPT_OK) {
                return err;
            }
            pin        += x;
            cout       += x;
            remaining  -= x;
        }
    }

    /* 5. Finalize and get tag */
    x = taglen;
    if ((err = ccm_done(&ccm, tag, &x)) != CRYPT_OK) {
        return err;
    }

    /* 6. Clean up key schedule */
    cipher_descriptor[idx].done(&ccm.key);

    return CRYPT_OK;
}

/* 
 * Chunked AES-CCM decrypt:
 *  - parameters same as encrypt, except:
 *    - ct: ciphertext input
 *    - pt: plaintext output
 *    - tag: authentication tag received
 */
int aes_ccm_decrypt_chunked(const unsigned char *key, unsigned long keylen,
                            const unsigned char *nonce, unsigned long noncelen,
                            const unsigned char *aad, unsigned long aadlen,
                            const unsigned char *ct,  unsigned long ctlen,
                            unsigned char *pt,
                            const unsigned char *tag, unsigned long taglen) 
{
    int err, idx;
    symmetric_CCM ccm;
    unsigned long x;

    if ((err = cipher_descriptor[idx = find_cipher("aes")].setup(
             key, keylen, 0, &ccm.key)) != CRYPT_OK) {
        return err;
    }

    if ((err = ccm_start(&ccm, idx, nonce, noncelen, taglen, ctlen, aadlen))
        != CRYPT_OK) {
        return err;
    }

    /* AAD */
    {
        const unsigned char *p = aad;
        unsigned long remaining = aadlen, chunk;
        while (remaining) {
            chunk = remaining > 16 ? 16 : remaining;
            if ((err = ccm_add_aad(&ccm, p, chunk)) != CRYPT_OK) {
                return err;
            }
            p        += chunk;
            remaining -= chunk;
        }
    }

    /* Decrypt */
    {
        const unsigned char *cin = ct;
        unsigned char *pout = pt;
        unsigned long remaining = ctlen, chunk;
        while (remaining) {
            chunk = remaining > 16 ? 16 : remaining;
            x = chunk;
            if ((err = ccm_decrypt(&ccm, cin, pout, &x)) != CRYPT_OK) {
                return err;
            }
            cin        += x;
            pout       += x;
            remaining  -= x;
        }
    }

    /* Check tag */
    if ((err = ccm_done(&ccm, (unsigned char *)tag, &x)) != CRYPT_OK) {
        return err;
    }

    cipher_descriptor[idx].done(&ccm.key);
    return CRYPT_OK;
}

/* Example driver: */
int main(void)
{
    /* sample 128-bit key & nonce */
    unsigned char key[16]   = { 0x00,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15 };
    unsigned char nonce[12] = { 0xA0,1,2,3,4,5,6,7,8,9,10,11 };

    /* sample AAD & message */
    const char *aad_data = "This is some AAD that we feed in chunks...";
    const char *pt_data  = "The quick brown fox jumps over the lazy dog";

    unsigned long aadlen = (unsigned long)strlen(aad_data);
    unsigned long ptlen  = (unsigned long)strlen(pt_data);

    unsigned char *ct = malloc(ptlen), *pt = malloc(ptlen);
    unsigned char  tag[16];
    int            err;

    /* Encrypt */
    if ((err = aes_ccm_encrypt_chunked(key, sizeof key,
                                       nonce, sizeof nonce,
                                       (unsigned char*)aad_data, aadlen,
                                       (unsigned char*)pt_data, ptlen,
                                       ct, tag, sizeof tag)) != CRYPT_OK) {
        printf("Encryption error: %s\n", error_to_string(err));
        return 1;
    }

    printf("Ciphertext (%lu bytes) + Tag:\n", ptlen);
    for (unsigned long i = 0; i < ptlen; i++)   printf("%02X ", ct[i]);
    printf("\nTag: ");
    for (unsigned long i = 0; i < sizeof tag; i++) printf("%02X ", tag[i]);
    printf("\n\n");

    /* Decrypt */
    if ((err = aes_ccm_decrypt_chunked(key, sizeof key,
                                       nonce, sizeof nonce,
                                       (unsigned char*)aad_data, aadlen,
                                       ct, ptlen,
                                       pt, tag, sizeof tag)) != CRYPT_OK) {
        printf("Decryption failed (bad tag?): %s\n", error_to_string(err));
        return 1;
    }

    printf("Decrypted text: %.*s\n", (int)ptlen, pt);

    free(ct); free(pt);
    return 0;
}
