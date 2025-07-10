#include <tomcrypt.h>
#include <stdio.h>
#include <string.h>

void handle_error(const char* msg, int err) {
    fprintf(stderr, "%s: %s\n", msg, error_to_string(err));
    exit(EXIT_FAILURE);
}

int constant_time_compare(const void *a, const void *b, size_t len) {
    const unsigned char *pa = a;
    const unsigned char *pb = b;
    unsigned char diff = 0;
    
    for (size_t i = 0; i < len; i++) {
        diff |= pa[i] ^ pb[i];
    }
    
    return diff;
}

void print_hex(const char* label, const unsigned char* data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02X", data[i]);
    }
    printf("\n");
}

int aes_ccm_encrypt(
    const unsigned char* key, unsigned long keylen,
    const unsigned char* nonce, unsigned long noncelen,
    const unsigned char* header, unsigned long headerlen,
    const unsigned char* pt, unsigned long ptlen,
    unsigned char* ct,
    unsigned char* tag, unsigned long taglen
) {
    ccm_state ccm;
    int err;
    int cipher_idx = find_cipher("aes");
    if (cipher_idx == -1) return CRYPT_INVALID_CIPHER;

    // Debug print inputs
    printf("\n[ENCRYPTION INPUTS]\n");
    print_hex("Key", key, keylen);
    print_hex("Nonce", nonce, noncelen);
    print_hex("Header", header, headerlen);
    print_hex("Plaintext", pt, ptlen);
    printf("Taglen: %lu\n", taglen);

    // Initialize CCM
    if ((err = ccm_init(&ccm, cipher_idx, key, keylen, ptlen, taglen, headerlen)) != CRYPT_OK)
        return err;
    
    if ((err = ccm_add_nonce(&ccm, nonce, noncelen)) != CRYPT_OK)
        return err;
    
    if (headerlen > 0 && (err = ccm_add_aad(&ccm, header, headerlen)) != CRYPT_OK)
        return err;
    
    if ((err = ccm_process(&ccm, pt, ptlen, ct, CCM_ENCRYPT)) != CRYPT_OK)
        return err;
    
    unsigned long final_taglen = taglen;
    if ((err = ccm_done(&ccm, tag, &final_taglen)) != CRYPT_OK)
        return err;
    
    // Debug print results
    printf("\n[ENCRYPTION RESULTS]\n");
    print_hex("Ciphertext", ct, ptlen);
    print_hex("Tag", tag, taglen);
    
    return CRYPT_OK;
}

int aes_ccm_decrypt(
    const unsigned char* key, unsigned long keylen,
    const unsigned char* nonce, unsigned long noncelen,
    const unsigned char* header, unsigned long headerlen,
    const unsigned char* ct, unsigned long ctlen,
    unsigned char* pt,
    const unsigned char* tag, unsigned long taglen
) {
    ccm_state ccm;
    int err;
    unsigned char tagbuf[16];
    unsigned long tagbuflen = taglen;
    int cipher_idx = find_cipher("aes");
    if (cipher_idx == -1) return CRYPT_INVALID_CIPHER;

    // Debug print inputs
    printf("\n[DECRYPTION INPUTS]\n");
    print_hex("Key", key, keylen);
    print_hex("Nonce", nonce, noncelen);
    print_hex("Header", header, headerlen);
    print_hex("Ciphertext", ct, ctlen);
    print_hex("Tag", tag, taglen);
    printf("Taglen: %lu\n", taglen);

    // Initialize CCM
    if ((err = ccm_init(&ccm, cipher_idx, key, keylen, ctlen, taglen, headerlen)) != CRYPT_OK)
        return err;
    
    if ((err = ccm_add_nonce(&ccm, nonce, noncelen)) != CRYPT_OK)
        return err;
    
    if (headerlen > 0 && (err = ccm_add_aad(&ccm, header, headerlen)) != CRYPT_OK)
        return err;
    
    if ((err = ccm_process(&ccm, ct, ctlen, pt, CCM_DECRYPT)) != CRYPT_OK)
        return err;
    
    if ((err = ccm_done(&ccm, tagbuf, &tagbuflen)) != CRYPT_OK)
        return err;
    
    // Debug print results
    printf("\n[DECRYPTION RESULTS]\n");
    print_hex("Decrypted", pt, ctlen);
    print_hex("Computed Tag", tagbuf, taglen);
    print_hex("Expected Tag", tag, taglen);

    // Compare tags
    if (constant_time_compare(tag, tagbuf, taglen) != 0) {
        printf("[TAG MISMATCH]\n");
        return CRYPT_ERROR;
    }

    return CRYPT_OK;
}

int main() {
    int err;
    
    // Manually register AES
    int cipher_idx = register_cipher(&aes_desc);
    if (cipher_idx == -1)
        handle_error("AES registration failed", -1);

    // Test parameters
    unsigned char key[16] = {
        0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7,
        0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF
    };
    unsigned char nonce[13] = {
        0x00, 0x00, 0x00, 0x03, 0x02, 0x01, 0x00, 0xA0,
        0xA1, 0xA2, 0xA3, 0xA4, 0xA5
    };
    unsigned char header[8] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07
    };
    unsigned char pt[23] = {
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E
    };
    unsigned char ct[sizeof(pt)];
    unsigned char decrypted[sizeof(pt)];
    unsigned char tag[8];
    
    unsigned long keylen = sizeof(key);
    unsigned long noncelen = sizeof(nonce);
    unsigned long headerlen = sizeof(header);
    unsigned long ptlen = sizeof(pt);
    unsigned long taglen = sizeof(tag);

    printf("========= KNOWN TEST VECTOR (RFC 3610) =========\n");
    printf("Expecting tag: 1F247C89A8107D22\n");

    // Encrypt
    err = aes_ccm_encrypt(
        key, keylen,
        nonce, noncelen,
        header, headerlen,
        pt, ptlen,
        ct,
        tag, taglen
    );
    if (err != CRYPT_OK) 
        handle_error("Encryption failed", err);
    
    // Decrypt
    err = aes_ccm_decrypt(
        key, keylen,
        nonce, noncelen,
        header, headerlen,
        ct, ptlen,
        decrypted,
        tag, taglen
    );
    
    if (err == CRYPT_OK) {
        printf("\nSUCCESS: Authentication passed!\n");
        
        // Verify decrypted text matches original
        if (memcmp(pt, decrypted, ptlen) == 0) {
            printf("SUCCESS: Decrypted text matches original\n");
        } else {
            printf("ERROR: Decrypted text mismatch!\n");
            print_hex("Original", pt, ptlen);
            print_hex("Decrypted", decrypted, ptlen);
        }
    }
    else if (err == CRYPT_ERROR) {
        printf("\nERROR: Authentication failed! Tags don't match.\n");
    }
    else {
        handle_error("Decryption error", err);
    }

    // Cleanup
    unregister_cipher(&aes_desc);
    return 0;
}
