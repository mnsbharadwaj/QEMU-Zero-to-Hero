#include <tomcrypt.h>
#include <stdio.h>
#include <string.h>

void handle_error(const char* msg, int err) {
    fprintf(stderr, "%s: %s\n", msg, error_to_string(err));
    exit(EXIT_FAILURE);
}

int aes_ccm_encrypt(
    const unsigned char* key, unsigned long keylen,
    const unsigned char* nonce, unsigned long noncelen,
    const unsigned char* header, unsigned long headerlen,
    const unsigned char* pt, unsigned long ptlen,
    unsigned char* ct,
    unsigned char* tag, unsigned long taglen
) {
    int err, cipher_idx;
    ccm_state ccm;

    // Register AES cipher
    cipher_idx = register_cipher(&aes_desc);
    if (cipher_idx == -1) return CRYPT_INVALID_CIPHER;

    // Initialize CCM mode
    err = ccm_init(&ccm, cipher_idx, key, keylen, ptlen, taglen, headerlen);
    if (err != CRYPT_OK) return err;
    
    // Add nonce
    err = ccm_add_nonce(&ccm, nonce, noncelen);
    if (err != CRYPT_OK) return err;
    
    // Add header data (AAD)
    if (headerlen > 0) {
        err = ccm_add_aad(&ccm, header, headerlen);
        if (err != CRYPT_OK) return err;
    }
    
    // Process plaintext
    err = ccm_process(&ccm, pt, ptlen, ct, CCM_ENCRYPT);
    if (err != CRYPT_OK) return err;
    
    // Generate authentication tag
    return ccm_done(&ccm, tag, &taglen);
}

int aes_ccm_decrypt(
    const unsigned char* key, unsigned long keylen,
    const unsigned char* nonce, unsigned long noncelen,
    const unsigned char* header, unsigned long headerlen,
    const unsigned char* ct, unsigned long ctlen,
    unsigned char* pt,
    const unsigned char* tag, unsigned long taglen
) {
    int err, cipher_idx, stat;
    ccm_state ccm;
    unsigned char tagbuf[16];
    unsigned long tagbuflen = taglen;

    // Register AES cipher
    cipher_idx = register_cipher(&aes_desc);
    if (cipher_idx == -1) return CRYPT_INVALID_CIPHER;

    // Initialize CCM mode
    err = ccm_init(&ccm, cipher_idx, key, keylen, ctlen, taglen, headerlen);
    if (err != CRYPT_OK) return err;
    
    // Add nonce
    err = ccm_add_nonce(&ccm, nonce, noncelen);
    if (err != CRYPT_OK) return err;
    
    // Add header data (AAD)
    if (headerlen > 0) {
        err = ccm_add_aad(&ccm, header, headerlen);
        if (err != CRYPT_OK) return err;
    }
    
    // Process ciphertext
    err = ccm_process(&ccm, ct, ctlen, pt, CCM_DECRYPT);
    if (err != CRYPT_OK) return err;
    
    // Verify tag
    err = ccm_done(&ccm, tagbuf, &tagbuflen);
    if (err != CRYPT_OK) return err;
    
    // Compare tags (constant-time comparison)
    if (XMEM_NEQ(tag, tagbuf, taglen)) {
        return CRYPT_ERROR;
    }

    return CRYPT_OK;
}

int main() {
    int err;
    
    // Manually register AES (safer than automatic registration)
    int cipher_idx = register_cipher(&aes_desc);
    if (cipher_idx == -1)
        handle_error("AES registration failed", -1);

    // Test parameters - MUST be same in both encrypt/decrypt
    unsigned char key[16] = {0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
                             0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,0x10};
    unsigned char nonce[12] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B};
    unsigned char header[] = "AdditionalData";
    unsigned char pt[] = "SecretMessage";
    unsigned char ct[sizeof(pt)];
    unsigned char decrypted[sizeof(pt)];
    unsigned char tag[12];
    
    unsigned long keylen = sizeof(key);
    unsigned long noncelen = sizeof(nonce);
    unsigned long headerlen = sizeof(header)-1;  // Exclude NULL terminator!
    unsigned long ptlen = sizeof(pt)-1;          // Exclude NULL terminator!
    unsigned long taglen = sizeof(tag);

    printf("======== Encryption ========\n");
    printf("Key: ");
    for(int i=0; i<keylen; i++) printf("%02X", key[i]);
    printf("\nNonce: ");
    for(int i=0; i<noncelen; i++) printf("%02X", nonce[i]);
    printf("\nHeader: %.*s\n", (int)headerlen, header);
    printf("Plaintext: %.*s\n", (int)ptlen, pt);
    
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
    
    printf("\nCiphertext: ");
    for (int i = 0; i < ptlen; i++) printf("%02X", ct[i]);
    printf("\nTag: ");
    for (int i = 0; i < taglen; i++) printf("%02X", tag[i]);
    printf("\n\n");
    
    printf("======== Decryption ========\n");
    // TEST: Simulate data tampering (uncomment to test)
    // ct[0] ^= 0x01;  // Flip first bit of ciphertext
    
    // Decrypt with correct parameters
    err = aes_ccm_decrypt(
        key, keylen,
        nonce, noncelen,
        header, headerlen,
        ct, ptlen,    // ctlen = ptlen for CCM
        decrypted,
        tag, taglen
    );
    
    if (err == CRYPT_OK) {
        printf("Authentication SUCCESS!\n");
        printf("Decrypted: %.*s\n", (int)ptlen, decrypted);
    }
    else if (err == CRYPT_ERROR) {
        printf("Authentication FAILED! Data tampered.\n");
    }
    else {
        handle_error("Decryption error", err);
    }

    // Cleanup
    unregister_cipher(&aes_desc);
    return 0;
}
