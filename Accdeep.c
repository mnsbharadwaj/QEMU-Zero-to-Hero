#include <tomcrypt.h>
#include <stdio.h>
#include <string.h>

void handle_error(const char* msg, int err) {
    fprintf(stderr, "%s: %s\n", msg, error_to_string(err));
    exit(EXIT_FAILURE);
}

int aes_ccm_encrypt(
    const unsigned char* key, int keylen,
    const unsigned char* nonce, int noncelen,
    const unsigned char* header, int headerlen,
    const unsigned char* pt, int ptlen,
    unsigned char* ct,
    unsigned char* tag, int taglen
) {
    int err, cipher_idx;
    ccm_state ccm;

    // Validate parameters
    if (keylen != 16 && keylen != 24 && keylen != 32) return CRYPT_INVALID_KEYSIZE;
    if (noncelen < 7 || noncelen > 13) return CRYPT_INVALID_ARG;
    if (taglen < 4 || taglen > 16) return CRYPT_INVALID_ARG;

    // Register AES cipher
    cipher_idx = find_cipher("aes");
    if (cipher_idx == -1) return CRYPT_INVALID_CIPHER;

    // Initialize CCM mode
    if ((err = ccm_init(&ccm, cipher_idx, key, keylen, ptlen, taglen, headerlen)) != CRYPT_OK) 
        return err;
    
    // Add nonce
    if ((err = ccm_add_nonce(&ccm, nonce, noncelen)) != CRYPT_OK)
        return err;
    
    // Add header data (AAD)
    if (headerlen > 0 && (err = ccm_add_aad(&ccm, header, headerlen)) != CRYPT_OK)
        return err;
    
    // Process plaintext
    if ((err = ccm_process(&ccm, pt, ptlen, ct, CCM_ENCRYPT)) != CRYPT_OK)
        return err;
    
    // Generate authentication tag
    return ccm_done(&ccm, tag, &taglen);
}

int aes_ccm_decrypt(
    const unsigned char* key, int keylen,
    const unsigned char* nonce, int noncelen,
    const unsigned char* header, int headerlen,
    const unsigned char* ct, int ctlen,
    unsigned char* pt,
    const unsigned char* tag, int taglen
) {
    int err, cipher_idx, stat;
    ccm_state ccm;
    unsigned char tagbuf[16];

    // Validate parameters
    if (keylen != 16 && keylen != 24 && keylen != 32) return CRYPT_INVALID_KEYSIZE;
    if (noncelen < 7 || noncelen > 13) return CRYPT_INVALID_ARG;
    if (taglen < 4 || taglen > 16) return CRYPT_INVALID_ARG;

    // Register AES cipher
    cipher_idx = find_cipher("aes");
    if (cipher_idx == -1) return CRYPT_INVALID_CIPHER;

    // Initialize CCM mode
    if ((err = ccm_init(&ccm, cipher_idx, key, keylen, ctlen, taglen, headerlen)) != CRYPT_OK)
        return err;
    
    // Add nonce
    if ((err = ccm_add_nonce(&ccm, nonce, noncelen)) != CRYPT_OK)
        return err;
    
    // Add header data (AAD)
    if (headerlen > 0 && (err = ccm_add_aad(&ccm, header, headerlen)) != CRYPT_OK)
        return err;
    
    // Process ciphertext
    if ((err = ccm_process(&ccm, ct, ctlen, pt, CCM_DECRYPT)) != CRYPT_OK)
        return err;
    
    // Verify tag
    if ((err = ccm_done(&ccm, tagbuf, &taglen)) != CRYPT_OK)
        return err;
    
    // Compare tags
    if (XMEMCMP(tag, tagbuf, taglen) != 0) {
        return CRYPT_ERROR;
    }

    return CRYPT_OK;
}

int main() {
    int err;
    
    // Register AES cipher
    if (register_cipher(&aes_desc) == -1)
        handle_error("AES registration failed", -1);

    // Test parameters
    unsigned char key[] = {0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
                           0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,0x10}; // 128-bit key
    unsigned char nonce[] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B}; // 12-byte nonce
    unsigned char header[] = "AdditionalData"; // Authenticated but not encrypted
    unsigned char pt[] = "SecretMessage";     // Plaintext to encrypt
    unsigned char ct[sizeof(pt)];             // Ciphertext buffer
    unsigned char decrypted[sizeof(pt)];      // Decrypted text buffer
    unsigned char tag[12];                    // Authentication tag
    
    int keylen = sizeof(key);
    int noncelen = sizeof(nonce);
    int headerlen = sizeof(header)-1; // Exclude null terminator
    int ptlen = sizeof(pt)-1;         // Exclude null terminator
    int taglen = sizeof(tag);

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
    
    printf("Encryption Successful!\n");
    printf("Ciphertext: ");
    for (int i = 0; i < ptlen; i++) printf("%02X", ct[i]);
    printf("\nTag: ");
    for (int i = 0; i < taglen; i++) printf("%02X", tag[i]);
    printf("\n\n");

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
        printf("Decryption Successful!\n");
        printf("Plaintext: %s\n", decrypted);
    } else if (err == CRYPT_ERROR) {
        printf("Authentication FAILED! Data tampered.\n");
    } else {
        handle_error("Decryption failed", err);
    }

    // Cleanup
    unregister_cipher(&aes_desc);
    return 0;
}
