#include <tomcrypt.h>
#include <stdio.h>
#include <string.h>

void handle_error(const char* msg, int err) {
    fprintf(stderr, "%s: %s\n", msg, error_to_string(err));
    exit(EXIT_FAILURE);
}

void print_hex(const char* label, const unsigned char* data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02X", data[i]);
    }
    printf("\n");
}

int main() {
    int err;
    int cipher_idx;
    
    // Register AES
    if (register_cipher(&aes_desc) == -1)
        handle_error("AES registration failed", -1);
    cipher_idx = find_cipher("aes");
    if (cipher_idx == -1)
        handle_error("AES not found", -1);
    
    printf("Using LibTomCrypt Version: %s\n", SCRYPT);
    
    // ===== Fixed Test Vector =====
    // Using simpler vector for better debugging
    unsigned char key[16] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    };
    unsigned char nonce[13] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
        0x00, 0x00, 0x00, 0x00, 0x00
    };
    unsigned char header[8] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07
    };
    unsigned char pt[4] = {0x48, 0x65, 0x6c, 0x6c}; // "Hell"
    unsigned char ct[sizeof(pt)];
    unsigned char decrypted[sizeof(pt)];
    unsigned char tag[4];
    unsigned long taglen = sizeof(tag);
    
    unsigned long ptlen = sizeof(pt);
    unsigned long noncelen = sizeof(nonce);
    unsigned long headerlen = sizeof(header);
    
    printf("======== FIXED TEST VECTOR ========\n");
    print_hex("Key        ", key, sizeof(key));
    print_hex("Nonce      ", nonce, noncelen);
    print_hex("Header     ", header, headerlen);
    print_hex("Plaintext  ", pt, ptlen);
    printf("Plaintext length: %lu\n", ptlen);
    printf("Header length: %lu\n", headerlen);
    printf("Tag length: %lu\n", taglen);
    
    // ====== ENCRYPTION ======
    ccm_state ccm_enc;
    
    // 1. Initialize CCM
    if ((err = ccm_init(&ccm_enc, cipher_idx, key, sizeof(key), ptlen, taglen, headerlen)) != CRYPT_OK)
        handle_error("ccm_init failed", err);
    
    // 2. Add nonce
    if ((err = ccm_add_nonce(&ccm_enc, nonce, noncelen)) != CRYPT_OK)
        handle_error("ccm_add_nonce failed", err);
    
    // 3. Add AAD
    if (headerlen > 0) {
        if ((err = ccm_add_aad(&ccm_enc, header, headerlen)) != CRYPT_OK)
            handle_error("ccm_add_aad failed", err);
    }
    
    // 4. Process plaintext
    if ((err = ccm_process(&ccm_enc, pt, ptlen, ct, CCM_ENCRYPT)) != CRYPT_OK)
        handle_error("ccm_process failed", err);
    
    // 5. Generate tag
    if ((err = ccm_done(&ccm_enc, tag, &taglen)) != CRYPT_OK)
        handle_error("ccm_done failed", err);
    
    printf("\nENCRYPTION SUCCESS\n");
    print_hex("Ciphertext ", ct, ptlen);
    print_hex("Tag        ", tag, taglen);
    
    // ====== DECRYPTION ======
    ccm_state ccm_dec;
    unsigned char decrypted_tag[sizeof(tag)];
    unsigned long decrypted_taglen = taglen;
    
    // 1. Initialize CCM - MUST match encryption parameters exactly
    if ((err = ccm_init(&ccm_dec, cipher_idx, key, sizeof(key), ptlen, taglen, headerlen)) != CRYPT_OK)
        handle_error("decrypt: ccm_init failed", err);
    
    // 2. Add nonce - MUST be identical to encryption
    if ((err = ccm_add_nonce(&ccm_dec, nonce, noncelen)) != CRYPT_OK)
        handle_error("decrypt: ccm_add_nonce failed", err);
    
    // 3. Add AAD - MUST be identical to encryption
    if (headerlen > 0) {
        if ((err = ccm_add_aad(&ccm_dec, header, headerlen)) != CRYPT_OK)
            handle_error("decrypt: ccm_add_aad failed", err);
    }
    
    // 4. Process ciphertext
    if ((err = ccm_process(&ccm_dec, ct, ptlen, decrypted, CCM_DECRYPT)) != CRYPT_OK)
        handle_error("decrypt: ccm_process failed", err);
    
    // 5. Verify tag
    if ((err = ccm_done(&ccm_dec, decrypted_tag, &decrypted_taglen)) != CRYPT_OK)
        handle_error("decrypt: ccm_done failed", err);
    
    printf("\nDECRYPTION COMPLETE\n");
    print_hex("Decrypted  ", decrypted, ptlen);
    
    // Verify decrypted text
    if (memcmp(pt, decrypted, ptlen) == 0) {
        printf("SUCCESS: Decrypted text matches original!\n");
    } else {
        printf("ERROR: Decrypted text mismatch!\n");
        print_hex("Original   ", pt, ptlen);
    }
    
    // Verify tag
    if (memcmp(tag, decrypted_tag, taglen) == 0) {
        printf("SUCCESS: Tag verification passed!\n");
    } else {
        printf("ERROR: Tag verification failed!\n");
        print_hex("Expected tag", tag, taglen);
        print_hex("Actual tag  ", decrypted_tag, taglen);
    }
    
    // Cleanup
    unregister_cipher(&aes_desc);
    return 0;
}
