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
    
    printf("LibTomCrypt Version: %s\n", SCRYPT);
    
    // ===== RFC 3610 Test Vector =====
    unsigned char key[] = {
        0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7,
        0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF
    };
    unsigned char nonce[] = {
        0x00, 0x00, 0x00, 0x03, 0x02, 0x01, 0x00, 0xA0,
        0xA1, 0xA2, 0xA3, 0xA4, 0xA5
    };
    unsigned char header[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07
    };
    unsigned char pt[] = {
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E
    };
    unsigned char ct[sizeof(pt)];
    unsigned char decrypted[sizeof(pt)];
    unsigned char tag[8];
    unsigned long taglen = sizeof(tag);
    
    unsigned long ptlen = sizeof(pt);
    unsigned long noncelen = sizeof(nonce);
    unsigned long headerlen = sizeof(header);
    
    printf("======== TEST VECTOR ========\n");
    print_hex("Key        ", key, sizeof(key));
    print_hex("Nonce      ", nonce, noncelen);
    print_hex("Header     ", header, headerlen);
    print_hex("Plaintext  ", pt, ptlen);
    printf("Plaintext length: %lu\n", ptlen);
    printf("Header length: %lu\n", headerlen);
    printf("Tag length: %lu\n", taglen);
    
    // ====== ENCRYPTION ======
    ccm_state enc_state;
    
    // 1. Initialize CCM
    if ((err = ccm_init(&enc_state, cipher_idx, key, sizeof(key), ptlen, taglen, headerlen)) != CRYPT_OK)
        handle_error("ccm_init failed", err);
    
    // 2. Add nonce
    if ((err = ccm_add_nonce(&enc_state, nonce, noncelen)) != CRYPT_OK)
        handle_error("ccm_add_nonce failed", err);
    
    // 3. Add AAD (in one chunk)
    if ((err = ccm_add_aad(&enc_state, header, headerlen)) != CRYPT_OK)
        handle_error("ccm_add_aad failed", err);
    
    // 4. Process plaintext (in one chunk)
    if ((err = ccm_process(&enc_state, pt, ptlen, ct, CCM_ENCRYPT)) != CRYPT_OK)
        handle_error("ccm_process failed", err);
    
    // 5. Generate tag
    if ((err = ccm_done(&enc_state, tag, &taglen)) != CRYPT_OK)
        handle_error("ccm_done failed", err);
    
    printf("\nENCRYPTION SUCCESS\n");
    print_hex("Ciphertext ", ct, ptlen);
    print_hex("Tag        ", tag, taglen);
    
    // ====== DECRYPTION ======
    ccm_state dec_state;
    unsigned char decrypted_tag[sizeof(tag)];
    unsigned long decrypted_taglen = taglen;
    
    // 1. Initialize CCM (SAME parameters as encryption)
    if ((err = ccm_init(&dec_state, cipher_idx, key, sizeof(key), ptlen, taglen, headerlen)) != CRYPT_OK)
        handle_error("decrypt: ccm_init failed", err);
    
    // 2. Add nonce (SAME as encryption)
    if ((err = ccm_add_nonce(&dec_state, nonce, noncelen)) != CRYPT_OK)
        handle_error("decrypt: ccm_add_nonce failed", err);
    
    // 3. Add AAD (SAME as encryption)
    if ((err = ccm_add_aad(&dec_state, header, headerlen)) != CRYPT_OK)
        handle_error("decrypt: ccm_add_aad failed", err);
    
    // 4. Process ciphertext (in one chunk)
    if ((err = ccm_process(&dec_state, ct, ptlen, decrypted, CCM_DECRYPT)) != CRYPT_OK)
        handle_error("decrypt: ccm_process failed", err);
    
    // 5. Verify tag
    if ((err = ccm_done(&dec_state, decrypted_tag, &decrypted_taglen)) != CRYPT_OK)
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
