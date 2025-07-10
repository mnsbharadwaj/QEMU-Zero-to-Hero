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
    if (register_cipher(&aes_desc) == -1) {
        fprintf(stderr, "AES registration failed\n");
        return -1;
    }
    cipher_idx = find_cipher("aes");
    if (cipher_idx == -1) {
        fprintf(stderr, "AES not found\n");
        return -1;
    }
    
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
    
    // Print inputs
    printf("======== RFC 3610 TEST VECTOR (Multi-block) ========\n");
    print_hex("Key        ", key, sizeof(key));
    print_hex("Nonce      ", nonce, noncelen);
    print_hex("Header     ", header, headerlen);
    print_hex("Plaintext  ", pt, ptlen);
    printf("Tag length: %lu\n", taglen);
    printf("Plaintext length: %lu\n", ptlen);
    
    // ====== MULTI-BLOCK ENCRYPTION ======
    ccm_state ccm;
    unsigned long processed;
    
    // Initialize CCM
    if ((err = ccm_init(&ccm, cipher_idx, key, sizeof(key), ptlen, taglen, headerlen)) != CRYPT_OK)
        handle_error("ccm_init failed", err);
    
    // Add nonce
    if ((err = ccm_add_nonce(&ccm, nonce, noncelen)) != CRYPT_OK)
        handle_error("ccm_add_nonce failed", err);
    
    // Add AAD in chunks (2 chunks of 4 bytes each)
    if (headerlen > 0) {
        size_t aad_chunk1 = 4;
        size_t aad_chunk2 = 4;
        
        if ((err = ccm_add_aad(&ccm, header, aad_chunk1)) != CRYPT_OK)
            handle_error("ccm_add_aad chunk1 failed", err);
        
        if ((err = ccm_add_aad(&ccm, header + aad_chunk1, aad_chunk2)) != CRYPT_OK)
            handle_error("ccm_add_aad chunk2 failed", err);
    }
    
    // Process plaintext in chunks (3 chunks: 8, 8, 7 bytes)
    size_t chunk1 = 8;
    size_t chunk2 = 8;
    size_t chunk3 = 7;
    
    if ((err = ccm_process(&ccm, pt, chunk1, ct, CCM_ENCRYPT)) != CRYPT_OK)
        handle_error("ccm_process chunk1 failed", err);
    
    if ((err = ccm_process(&ccm, pt + chunk1, chunk2, ct + chunk1, CCM_ENCRYPT)) != CRYPT_OK)
        handle_error("ccm_process chunk2 failed", err);
    
    if ((err = ccm_process(&ccm, pt + chunk1 + chunk2, chunk3, ct + chunk1 + chunk2, CCM_ENCRYPT)) != CRYPT_OK)
        handle_error("ccm_process chunk3 failed", err);
    
    // Generate tag
    if ((err = ccm_done(&ccm, tag, &taglen)) != CRYPT_OK)
        handle_error("ccm_done failed", err);
    
    // Print results
    printf("\nENCRYPTION RESULTS:\n");
    print_hex("Ciphertext ", ct, ptlen);
    print_hex("Tag        ", tag, taglen);
    
    // Expected results from RFC 3610
    unsigned char expected_ct[] = {
        0x58, 0x8C, 0x97, 0x9A, 0x61, 0xC6, 0x63, 0xD2, 
        0xF0, 0x66, 0xD0, 0xC2, 0xC0, 0xF9, 0x89, 0x80, 
        0x6D, 0x5F, 0x6B, 0x61, 0xDA, 0xC3, 0x84
    };
    unsigned char expected_tag[] = {0x1F, 0x24, 0x7C, 0x89, 0xA8, 0x10, 0x7D, 0x22};
    
    printf("\nEXPECTED RESULTS:\n");
    print_hex("Ciphertext ", expected_ct, ptlen);
    print_hex("Tag        ", expected_tag, sizeof(expected_tag));
    
    // Verify encryption results
    if (memcmp(ct, expected_ct, ptlen) != 0) {
        printf("\nERROR: Ciphertext mismatch!\n");
    } else {
        printf("\nSUCCESS: Ciphertext matches!\n");
    }
    
    if (memcmp(tag, expected_tag, sizeof(expected_tag)) != 0) {
        printf("ERROR: Tag mismatch!\n");
        print_hex("Expected tag", expected_tag, sizeof(expected_tag));
        print_hex("Actual tag  ", tag, taglen);
    } else {
        printf("SUCCESS: Tag matches!\n");
    }
    
    // ====== MULTI-BLOCK DECRYPTION ======
    unsigned char decrypted_tag[sizeof(tag)];
    unsigned long decrypted_taglen = taglen;
    
    // Initialize CCM
    if ((err = ccm_init(&ccm, cipher_idx, key, sizeof(key), ptlen, taglen, headerlen)) != CRYPT_OK)
        handle_error("decrypt: ccm_init failed", err);
    
    // Add nonce
    if ((err = ccm_add_nonce(&ccm, nonce, noncelen)) != CRYPT_OK)
        handle_error("decrypt: ccm_add_nonce failed", err);
    
    // Add AAD in same chunks
    if (headerlen > 0) {
        size_t aad_chunk1 = 4;
        size_t aad_chunk2 = 4;
        
        if ((err = ccm_add_aad(&ccm, header, aad_chunk1)) != CRYPT_OK)
            handle_error("decrypt: ccm_add_aad chunk1 failed", err);
        
        if ((err = ccm_add_aad(&ccm, header + aad_chunk1, aad_chunk2)) != CRYPT_OK)
            handle_error("decrypt: ccm_add_aad chunk2 failed", err);
    }
    
    // Process ciphertext in same chunks
    if ((err = ccm_process(&ccm, ct, chunk1, decrypted, CCM_DECRYPT)) != CRYPT_OK)
        handle_error("decrypt: ccm_process chunk1 failed", err);
    
    if ((err = ccm_process(&ccm, ct + chunk1, chunk2, decrypted + chunk1, CCM_DECRYPT)) != CRYPT_OK)
        handle_error("decrypt: ccm_process chunk2 failed", err);
    
    if ((err = ccm_process(&ccm, ct + chunk1 + chunk2, chunk3, decrypted + chunk1 + chunk2, CCM_DECRYPT)) != CRYPT_OK)
        handle_error("decrypt: ccm_process chunk3 failed", err);
    
    // Generate tag for verification
    if ((err = ccm_done(&ccm, decrypted_tag, &decrypted_taglen)) != CRYPT_OK)
        handle_error("decrypt: ccm_done failed", err);
    
    // Compare tags
    if (memcmp(tag, decrypted_tag, taglen) != 0) {
        printf("\nDECRYPT: Authentication FAILED!\n");
    } else {
        printf("\nDECRYPT: Authentication SUCCESS!\n");
        print_hex("Decrypted text", decrypted, ptlen);
        
        // Verify decrypted text
        if (memcmp(pt, decrypted, ptlen) == 0) {
            printf("SUCCESS: Decrypted text matches original!\n");
        } else {
            printf("ERROR: Decrypted text mismatch!\n");
            print_hex("Original ", pt, ptlen);
            print_hex("Decrypted", decrypted, ptlen);
        }
    }
    
    // Cleanup
    unregister_cipher(&aes_desc);
    return 0;
}
