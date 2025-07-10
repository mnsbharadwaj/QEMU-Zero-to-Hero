#include <tomcrypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Function to print hex data
void print_hex(const char* label, const unsigned char* data, unsigned long len) {
    printf("%s: ", label);
    for (unsigned long i = 0; i < len; i++) {
        printf("%02x ", data[i]);
    }
    printf("\n");
}

// CCM encryption function using LibTomCrypt's native CCM
int aes_ccm_encrypt_multiblock(const unsigned char *key, unsigned long keylen,
                               const unsigned char *nonce, unsigned long noncelen,
                               const unsigned char *aad, unsigned long aadlen,
                               const unsigned char *plaintext, unsigned long plaintextlen,
                               unsigned char *ciphertext, unsigned char *tag, 
                               unsigned long *taglen) {
    
    ccm_state ccm;
    int err;
    
    // Find AES cipher
    int cipher_idx = find_cipher("aes");
    if (cipher_idx == -1) {
        printf("AES cipher not found\n");
        return CRYPT_INVALID_CIPHER;
    }
    
    // Initialize CCM state
    if ((err = ccm_init(&ccm, cipher_idx, key, keylen, plaintextlen, *taglen, aadlen)) != CRYPT_OK) {
        printf("CCM init failed: %s\n", error_to_string(err));
        return err;
    }
    
    // Add nonce
    if ((err = ccm_add_nonce(&ccm, nonce, noncelen)) != CRYPT_OK) {
        printf("CCM add nonce failed: %s\n", error_to_string(err));
        ccm_done(&ccm);
        return err;
    }
    
    // Add AAD (can be called multiple times for multiblock AAD)
    if (aadlen > 0 && aad != NULL) {
        unsigned long remaining = aadlen;
        const unsigned char *aad_ptr = aad;
        unsigned long chunk_size = 1024; // Process AAD in chunks
        
        while (remaining > 0) {
            unsigned long to_process = (remaining > chunk_size) ? chunk_size : remaining;
            
            if ((err = ccm_add_aad(&ccm, aad_ptr, to_process)) != CRYPT_OK) {
                printf("CCM add AAD failed: %s\n", error_to_string(err));
                ccm_done(&ccm);
                return err;
            }
            
            aad_ptr += to_process;
            remaining -= to_process;
        }
    }
    
    // Process plaintext (can be called multiple times for multiblock messages)
    if (plaintextlen > 0 && plaintext != NULL) {
        unsigned long remaining = plaintextlen;
        const unsigned char *pt_ptr = plaintext;
        unsigned char *ct_ptr = ciphertext;
        unsigned long chunk_size = 1024; // Process plaintext in chunks
        
        while (remaining > 0) {
            unsigned long to_process = (remaining > chunk_size) ? chunk_size : remaining;
            
            if ((err = ccm_process(&ccm, pt_ptr, to_process, ct_ptr, CCM_ENCRYPT)) != CRYPT_OK) {
                printf("CCM process failed: %s\n", error_to_string(err));
                ccm_done(&ccm);
                return err;
            }
            
            pt_ptr += to_process;
            ct_ptr += to_process;
            remaining -= to_process;
        }
    }
    
    // Generate tag
    if ((err = ccm_done(&ccm, tag, taglen)) != CRYPT_OK) {
        printf("CCM done failed: %s\n", error_to_string(err));
        return err;
    }
    
    return CRYPT_OK;
}

// CCM decryption function using LibTomCrypt's native CCM
int aes_ccm_decrypt_multiblock(const unsigned char *key, unsigned long keylen,
                               const unsigned char *nonce, unsigned long noncelen,
                               const unsigned char *aad, unsigned long aadlen,
                               const unsigned char *ciphertext, unsigned long ciphertextlen,
                               unsigned char *plaintext, const unsigned char *tag, 
                               unsigned long taglen) {
    
    ccm_state ccm;
    int err;
    
    // Find AES cipher
    int cipher_idx = find_cipher("aes");
    if (cipher_idx == -1) {
        printf("AES cipher not found\n");
        return CRYPT_INVALID_CIPHER;
    }
    
    // Initialize CCM state
    if ((err = ccm_init(&ccm, cipher_idx, key, keylen, ciphertextlen, taglen, aadlen)) != CRYPT_OK) {
        printf("CCM init failed: %s\n", error_to_string(err));
        return err;
    }
    
    // Add nonce
    if ((err = ccm_add_nonce(&ccm, nonce, noncelen)) != CRYPT_OK) {
        printf("CCM add nonce failed: %s\n", error_to_string(err));
        ccm_done(&ccm);
        return err;
    }
    
    // Add AAD (multiblock support)
    if (aadlen > 0 && aad != NULL) {
        unsigned long remaining = aadlen;
        const unsigned char *aad_ptr = aad;
        unsigned long chunk_size = 1024; // Process AAD in chunks
        
        while (remaining > 0) {
            unsigned long to_process = (remaining > chunk_size) ? chunk_size : remaining;
            
            if ((err = ccm_add_aad(&ccm, aad_ptr, to_process)) != CRYPT_OK) {
                printf("CCM add AAD failed: %s\n", error_to_string(err));
                ccm_done(&ccm);
                return err;
            }
            
            aad_ptr += to_process;
            remaining -= to_process;
        }
    }
    
    // Process ciphertext (multiblock support)
    if (ciphertextlen > 0 && ciphertext != NULL) {
        unsigned long remaining = ciphertextlen;
        const unsigned char *ct_ptr = ciphertext;
        unsigned char *pt_ptr = plaintext;
        unsigned long chunk_size = 1024; // Process ciphertext in chunks
        
        while (remaining > 0) {
            unsigned long to_process = (remaining > chunk_size) ? chunk_size : remaining;
            
            if ((err = ccm_process(&ccm, ct_ptr, to_process, pt_ptr, CCM_DECRYPT)) != CRYPT_OK) {
                printf("CCM process failed: %s\n", error_to_string(err));
                ccm_done(&ccm);
                return err;
            }
            
            ct_ptr += to_process;
            pt_ptr += to_process;
            remaining -= to_process;
        }
    }
    
    // Verify tag
    unsigned char computed_tag[16];
    unsigned long computed_taglen = taglen;
    
    if ((err = ccm_done(&ccm, computed_tag, &computed_taglen)) != CRYPT_OK) {
        printf("CCM done failed: %s\n", error_to_string(err));
        return err;
    }
    
    // Compare tags
    if (computed_taglen != taglen || memcmp(computed_tag, tag, taglen) != 0) {
        printf("Authentication failed: tag mismatch\n");
        return CRYPT_ERROR;
    }
    
    return CRYPT_OK;
}

// Streaming CCM encryption for very large data
int aes_ccm_encrypt_streaming(const unsigned char *key, unsigned long keylen,
                              const unsigned char *nonce, unsigned long noncelen,
                              const unsigned char *aad, unsigned long aadlen,
                              FILE *input_file, FILE *output_file,
                              unsigned char *tag, unsigned long *taglen,
                              unsigned long total_plaintext_len) {
    
    ccm_state ccm;
    int err;
    unsigned char buffer[4096];
    size_t bytes_read;
    
    // Find AES cipher
    int cipher_idx = find_cipher("aes");
    if (cipher_idx == -1) {
        return CRYPT_INVALID_CIPHER;
    }
    
    // Initialize CCM state
    if ((err = ccm_init(&ccm, cipher_idx, key, keylen, total_plaintext_len, *taglen, aadlen)) != CRYPT_OK) {
        return err;
    }
    
    // Add nonce
    if ((err = ccm_add_nonce(&ccm, nonce, noncelen)) != CRYPT_OK) {
        ccm_done(&ccm);
        return err;
    }
    
    // Add AAD
    if (aadlen > 0 && aad != NULL) {
        if ((err = ccm_add_aad(&ccm, aad, aadlen)) != CRYPT_OK) {
            ccm_done(&ccm);
            return err;
        }
    }
    
    // Process file in chunks
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), input_file)) > 0) {
        unsigned char ciphertext[sizeof(buffer)];
        
        if ((err = ccm_process(&ccm, buffer, bytes_read, ciphertext, CCM_ENCRYPT)) != CRYPT_OK) {
            ccm_done(&ccm);
            return err;
        }
        
        if (fwrite(ciphertext, 1, bytes_read, output_file) != bytes_read) {
            ccm_done(&ccm);
            return CRYPT_ERROR;
        }
    }
    
    // Generate tag
    if ((err = ccm_done(&ccm, tag, taglen)) != CRYPT_OK) {
        return err;
    }
    
    return CRYPT_OK;
}

// Streaming CCM decryption for very large data
int aes_ccm_decrypt_streaming(const unsigned char *key, unsigned long keylen,
                              const unsigned char *nonce, unsigned long noncelen,
                              const unsigned char *aad, unsigned long aadlen,
                              FILE *input_file, FILE *output_file,
                              const unsigned char *tag, unsigned long taglen,
                              unsigned long total_ciphertext_len) {
    
    ccm_state ccm;
    int err;
    unsigned char buffer[4096];
    size_t bytes_read;
    
    // Find AES cipher
    int cipher_idx = find_cipher("aes");
    if (cipher_idx == -1) {
        return CRYPT_INVALID_CIPHER;
    }
    
    // Initialize CCM state
    if ((err = ccm_init(&ccm, cipher_idx, key, keylen, total_ciphertext_len, taglen, aadlen)) != CRYPT_OK) {
        return err;
    }
    
    // Add nonce
    if ((err = ccm_add_nonce(&ccm, nonce, noncelen)) != CRYPT_OK) {
        ccm_done(&ccm);
        return err;
    }
    
    // Add AAD
    if (aadlen > 0 && aad != NULL) {
        if ((err = ccm_add_aad(&ccm, aad, aadlen)) != CRYPT_OK) {
            ccm_done(&ccm);
            return err;
        }
    }
    
    // Process file in chunks
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), input_file)) > 0) {
        unsigned char plaintext[sizeof(buffer)];
        
        if ((err = ccm_process(&ccm, buffer, bytes_read, plaintext, CCM_DECRYPT)) != CRYPT_OK) {
            ccm_done(&ccm);
            return err;
        }
        
        if (fwrite(plaintext, 1, bytes_read, output_file) != bytes_read) {
            ccm_done(&ccm);
            return CRYPT_ERROR;
        }
    }
    
    // Verify tag
    unsigned char computed_tag[16];
    unsigned long computed_taglen = taglen;
    
    if ((err = ccm_done(&ccm, computed_tag, &computed_taglen)) != CRYPT_OK) {
        return err;
    }
    
    if (computed_taglen != taglen || memcmp(computed_tag, tag, taglen) != 0) {
        return CRYPT_ERROR; // Authentication failed
    }
    
    return CRYPT_OK;
}

// Example and test function
int main() {
    int err;
    
    // Initialize LibTomCrypt
    if ((err = register_cipher(&aes_desc)) == -1) {
        printf("Error registering AES cipher\n");
        return 1;
    }
    
    // Test vectors
    unsigned char key[] = {
        0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
        0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f
    };
    
    unsigned char nonce[] = {
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16
    };
    
    // Large multiblock AAD (simulating multiple AAD chunks)
    unsigned char aad[2048];
    for (int i = 0; i < sizeof(aad); i++) {
        aad[i] = i & 0xff;
    }
    
    // Large multiblock plaintext
    unsigned char plaintext[5000];
    for (int i = 0; i < sizeof(plaintext); i++) {
        plaintext[i] = (i + 0x20) & 0xff;
    }
    
    unsigned char ciphertext[sizeof(plaintext)];
    unsigned char decrypted[sizeof(plaintext)];
    unsigned char tag[16];
    unsigned long taglen = 16;
    
    printf("=== AES-CCM Multiblock Test ===\n");
    printf("Key length: %lu bytes\n", sizeof(key));
    printf("Nonce length: %lu bytes\n", sizeof(nonce));
    printf("AAD length: %lu bytes\n", sizeof(aad));
    printf("Plaintext length: %lu bytes\n", sizeof(plaintext));
    printf("Tag length: %lu bytes\n", taglen);
    
    // Test 1: Basic multiblock encryption/decryption
    printf("\n--- Test 1: Basic Multiblock Operations ---\n");
    
    // Encrypt
    printf("Encrypting...\n");
    if ((err = aes_ccm_encrypt_multiblock(key, sizeof(key), nonce, sizeof(nonce),
                                         aad, sizeof(aad), plaintext, sizeof(plaintext),
                                         ciphertext, tag, &taglen)) != CRYPT_OK) {
        printf("Encryption failed: %s\n", error_to_string(err));
        return 1;
    }
    
    print_hex("Tag", tag, taglen);
    printf("First 32 bytes of ciphertext: ");
    for (int i = 0; i < 32; i++) {
        printf("%02x ", ciphertext[i]);
    }
    printf("\n");
    
    // Decrypt
    printf("Decrypting...\n");
    if ((err = aes_ccm_decrypt_multiblock(key, sizeof(key), nonce, sizeof(nonce),
                                         aad, sizeof(aad), ciphertext, sizeof(ciphertext),
                                         decrypted, tag, taglen)) != CRYPT_OK) {
        printf("Decryption failed: %s\n", error_to_string(err));
        return 1;
    }
    
    // Verify
    if (memcmp(plaintext, decrypted, sizeof(plaintext)) == 0) {
        printf("SUCCESS: Decryption matches original plaintext\n");
    } else {
        printf("FAILURE: Decryption does not match original plaintext\n");
        return 1;
    }
    
    // Test 2: Authentication failure test
    printf("\n--- Test 2: Authentication Failure Test ---\n");
    unsigned char bad_tag[16];
    memcpy(bad_tag, tag, sizeof(bad_tag));
    bad_tag[0] ^= 0x01; // Corrupt the tag
    
    if ((err = aes_ccm_decrypt_multiblock(key, sizeof(key), nonce, sizeof(nonce),
                                         aad, sizeof(aad), ciphertext, sizeof(ciphertext),
                                         decrypted, bad_tag, taglen)) == CRYPT_ERROR) {
        printf("SUCCESS: Authentication failure correctly detected\n");
    } else {
        printf("FAILURE: Authentication failure not detected\n");
        return 1;
    }
    
    // Test 3: No AAD test
    printf("\n--- Test 3: No AAD Test ---\n");
    unsigned char tag_no_aad[16];
    unsigned long taglen_no_aad = 16;
    
    if ((err = aes_ccm_encrypt_multiblock(key, sizeof(key), nonce, sizeof(nonce),
                                         NULL, 0, plaintext, sizeof(plaintext),
                                         ciphertext, tag_no_aad, &taglen_no_aad)) != CRYPT_OK) {
        printf("Encryption without AAD failed: %s\n", error_to_string(err));
        return 1;
    }
    
    if ((err = aes_ccm_decrypt_multiblock(key, sizeof(key), nonce, sizeof(nonce),
                                         NULL, 0, ciphertext, sizeof(ciphertext),
                                         decrypted, tag_no_aad, taglen_no_aad)) != CRYPT_OK) {
        printf("Decryption without AAD failed: %s\n", error_to_string(err));
        return 1;
    }
    
    if (memcmp(plaintext, decrypted, sizeof(plaintext)) == 0) {
        printf("SUCCESS: No AAD test passed\n");
    } else {
        printf("FAILURE: No AAD test failed\n");
        return 1;
    }
    
    printf("\n=== All tests passed! ===\n");
    printf("The implementation successfully handles:\n");
    printf("- Multiblock messages (%lu bytes)\n", sizeof(plaintext));
    printf("- Multiblock AAD (%lu bytes)\n", sizeof(aad));
    printf("- Authentication verification\n");
    printf("- Various input scenarios\n");
    
    return 0;
}
