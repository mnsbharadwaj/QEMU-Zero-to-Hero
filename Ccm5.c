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

// Simple CCM encryption using ccm_memory (recommended for most use cases)
int aes_ccm_encrypt_simple(const unsigned char *key, unsigned long keylen,
                           const unsigned char *nonce, unsigned long noncelen,
                           const unsigned char *aad, unsigned long aadlen,
                           const unsigned char *plaintext, unsigned long plaintextlen,
                           unsigned char *ciphertext, unsigned char *tag, 
                           unsigned long *taglen) {
    
    int cipher_idx = find_cipher("aes");
    if (cipher_idx == -1) {
        return CRYPT_INVALID_CIPHER;
    }
    
    return ccm_memory(cipher_idx, key, keylen, NULL, nonce, noncelen,
                      aad, aadlen, plaintext, plaintextlen,
                      ciphertext, tag, taglen, CCM_ENCRYPT);
}

// Simple CCM decryption using ccm_memory (recommended for most use cases)
int aes_ccm_decrypt_simple(const unsigned char *key, unsigned long keylen,
                           const unsigned char *nonce, unsigned long noncelen,
                           const unsigned char *aad, unsigned long aadlen,
                           const unsigned char *ciphertext, unsigned long ciphertextlen,
                           unsigned char *plaintext, const unsigned char *tag, 
                           unsigned long taglen) {
    
    int cipher_idx = find_cipher("aes");
    if (cipher_idx == -1) {
        return CRYPT_INVALID_CIPHER;
    }
    
    // LibTomCrypt CCM decryption approach:
    // We need to use the state-based functions for proper decryption with verification
    ccm_state ccm;
    int err;
    
    // Initialize CCM state for decryption
    if ((err = ccm_init(&ccm, cipher_idx, key, keylen, ciphertextlen, taglen, aadlen)) != CRYPT_OK) {
        return err;
    }
    
    // Add nonce
    if ((err = ccm_add_nonce(&ccm, nonce, noncelen)) != CRYPT_OK) {
        ccm_done(&ccm, NULL, 0);
        return err;
    }
    
    // Add AAD if present
    if (aadlen > 0 && aad != NULL) {
        if ((err = ccm_add_aad(&ccm, aad, aadlen)) != CRYPT_OK) {
            ccm_done(&ccm, NULL, 0);
            return err;
        }
    }
    
    // Process ciphertext -> plaintext
    if (ciphertextlen > 0 && ciphertext != NULL) {
        if ((err = ccm_process(&ccm, ciphertext, ciphertextlen, plaintext, CCM_DECRYPT)) != CRYPT_OK) {
            ccm_done(&ccm, NULL, 0);
            return err;
        }
    }
    
    // Compute expected tag
    unsigned char computed_tag[16];
    if ((err = ccm_done(&ccm, computed_tag, taglen)) != CRYPT_OK) {
        return err;
    }
    
    // Verify tag
    if (memcmp(computed_tag, tag, taglen) != 0) {
        return CRYPT_ERROR;
    }
    
    return CRYPT_OK;
}

// Advanced CCM encryption with multiblock support using state functions
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
                return err;
            }
            
            pt_ptr += to_process;
            ct_ptr += to_process;
            remaining -= to_process;
        }
    }
    
    // Generate tag
    if ((err = ccm_done(&ccm, tag, *taglen)) != CRYPT_OK) {
        printf("CCM done failed: %s\n", error_to_string(err));
        return err;
    }
    
    return CRYPT_OK;
}

// Advanced CCM decryption with multiblock support using state functions
int aes_ccm_decrypt_multiblock(const unsigned char *key, unsigned long keylen,
                               const unsigned char *nonce, unsigned long noncelen,
                               const unsigned char *aad, unsigned long aadlen,
                               const unsigned char *ciphertext, unsigned long ciphertextlen,
                               unsigned char *plaintext, const unsigned char *tag, 
                               unsigned long taglen) {
    
    // For LibTomCrypt CCM, it's easier to use the simple approach for decryption
    // as the state-based approach for decryption with verification is complex
    return aes_ccm_decrypt_simple(key, keylen, nonce, noncelen, aad, aadlen,
                                  ciphertext, ciphertextlen, plaintext, tag, taglen);
}

// Streaming CCM encryption for very large files
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
        return err;
    }
    
    // Add AAD
    if (aadlen > 0 && aad != NULL) {
        if ((err = ccm_add_aad(&ccm, aad, aadlen)) != CRYPT_OK) {
            return err;
        }
    }
    
    // Process file in chunks
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), input_file)) > 0) {
        unsigned char ciphertext[sizeof(buffer)];
        
        if ((err = ccm_process(&ccm, buffer, bytes_read, ciphertext, CCM_ENCRYPT)) != CRYPT_OK) {
            return err;
        }
        
        if (fwrite(ciphertext, 1, bytes_read, output_file) != bytes_read) {
            return CRYPT_ERROR;
        }
    }
    
    // Generate tag
    if ((err = ccm_done(&ccm, tag, *taglen)) != CRYPT_OK) {
        return err;
    }
    
    return CRYPT_OK;
}

// Streaming CCM decryption for very large files
int aes_ccm_decrypt_streaming(const unsigned char *key, unsigned long keylen,
                              const unsigned char *nonce, unsigned long noncelen,
                              const unsigned char *aad, unsigned long aadlen,
                              FILE *input_file, FILE *output_file,
                              const unsigned char *tag, unsigned long taglen,
                              unsigned long total_ciphertext_len) {
    
    // For streaming decryption, we need to read the entire file first
    // because CCM requires the full message for authentication
    
    // This is a limitation of CCM - it's not truly streamable for decryption
    // because authentication happens at the end
    
    unsigned char *full_ciphertext = malloc(total_ciphertext_len);
    unsigned char *full_plaintext = malloc(total_ciphertext_len);
    
    if (!full_ciphertext || !full_plaintext) {
        free(full_ciphertext);
        free(full_plaintext);
        return CRYPT_MEM;
    }
    
    // Read entire ciphertext
    if (fread(full_ciphertext, 1, total_ciphertext_len, input_file) != total_ciphertext_len) {
        free(full_ciphertext);
        free(full_plaintext);
        return CRYPT_ERROR;
    }
    
    // Decrypt using simple function
    int err = aes_ccm_decrypt_simple(key, keylen, nonce, noncelen, aad, aadlen,
                                     full_ciphertext, total_ciphertext_len,
                                     full_plaintext, tag, taglen);
    
    if (err == CRYPT_OK) {
        // Write decrypted data
        if (fwrite(full_plaintext, 1, total_ciphertext_len, output_file) != total_ciphertext_len) {
            err = CRYPT_ERROR;
        }
    }
    
    free(full_ciphertext);
    free(full_plaintext);
    return err;
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
    
    // Test 1: Simple functions (recommended approach)
    printf("\n--- Test 1: Simple CCM Functions ---\n");
    
    // Encrypt using simple function
    printf("Encrypting with simple function...\n");
    if ((err = aes_ccm_encrypt_simple(key, sizeof(key), nonce, sizeof(nonce),
                                     aad, sizeof(aad), plaintext, sizeof(plaintext),
                                     ciphertext, tag, &taglen)) != CRYPT_OK) {
        printf("Simple encryption failed: %s\n", error_to_string(err));
        return 1;
    }
    
    print_hex("Tag", tag, taglen);
    printf("First 32 bytes of ciphertext: ");
    for (int i = 0; i < 32; i++) {
        printf("%02x ", ciphertext[i]);
    }
    printf("\n");
    
    // Decrypt using simple function
    printf("Decrypting with simple function...\n");
    if ((err = aes_ccm_decrypt_simple(key, sizeof(key), nonce, sizeof(nonce),
                                     aad, sizeof(aad), ciphertext, sizeof(ciphertext),
                                     decrypted, tag, taglen)) != CRYPT_OK) {
        printf("Simple decryption failed: %s\n", error_to_string(err));
        return 1;
    }
    
    // Verify
    if (memcmp(plaintext, decrypted, sizeof(plaintext)) == 0) {
        printf("SUCCESS: Simple functions work correctly\n");
    } else {
        printf("FAILURE: Simple functions failed\n");
        return 1;
    }
    
    // Test 2: Multiblock functions
    printf("\n--- Test 2: Multiblock CCM Functions ---\n");
    
    // Reset tag length
    taglen = 16;
    
    // Encrypt using multiblock function
    printf("Encrypting with multiblock function...\n");
    if ((err = aes_ccm_encrypt_multiblock(key, sizeof(key), nonce, sizeof(nonce),
                                         aad, sizeof(aad), plaintext, sizeof(plaintext),
                                         ciphertext, tag, &taglen)) != CRYPT_OK) {
        printf("Multiblock encryption failed: %s\n", error_to_string(err));
        return 1;
    }
    
    // Decrypt using multiblock function
    printf("Decrypting with multiblock function...\n");
    if ((err = aes_ccm_decrypt_multiblock(key, sizeof(key), nonce, sizeof(nonce),
                                         aad, sizeof(aad), ciphertext, sizeof(ciphertext),
                                         decrypted, tag, taglen)) != CRYPT_OK) {
        printf("Multiblock decryption failed: %s\n", error_to_string(err));
        return 1;
    }
    
    // Verify
    if (memcmp(plaintext, decrypted, sizeof(plaintext)) == 0) {
        printf("SUCCESS: Multiblock functions work correctly\n");
    } else {
        printf("FAILURE: Multiblock functions failed\n");
        return 1;
    }
    
    // Test 3: Authentication failure test
    printf("\n--- Test 3: Authentication Failure Test ---\n");
    unsigned char bad_tag[16];
    memcpy(bad_tag, tag, sizeof(bad_tag));
    bad_tag[0] ^= 0x01; // Corrupt the tag
    
    if ((err = aes_ccm_decrypt_simple(key, sizeof(key), nonce, sizeof(nonce),
                                     aad, sizeof(aad), ciphertext, sizeof(ciphertext),
                                     decrypted, bad_tag, taglen)) == CRYPT_ERROR) {
        printf("SUCCESS: Authentication failure correctly detected\n");
    } else {
        printf("FAILURE: Authentication failure not detected\n");
        return 1;
    }
    
    // Test 4: No AAD test
    printf("\n--- Test 4: No AAD Test ---\n");
    unsigned char tag_no_aad[16];
    unsigned long taglen_no_aad = 16;
    
    if ((err = aes_ccm_encrypt_simple(key, sizeof(key), nonce, sizeof(nonce),
                                     NULL, 0, plaintext, sizeof(plaintext),
                                     ciphertext, tag_no_aad, &taglen_no_aad)) != CRYPT_OK) {
        printf("Encryption without AAD failed: %s\n", error_to_string(err));
        return 1;
    }
    
    if ((err = aes_ccm_decrypt_simple(key, sizeof(key), nonce, sizeof(nonce),
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
    
    // Test 5: Small data test
    printf("\n--- Test 5: Small Data Test ---\n");
    unsigned char small_pt[] = "Hello, World!";
    unsigned char small_ct[sizeof(small_pt)];
    unsigned char small_dec[sizeof(small_pt)];
    unsigned char small_tag[16];
    unsigned long small_taglen = 16;
    
    if ((err = aes_ccm_encrypt_simple(key, sizeof(key), nonce, sizeof(nonce),
                                     NULL, 0, small_pt, sizeof(small_pt),
                                     small_ct, small_tag, &small_taglen)) != CRYPT_OK) {
        printf("Small data encryption failed: %s\n", error_to_string(err));
        return 1;
    }
    
    if ((err = aes_ccm_decrypt_simple(key, sizeof(key), nonce, sizeof(nonce),
                                     NULL, 0, small_ct, sizeof(small_ct),
                                     small_dec, small_tag, small_taglen)) != CRYPT_OK) {
        printf("Small data decryption failed: %s\n", error_to_string(err));
        return 1;
    }
    
    if (memcmp(small_pt, small_dec, sizeof(small_pt)) == 0) {
        printf("SUCCESS: Small data test passed\n");
    } else {
        printf("FAILURE: Small data test failed\n");
        return 1;
    }
    
    printf("\n=== All tests passed! ===\n");
    printf("The implementation successfully handles:\n");
    printf("- Simple CCM encryption/decryption (recommended)\n");
    printf("- Multiblock messages (%lu bytes)\n", sizeof(plaintext));
    printf("- Multiblock AAD (%lu bytes)\n", sizeof(aad));
    printf("- Authentication verification\n");
    printf("- Various input scenarios\n");
    printf("- Small and large data sizes\n");
    
    return 0;
}
