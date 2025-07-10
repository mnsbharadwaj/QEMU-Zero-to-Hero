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
    // Using a known test vector from RFC 3610
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
    unsigned long taglen = sizeof(tag);
    
    unsigned long ptlen = sizeof(pt);
    unsigned long noncelen = sizeof(nonce);
    unsigned long headerlen = sizeof(header);
    
    printf("======== RFC 3610 TEST VECTOR ========\n");
    print_hex("Key        ", key, sizeof(key));
    print_hex("Nonce      ", nonce, noncelen);
    print_hex("Header     ", header, headerlen);
    print_hex("Plaintext  ", pt, ptlen);
    printf("Plaintext length: %lu\n", ptlen);
    printf("Header length: %lu\n", headerlen);
    printf("Tag length: %lu\n", taglen);
    
    // Encrypt using one-shot function
    err = ccm_memory(
        cipher_idx,
        key, sizeof(key),
        NULL,           // PRNG state (not used)
        nonce, noncelen,
        header, headerlen,
        pt, ptlen,
        ct,             // Output ciphertext
        tag, &taglen,
        CCM_ENCRYPT
    );
    if (err != CRYPT_OK) 
        handle_error("ccm_memory (encrypt) failed", err);
    
    printf("\nENCRYPTION SUCCESS\n");
    print_hex("Ciphertext ", ct, ptlen);
    print_hex("Tag        ", tag, taglen);
    
    // Expected results
    unsigned char expected_tag[8] = {0x1F, 0x24, 0x7C, 0x89, 0xA8, 0x10, 0x7D, 0x22};
    print_hex("Expected tag", expected_tag, sizeof(expected_tag));
    
    // Compare the generated tag with the expected one
    if (memcmp(tag, expected_tag, taglen) != 0) {
        printf("ERROR: Tag does not match expected value!\n");
    } else {
        printf("SUCCESS: Tag matches expected value!\n");
    }
    
    // Decrypt using one-shot function
    unsigned char decrypted_tag[8];
    unsigned long decrypted_taglen = taglen;
    
    err = ccm_memory(
        cipher_idx,
        key, sizeof(key),
        NULL,
        nonce, noncelen,
        header, headerlen,
        ct, ptlen,      // Input ciphertext
        decrypted,      // Output plaintext
        decrypted_tag, &decrypted_taglen,
        CCM_DECRYPT
    );
    if (err != CRYPT_OK) 
        handle_error("ccm_memory (decrypt) failed", err);
    
    printf("\nDECRYPTION COMPLETE\n");
    print_hex("Decrypted  ", decrypted, ptlen);
    
    // Verify decrypted text
    if (memcmp(pt, decrypted, ptlen) == 0) {
        printf("SUCCESS: Decrypted text matches original!\n");
    } else {
        printf("ERROR: Decrypted text mismatch!\n");
    }
    
    // Verify the tag during decryption (should be same as the one we got during encryption)
    if (memcmp(tag, decrypted_tag, taglen) == 0) {
        printf("SUCCESS: Decryption tag matches encryption tag!\n");
    } else {
        printf("ERROR: Decryption tag does not match encryption tag!\n");
        print_hex("Encryption tag", tag, taglen);
        print_hex("Decryption tag", decrypted_tag, taglen);
    }
    
    // Cleanup
    unregister_cipher(&aes_desc);
    return 0;
}
