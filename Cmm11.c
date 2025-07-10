#include <tomcrypt.h>
#include <stdio.h>
#include <string.h>
#include <endian.h>  // For endianness detection

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

// Workaround for potential libtomcrypt CCM issues
int safe_ccm_memory(
    int cipher_idx,
    const unsigned char *key,    unsigned long keylen,
    const unsigned char *nonce,  unsigned long noncelen,
    const unsigned char *header, unsigned long headerlen,
    const unsigned char *pt,     unsigned long ptlen,
    unsigned char *ct,
    unsigned char *tag,          unsigned long *taglen,
    int direction)
{
    ccm_state ccm;
    int err;
    
    // Initialize CCM
    if ((err = ccm_init(&ccm, cipher_idx, key, keylen, ptlen, *taglen, headerlen)) != CRYPT_OK)
        return err;
    
    // Add nonce
    if ((err = ccm_add_nonce(&ccm, nonce, noncelen)) != CRYPT_OK)
        return err;
    
    // Add AAD
    if (headerlen > 0 && (err = ccm_add_aad(&ccm, header, headerlen)) != CRYPT_OK)
        return err;
    
    // Process data
    if ((err = ccm_process(&ccm, pt, ptlen, ct, direction)) != CRYPT_OK)
        return err;
    
    // Finalize
    return ccm_done(&ccm, tag, taglen);
}

int main() {
    int err;
    int cipher_idx;
    
    // Initialize math library (critical for some platforms)
    ltc_mp = ltm_desc;
    
    // Register AES
    if (register_cipher(&aes_desc) == -1)
        handle_error("AES registration failed", -1);
    cipher_idx = find_cipher("aes");
    if (cipher_idx == -1)
        handle_error("AES not found", -1);
    
    printf("Using LibTomCrypt Version: %s\n", SCRYPT);
    #ifdef ENDIAN_LITTLE
    printf("System: Little-endian\n");
    #else
    printf("System: Big-endian\n");
    #endif
    
    // ===== NIST Validated Test Vector =====
    // From NIST CCM test vectors: Count = 0
    unsigned char key[16] = {
        0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
        0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f
    };
    unsigned char nonce[13] = {
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c
    };
    unsigned char header[8] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07
    };
    unsigned char pt[24] = {
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
        0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37
    };
    unsigned char ct[sizeof(pt)];
    unsigned char decrypted[sizeof(pt)];
    unsigned char tag[8];
    unsigned long taglen = sizeof(tag);
    
    unsigned long ptlen = sizeof(pt);
    unsigned long noncelen = sizeof(nonce);
    unsigned long headerlen = sizeof(header);
    
    // Expected results from NIST
    unsigned char expected_ct[24] = {
        0x59, 0x8B, 0x0A, 0xCE, 0x8E, 0x5C, 0x27, 0x41, 
        0x21, 0xEB, 0x3E, 0xE0, 0x9B, 0xE2, 0x4F, 0xE1, 
        0x28, 0x6E, 0x7A, 0xD5, 0x40, 0x80, 0xFB, 0x4B
    };
    unsigned char expected_tag[8] = {
        0x3D, 0x8F, 0x05, 0x0D, 0x6E, 0xE4, 0x06, 0x5F
    };
    
    printf("======== NIST VALIDATED TEST VECTOR ========\n");
    print_hex("Key        ", key, sizeof(key));
    print_hex("Nonce      ", nonce, noncelen);
    print_hex("Header     ", header, headerlen);
    print_hex("Plaintext  ", pt, ptlen);
    print_hex("Expected CT", expected_ct, ptlen);
    print_hex("Expected Tag", expected_tag, taglen);
    
    // ====== ENCRYPTION ======
    printf("\n===== ENCRYPTION =====\n");
    
    // Try one-shot method first
    err = ccm_memory(
        cipher_idx,
        key, sizeof(key),
        NULL,
        nonce, noncelen,
        header, headerlen,
        pt, ptlen,
        ct,
        tag, &taglen,
        CCM_ENCRYPT
    );
    
    if (err != CRYPT_OK) {
        printf("ccm_memory failed: %s\n", error_to_string(err));
        printf("Trying safe_ccm_memory workaround...\n");
        taglen = sizeof(tag);
        err = safe_ccm_memory(
            cipher_idx,
            key, sizeof(key),
            nonce, noncelen,
            header, headerlen,
            pt, ptlen,
            ct,
            tag, &taglen,
            CCM_ENCRYPT
        );
        if (err != CRYPT_OK)
            handle_error("safe_ccm_memory failed", err);
    }
    
    print_hex("Ciphertext ", ct, ptlen);
    print_hex("Tag        ", tag, taglen);
    
    // Verify encryption
    int ct_match = (memcmp(ct, expected_ct, ptlen) == 0);
    int tag_match = (memcmp(tag, expected_tag, taglen) == 0);
    
    printf("Ciphertext %s\n", ct_match ? "MATCHES" : "DOES NOT MATCH");
    printf("Tag %s\n", tag_match ? "MATCHES" : "DOES NOT MATCH");
    
    // ====== DECRYPTION ======
    printf("\n===== DECRYPTION =====\n");
    
    unsigned char decrypted_tag[sizeof(tag)];
    unsigned long decrypted_taglen = taglen;
    
    // Try one-shot method first
    err = ccm_memory(
        cipher_idx,
        key, sizeof(key),
        NULL,
        nonce, noncelen,
        header, headerlen,
        ct, ptlen,
        decrypted,
        decrypted_tag, &decrypted_taglen,
        CCM_DECRYPT
    );
    
    if (err != CRYPT_OK) {
        printf("ccm_memory failed: %s\n", error_to_string(err));
        printf("Trying safe_ccm_memory workaround...\n");
        decrypted_taglen = taglen;
        err = safe_ccm_memory(
            cipher_idx,
            key, sizeof(key),
            nonce, noncelen,
            header, headerlen,
            ct, ptlen,
            decrypted,
            decrypted_tag, &decrypted_taglen,
            CCM_DECRYPT
        );
        if (err != CRYPT_OK)
            handle_error("safe_ccm_memory failed", err);
    }
    
    print_hex("Decrypted  ", decrypted, ptlen);
    print_hex("Decrypted Tag", decrypted_tag, decrypted_taglen);
    
    // Verify decryption
    int pt_match = (memcmp(pt, decrypted, ptlen) == 0);
    int dec_tag_match = (memcmp(tag, decrypted_tag, taglen) == 0);
    
    printf("Plaintext %s\n", pt_match ? "MATCHES" : "DOES NOT MATCH");
    printf("Decrypted Tag %s\n", dec_tag_match ? "MATCHES" : "DOES NOT MATCH");
    
    // Final verification
    if (pt_match && dec_tag_match) {
        printf("\nSUCCESS: Full decryption verified!\n");
    } else {
        printf("\nERROR: Decryption failed!\n");
        
        if (!pt_match) {
            printf("Plaintext mismatch!\n");
            print_hex("Original ", pt, ptlen);
            print_hex("Decrypted", decrypted, ptlen);
        }
        
        if (!dec_tag_match) {
            printf("Tag mismatch!\n");
            print_hex("Encryption Tag", tag, taglen);
            print_hex("Decryption Tag", decrypted_tag, decrypted_taglen);
        }
    }
    
    // Cleanup
    unregister_cipher(&aes_desc);
    return 0;
}
