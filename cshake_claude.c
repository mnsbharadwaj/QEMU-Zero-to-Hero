#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libkeccak.h>

// Function to convert bytes to hex string for display
void bytes_to_hex(const unsigned char *bytes, size_t len, char *hex_str) {
    for (size_t i = 0; i < len; i++) {
        sprintf(hex_str + (i * 2), "%02x", bytes[i]);
    }
    hex_str[len * 2] = '\0';
}

// Function to compute CSHAKE hash of multipart message (data already bytepadded)
int compute_cshake_multipart(const char **message_parts, size_t *part_lengths, 
                           size_t num_parts, size_t output_length,
                           char *hash_output) {
    
    struct libkeccak_spec spec;
    struct libkeccak_state state;
    int ret;
    
    // Set up CSHAKE256 specification
    libkeccak_spec_cshake(&spec, 256, output_length * 8);
    
    // Initialize the state
    ret = libkeccak_state_initialise(&state, &spec);
    if (ret) {
        fprintf(stderr, "Failed to initialize Keccak state: %d\n", ret);
        return -1;
    }
    
    // Absorb all message parts (assuming data is already bytepadded)
    for (size_t i = 0; i < num_parts; i++) {
        if (message_parts[i] && part_lengths[i] > 0) {
            ret = libkeccak_update(&state, message_parts[i], part_lengths[i]);
            if (ret) {
                fprintf(stderr, "Failed to update state with message part %zu: %d\n", i, ret);
                libkeccak_state_destroy(&state);
                return -1;
            }
        }
    }
    
    // Finalize and get the hash using libkeccak_digest
    ret = libkeccak_digest(&state, NULL, 0, 0, "", hash_output);
    if (ret) {
        fprintf(stderr, "Failed to finalize hash computation: %d\n", ret);
        libkeccak_state_destroy(&state);
        return -1;
    }
    
    // Clean up
    libkeccak_state_destroy(&state);
    return 0;
}

// Alternative single message function
int compute_cshake_single(const char *message, size_t message_length,
                         size_t output_length, char *hash_output) {
    
    struct libkeccak_spec spec;
    struct libkeccak_state state;
    int ret;
    
    // Set up CSHAKE256 specification
    libkeccak_spec_cshake(&spec, 256, output_length * 8);
    
    // Initialize the state
    ret = libkeccak_state_initialise(&state, &spec);
    if (ret) {
        fprintf(stderr, "Failed to initialize Keccak state: %d\n", ret);
        return -1;
    }
    
    // Use libkeccak_digest directly with the complete message
    ret = libkeccak_digest(&state, message, message_length, 0, "", hash_output);
    if (ret) {
        fprintf(stderr, "Failed to compute hash: %d\n", ret);
        libkeccak_state_destroy(&state);
        return -1;
    }
    
    // Clean up
    libkeccak_state_destroy(&state);
    return 0;
}

// Function for CSHAKE128 variant
int compute_cshake128_single(const char *message, size_t message_length,
                           size_t output_length, char *hash_output) {
    
    struct libkeccak_spec spec;
    struct libkeccak_state state;
    int ret;
    
    // Set up CSHAKE128 specification
    libkeccak_spec_cshake(&spec, 128, output_length * 8);
    
    // Initialize the state
    ret = libkeccak_state_initialise(&state, &spec);
    if (ret) {
        fprintf(stderr, "Failed to initialize Keccak state: %d\n", ret);
        return -1;
    }
    
    // Use libkeccak_digest directly with the complete message
    ret = libkeccak_digest(&state, message, message_length, 0, "", hash_output);
    if (ret) {
        fprintf(stderr, "Failed to compute hash: %d\n", ret);
        libkeccak_state_destroy(&state);
        return -1;
    }
    
    // Clean up
    libkeccak_state_destroy(&state);
    return 0;
}

int main() {
    // Example usage
    const char *message_parts[] = {
        "First part of message",
        "Second part of message", 
        "Third part of message"
    };
    
    size_t part_lengths[] = {
        strlen("First part of message"),
        strlen("Second part of message"),
        strlen("Third part of message")
    };
    
    size_t num_parts = 3;
    size_t output_length = 32; // 256 bits = 32 bytes
    
    char hash_output[32];
    char hex_output[65]; // 32 bytes * 2 + null terminator
    
    printf("Computing CSHAKE hash for multipart message...\n");
    printf("Using Codeberg mattias-ae/libkeccak implementation\n\n");
    
    // Method 1: Multipart processing
    printf("Method 1: Multipart processing\n");
    int result = compute_cshake_multipart(message_parts, part_lengths, num_parts, 
                                        output_length, hash_output);
    
    if (result == 0) {
        bytes_to_hex((unsigned char*)hash_output, output_length, hex_output);
        printf("CSHAKE Hash (multipart): %s\n", hex_output);
    } else {
        printf("Multipart hash computation failed\n");
    }
    
    // Method 2: Single concatenated message
    printf("\nMethod 2: Single message processing\n");
    char concatenated[1000] = {0};
    size_t total_len = 0;
    
    for (size_t i = 0; i < num_parts; i++) {
        strcat(concatenated, message_parts[i]);
        total_len += part_lengths[i];
    }
    
    memset(hash_output, 0, sizeof(hash_output));
    result = compute_cshake_single(concatenated, total_len, output_length, hash_output);
    
    if (result == 0) {
        bytes_to_hex((unsigned char*)hash_output, output_length, hex_output);
        printf("CSHAKE Hash (single): %s\n", hex_output);
    } else {
        printf("Single message hash computation failed\n");
    }
    
    // Method 3: Using CSHAKE128 variant
    printf("\nMethod 3: CSHAKE128 variant\n");
    memset(hash_output, 0, sizeof(hash_output));
    result = compute_cshake128_single(concatenated, total_len, output_length, hash_output);
    
    if (result == 0) {
        bytes_to_hex((unsigned char*)hash_output, output_length, hex_output);
        printf("CSHAKE128 Hash: %s\n", hex_output);
    } else {
        printf("CSHAKE128 hash computation failed\n");
    }
    
    printf("\nHash length: %zu bytes\n", output_length);
    return 0;
}

/*
 * Compilation instructions for Codeberg mattias-ae/libkeccak:
 * 
 * 1. Clone the repository:
 *    git clone https://codeberg.org/mattias-ae/libkeccak.git
 * 
 * 2. Build and install libkeccak:
 *    cd libkeccak
 *    make
 *    sudo make install
 * 
 * 3. Compile this program:
 *    gcc -o cshake_hash cshake_hash.c -lkeccak
 *    
 * 4. Or with explicit library path:
 *    gcc -o cshake_hash cshake_hash.c -L/usr/local/lib -lkeccak -I/usr/local/include
 */
