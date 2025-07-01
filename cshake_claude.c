#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libkeccak.h>

typedef struct {
    libkeccak_state_t state;
    int initialized;
    size_t capacity;
    size_t rate;
} cshake_ctx_t;

/**
 * Initialize cSHAKE context for multipart hashing
 * 
 * @param ctx - cSHAKE context
 * @param capacity - Security parameter (256 for cSHAKE256, 128 for cSHAKE128)
 * @param bytepad_data - Pre-computed bytepad(encode_string(N) || encode_string(S), rate/8)
 * @param bytepad_len - Length of bytepad_data
 * @return 0 on success, -1 on error
 */
int cshake_init(cshake_ctx_t *ctx, int capacity, 
                const uint8_t *bytepad_data, size_t bytepad_len) {
    if (!ctx) return -1;
    
    ctx->capacity = capacity;
    ctx->rate = 1600 - 2 * capacity; // Keccak rate
    
    libkeccak_spec_t spec;
    libkeccak_spec_shake(&spec, ctx->capacity, ctx->capacity);
    
    if (libkeccak_state_initialise(&ctx->state, &spec) < 0) {
        return -1;
    }
    
    // If no bytepad data provided, use regular SHAKE
    if (!bytepad_data || bytepad_len == 0) {
        ctx->initialized = 1;
        return 0;
    }
    
    // Absorb the pre-computed bytepad data
    if (libkeccak_update(&ctx->state, bytepad_data, bytepad_len) < 0) {
        libkeccak_state_destroy(&ctx->state);
        return -1;
    }
    
    ctx->initialized = 1;
    return 0;
}

/**
 * Add message data to cSHAKE context (can be called multiple times)
 * 
 * @param ctx - cSHAKE context
 * @param data - Input message data
 * @param len - Length of input data in bytes
 * @return 0 on success, -1 on error
 */
int cshake_update(cshake_ctx_t *ctx, const uint8_t *data, size_t len) {
    if (!ctx || !ctx->initialized) return -1;
    if (!data && len > 0) return -1;
    if (len == 0) return 0;
    
    return libkeccak_update(&ctx->state, data, len);
}

/**
 * Finalize cSHAKE and produce output
 * 
 * @param ctx - cSHAKE context
 * @param output - Output buffer
 * @param output_len - Desired output length in bytes
 * @return 0 on success, -1 on error
 */
int cshake_final(cshake_ctx_t *ctx, uint8_t *output, size_t output_len) {
    if (!ctx || !ctx->initialized || !output) return -1;
    
    // For cSHAKE, use domain separation 0x04 instead of SHAKE's 0x1F
    int result = libkeccak_digest(&ctx->state, NULL, 0, 0x04, output, output_len);
    
    ctx->initialized = 0;
    return result;
}

/**
 * Clean up cSHAKE context
 */
void cshake_cleanup(cshake_ctx_t *ctx) {
    if (ctx) {
        if (ctx->initialized) {
            libkeccak_state_destroy(&ctx->state);
            ctx->initialized = 0;
        }
    }
}

/**
 * Convenience function for single-shot cSHAKE with pre-computed bytepad data
 */
int cshake_hash(const uint8_t *bytepad_data, size_t bytepad_len,
                const uint8_t *message, size_t msg_len,
                uint8_t *output, size_t output_len,
                int capacity) {
    cshake_ctx_t ctx;
    
    if (cshake_init(&ctx, capacity, bytepad_data, bytepad_len) < 0) {
        return -1;
    }
    
    if (cshake_update(&ctx, message, msg_len) < 0) {
        cshake_cleanup(&ctx);
        return -1;
    }
    
    if (cshake_final(&ctx, output, output_len) < 0) {
        cshake_cleanup(&ctx);
        return -1;
    }
    
    cshake_cleanup(&ctx);
    return 0;
}

// Example usage
int main() {
    // Example: cSHAKE256 with multipart message
    cshake_ctx_t ctx;
    uint8_t output[32];
    
    // Pre-computed bytepad data (you would compute this externally)
    // This would be: bytepad(encode_string(N) || encode_string(S), rate/8)
    // For this example, we'll use empty bytepad data (equivalent to SHAKE)
    const uint8_t *bytepad_data = NULL;
    size_t bytepad_len = 0;
    
    // Initialize cSHAKE256
    if (cshake_init(&ctx, 256, bytepad_data, bytepad_len) < 0) {
        fprintf(stderr, "Failed to initialize cSHAKE\n");
        return 1;
    }
    
    // Add message parts incrementally
    const char *part1 = "This is the first part of ";
    const char *part2 = "a multipart message for ";
    const char *part3 = "cSHAKE hashing.";
    
    if (cshake_update(&ctx, (uint8_t*)part1, strlen(part1)) < 0 ||
        cshake_update(&ctx, (uint8_t*)part2, strlen(part2)) < 0 ||
        cshake_update(&ctx, (uint8_t*)part3, strlen(part3)) < 0) {
        fprintf(stderr, "Failed to update cSHAKE\n");
        cshake_cleanup(&ctx);
        return 1;
    }
    
    // Finalize and get output
    if (cshake_final(&ctx, output, sizeof(output)) < 0) {
        fprintf(stderr, "Failed to finalize cSHAKE\n");
        cshake_cleanup(&ctx);
        return 1;
    }
    
    // Print result
    printf("cSHAKE256 output: ");
    for (int i = 0; i < sizeof(output); i++) {
        printf("%02x", output[i]);
    }
    printf("\n");
    
    cshake_cleanup(&ctx);
    
    // Example with actual bytepad data (you would compute this)
    // For demonstration, let's use some dummy bytepad data
    uint8_t sample_bytepad[] = {
        0x01, 0x20,  // left_encode(32) - example for 4-byte name
        'T', 'e', 's', 't',  // Name "Test" 
        0x01, 0x20,  // left_encode(32) - example for 4-byte custom
        'A', 'p', 'p', 's',  // Custom "Apps"
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // Padding to rate boundary
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        // ... more padding as needed for rate alignment
    };
    
    const char *message = "Single shot message with bytepad";
    uint8_t output2[64];
    
    if (cshake_hash(sample_bytepad, sizeof(sample_bytepad),
                    (uint8_t*)message, strlen(message),
                    output2, sizeof(output2), 256) == 0) {
        printf("cSHAKE256 with bytepad: ");
        for (int i = 0; i < 32; i++) { // Print first 32 bytes
            printf("%02x", output2[i]);
        }
        printf("\n");
    }
    
    return 0;
}
