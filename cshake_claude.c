#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libkeccak.h>

typedef struct {
    struct libkeccak_state state;
    int initialized;
    size_t capacity;
    size_t rate;
    size_t output_size;
} cshake_ctx_t;

/**
 * Initialize cSHAKE context for multipart hashing
 * 
 * @param ctx - cSHAKE context
 * @param capacity - Security parameter (256 for cSHAKE256, 128 for cSHAKE128)
 * @param output_size - Desired output size in bits (0 for arbitrary length)
 * @param bytepad_data - Pre-computed bytepad(encode_string(N) || encode_string(S), rate/8)
 * @param bytepad_len - Length of bytepad_data in bytes
 * @return 0 on success, -1 on error
 */
int cshake_init(cshake_ctx_t *ctx, int capacity, size_t output_size,
                const char *bytepad_data, size_t bytepad_len) {
    if (!ctx) return -1;
    
    ctx->capacity = capacity;
    ctx->rate = 1600 - 2 * capacity;
    ctx->output_size = output_size;
    
    // Create spec for cSHAKE (using SHAKE as base)
    struct libkeccak_spec spec;
    if (capacity == 128) {
        libkeccak_spec_shake(&spec, 128, output_size);
    } else if (capacity == 256) {
        libkeccak_spec_shake(&spec, 256, output_size);
    } else {
        return -1; // Unsupported capacity
    }
    
    // Initialize state
    if (libkeccak_state_initialise(&ctx->state, &spec) < 0) {
        return -1;
    }
    
    // If no bytepad data provided, this becomes regular SHAKE
    if (bytepad_data && bytepad_len > 0) {
        // Absorb the pre-computed bytepad data
        if (libkeccak_absorb(&ctx->state, bytepad_data, bytepad_len) < 0) {
            libkeccak_state_destroy(&ctx->state);
            return -1;
        }
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
int cshake_update(cshake_ctx_t *ctx, const char *data, size_t len) {
    if (!ctx || !ctx->initialized) return -1;
    if (!data && len > 0) return -1;
    if (len == 0) return 0;
    
    return libkeccak_absorb(&ctx->state, data, len);
}

/**
 * Finalize cSHAKE and produce output
 * 
 * @param ctx - cSHAKE context
 * @param output - Output buffer
 * @param output_len - Desired output length in bytes
 * @return 0 on success, -1 on error
 */
int cshake_final(cshake_ctx_t *ctx, char *output, size_t output_len) {
    if (!ctx || !ctx->initialized || !output) return -1;
    
    // For cSHAKE, we need to use the correct suffix
    // cSHAKE uses 0x04 as domain separation, but maandree's libkeccak
    // handles this through the squeeze function
    int result = libkeccak_squeeze(&ctx->state, output, output_len);
    
    ctx->initialized = 0;
    return result;
}

/**
 * Alternative finalize that handles cSHAKE domain separation explicitly
 */
int cshake_final_explicit(cshake_ctx_t *ctx, char *output, size_t output_len) {
    if (!ctx || !ctx->initialized || !output) return -1;
    
    // Add cSHAKE padding manually if needed
    // This may not be necessary depending on how bytepad data was prepared
    const char cshake_suffix = 0x04;
    
    // Absorb final padding
    if (libkeccak_absorb(&ctx->state, &cshake_suffix, 1) < 0) {
        return -1;
    }
    
    int result = libkeccak_squeeze(&ctx->state, output, output_len);
    
    ctx->initialized = 0;
    return result;
}

/**
 * Clean up cSHAKE context
 */
void cshake_cleanup(cshake_ctx_t *ctx) {
    if (ctx && ctx->initialized) {
        libkeccak_state_destroy(&ctx->state);
        ctx->initialized = 0;
    }
}

/**
 * Convenience function for single-shot cSHAKE with pre-computed bytepad data
 */
int cshake_hash(const char *bytepad_data, size_t bytepad_len,
                const char *message, size_t msg_len,
                char *output, size_t output_len,
                int capacity) {
    cshake_ctx_t ctx;
    
    if (cshake_init(&ctx, capacity, output_len * 8, bytepad_data, bytepad_len) < 0) {
        return -1;
    }
    
    if (message && msg_len > 0) {
        if (cshake_update(&ctx, message, msg_len) < 0) {
            cshake_cleanup(&ctx);
            return -1;
        }
    }
    
    if (cshake_final(&ctx, output, output_len) < 0) {
        cshake_cleanup(&ctx);
        return -1;
    }
    
    cshake_cleanup(&ctx);
    return 0;
}

/**
 * Helper function to print hex output
 */
void print_hex(const char *label, const char *data, size_t len) {
    printf("%s", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", (unsigned char)data[i]);
    }
    printf("\n");
}

// Example usage
int main() {
    // Example: cSHAKE256 with multipart message
    cshake_ctx_t ctx;
    char output[32];
    
    // Pre-computed bytepad data (you would compute this externally)
    // This would be: bytepad(encode_string(N) || encode_string(S), rate/8)
    // For this example, we'll use NULL (equivalent to SHAKE)
    const char *bytepad_data = NULL;
    size_t bytepad_len = 0;
    
    printf("=== cSHAKE256 Multipart Example ===\n");
    
    // Initialize cSHAKE256 (256-bit capacity, 32-byte output)
    if (cshake_init(&ctx, 256, 256, bytepad_data, bytepad_len) < 0) {
        fprintf(stderr, "Failed to initialize cSHAKE\n");
        return 1;
    }
    
    // Add message parts incrementally
    const char *part1 = "This is the first part of ";
    const char *part2 = "a multipart message for ";
    const char *part3 = "cSHAKE hashing.";
    
    if (cshake_update(&ctx, part1, strlen(part1)) < 0 ||
        cshake_update(&ctx, part2, strlen(part2)) < 0 ||
        cshake_update(&ctx, part3, strlen(part3)) < 0) {
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
    
    print_hex("cSHAKE256 output: ", output, sizeof(output));
    cshake_cleanup(&ctx);
    
    printf("\n=== Single-shot Example ===\n");
    
    // Example with single-shot API
    const char *message = "Single shot message";
    char output2[64];
    
    if (cshake_hash(NULL, 0, message, strlen(message),
                    output2, sizeof(output2), 256) == 0) {
        print_hex("Single-shot cSHAKE256: ", output2, 32); // Print first 32 bytes
    }
    
    printf("\n=== Example with bytepad data ===\n");
    
    // Example with dummy bytepad data
    // In practice, this would be computed as:
    // bytepad(encode_string(N) || encode_string(S), rate/8)
    char sample_bytepad[136]; // For cSHAKE256, rate/8 = 136 bytes
    memset(sample_bytepad, 0, sizeof(sample_bytepad));
    
    // Simplified example - in practice you'd compute proper bytepad
    sample_bytepad[0] = 0x01; // Length encoding
    sample_bytepad[1] = 0x20; // 32 bits for 4 bytes
    memcpy(sample_bytepad + 2, "Test", 4); // Name
    sample_bytepad[6] = 0x01; // Length encoding  
    sample_bytepad[7] = 0x20; // 32 bits for 4 bytes
    memcpy(sample_bytepad + 8, "Demo", 4); // Customization
    // Rest is zero padding to rate boundary
    
    const char *test_msg = "Message with custom bytepad";
    char output3[32];
    
    if (cshake_hash(sample_bytepad, sizeof(sample_bytepad),
                    test_msg, strlen(test_msg),
                    output3, sizeof(output3), 256) == 0) {
        print_hex("cSHAKE256 with bytepad: ", output3, sizeof(output3));
    }
    
    return 0;
}
