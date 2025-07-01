#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libkeccak.h>

void print_hex(const unsigned char *buf, size_t len) {
    for (size_t i = 0; i < len; i++) printf("%02x", buf[i]);
    printf("\n");
}

typedef struct {
    struct libkeccak_spec spec;
    struct libkeccak_state state;
} cshake_ctx;

int cshake_init(cshake_ctx *ctx, int is_cshake128) {
    libkeccak_spec_initialise(&ctx->spec,
                               is_cshake128 ? 1344 : 1088,
                               is_cshake128 ? 256 : 512);

    if (libkeccak_state_initialise(&ctx->state, &ctx->spec) < 0) {
        fprintf(stderr, "State initialise failed\n");
        return -1;
    }
    return 0;
}

int cshake_process(cshake_ctx *ctx, const unsigned char *data, size_t len) {
    if (libkeccak_fast_update(&ctx->state, data, len) < 0) {
        fprintf(stderr, "Update failed\n");
        return -1;
    }
    return 0;
}

int cshake_done(cshake_ctx *ctx, unsigned char *out, size_t outlen) {
    unsigned char suffix_byte = 0x04; // SHAKE/cSHAKE XOF suffix
    if (libkeccak_fast_update(&ctx->state, &suffix_byte, 1) < 0) {
        fprintf(stderr, "Suffix append failed\n");
        return -1;
    }

    libkeccak_squeeze(&ctx->state, out); // Correct: no return value

    libkeccak_state_destroy(&ctx->state);
    return 0;
}

int main() {
    unsigned char data[172];
    for (int i = 0; i < 172; i++) {
        data[i] = i & 0xFF; // Example pattern
    }

    unsigned char out[64];

    printf("cSHAKE128 multiblock (libkeccak): ");
    cshake_ctx ctx;
    cshake_init(&ctx, 1); // cSHAKE128

    cshake_process(&ctx, data, 168);       // first block
    cshake_process(&ctx, data + 168, 4);   // second block
    cshake_done(&ctx, out, 32);            // read first 32 bytes
    print_hex(out, 32);

    printf("cSHAKE256 multiblock (libkeccak): ");
    cshake_init(&ctx, 0); // cSHAKE256

    cshake_process(&ctx, data, 168);       // first block
    cshake_process(&ctx, data + 168, 4);   // second block
    cshake_done(&ctx, out, 32);            // read first 32 bytes
    print_hex(out, 32);

    return 0;
}
