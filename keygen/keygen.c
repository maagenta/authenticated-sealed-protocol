#include "../protocol.h"
#include <sodium.h>
#include <stdio.h>
#include <sys/stat.h>

/* Write one key as a single line of base64 (standard variant), mode 0600. */
static int write_key_file(const char *path,
                            const unsigned char *key, size_t key_len) {
    char b64[512];
    sodium_bin2base64(b64, sizeof(b64), key, key_len,
                      sodium_base64_VARIANT_ORIGINAL);

    FILE *f = fopen(path, "w");
    if (!f) {
        fprintf(stderr, "Error: could not create %s\n", path);
        return -1;
    }
    fprintf(f, "%s\n", b64);
    fclose(f);
    chmod(path, 0600);
    printf("  Created: %s\n", path);
    return 0;
}

int main(void) {
    if (sodium_init() < 0) {
        fprintf(stderr, "Error: could not initialize libsodium\n");
        return 1;
    }

    printf("=== proto key generator ===\n\n");

    /* --- Authentication key pair (Ed25519) --- */
    printf("Generating authentication key pair (Ed25519)...\n");
    unsigned char auth_pk[AUTH_PK_LEN];
    unsigned char auth_sk[AUTH_SK_LEN];
    crypto_sign_keypair(auth_pk, auth_sk);

    if (write_key_file("auth.key", auth_sk, AUTH_SK_LEN) != 0)
        return 1;
    if (write_key_file("auth.pub", auth_pk, AUTH_PK_LEN) != 0)
        return 1;

    /* --- Encryption key pair (X25519) --- */
    /* Only the secret key is written: the public key is re-derived from it
     * on load (proto_load_keys) and reaches the server via REGISTER. */
    printf("\nGenerating encryption key pair (X25519)...\n");
    unsigned char enc_pk[ENC_PK_LEN];
    unsigned char enc_sk[ENC_SK_LEN];
    crypto_box_keypair(enc_pk, enc_sk);

    if (write_key_file("enc.key", enc_sk, ENC_SK_LEN) != 0)
        return 1;

    printf("\nKeys generated successfully:\n");
    printf("  auth.key  — authentication private key (KEEP SECRET)\n");
    printf("  auth.pub  — authentication public key  (server allowlist)\n");
    printf("  enc.key   — encryption private key     (KEEP SECRET)\n");
    printf("\nClients load auth.key + enc.key  (proto_load_keys).\n");
    printf("Servers load auth.pub             (proto_load_pubkey_hex).\n");
    return 0;
}
