#include "crypto.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Read the first line of a file and decode it from base64. */
static int read_b64_key(const char *path,
                        unsigned char *out, size_t expected_len) {
    FILE *f = fopen(path, "r");
    if (!f) {
        fprintf(stderr, "Error: could not open %s\n", path);
        return -1;
    }
    char line[512];
    if (!fgets(line, sizeof(line), f)) {
        fclose(f);
        fprintf(stderr, "Error: empty file %s\n", path);
        return -1;
    }
    fclose(f);

    size_t l = strlen(line);
    while (l > 0 && (line[l-1] == '\n' || line[l-1] == '\r'))
        line[--l] = '\0';

    size_t bin_len = 0;
    if (sodium_base642bin(out, expected_len, line, l,
                          NULL, &bin_len, NULL,
                          sodium_base64_VARIANT_ORIGINAL) != 0
        || bin_len != expected_len) {
        fprintf(stderr, "Error: invalid key format in %s\n", path);
        return -1;
    }
    return 0;
}

int proto_init(void) {
    return sodium_init() < 0 ? -1 : 0;
}

int proto_load_keys(const char *auth_sk_path,
                    const char *enc_sk_path,
                    proto_keys_t *out) {
    /* Ed25519 authentication private key (64 bytes) */
    if (read_b64_key(auth_sk_path, out->auth_sk, AUTH_SK_LEN) != 0)
        return -1;

    /* In libsodium, auth_sk = seed(32) || pubkey(32) */
    memcpy(out->auth_pk, out->auth_sk + 32, AUTH_PK_LEN);

    /* X25519 encryption private key (32 bytes) */
    if (read_b64_key(enc_sk_path, out->enc_sk, ENC_SK_LEN) != 0)
        return -1;

    crypto_scalarmult_base(out->enc_pk, out->enc_sk);
    return 0;
}

int proto_load_pubkey_hex(const char *path, char *hex_out, size_t hex_sz) {
    unsigned char pk[AUTH_PK_LEN];
    if (read_b64_key(path, pk, AUTH_PK_LEN) != 0)
        return -1;
    sodium_bin2hex(hex_out, hex_sz, pk, AUTH_PK_LEN);
    return 0;
}

int proto_seal(const unsigned char *msg, size_t msg_len,
               const unsigned char *enc_pk,
               char *out_b64, size_t out_b64_sz) {
    size_t cipher_len = msg_len + crypto_box_SEALBYTES;
    unsigned char *cipher = malloc(cipher_len);
    if (!cipher) return -1;

    if (crypto_box_seal(cipher, msg, msg_len, enc_pk) != 0) {
        free(cipher);
        return -1;
    }

    sodium_bin2base64(out_b64, out_b64_sz,
                      cipher, cipher_len,
                      sodium_base64_VARIANT_ORIGINAL);
    free(cipher);
    return 0;
}

char *proto_seal_new(const unsigned char *msg, size_t msg_len,
                     const unsigned char *enc_pk) {
    size_t cipher_len = msg_len + crypto_box_SEALBYTES;
    size_t b64_sz = sodium_base64_ENCODED_LEN(cipher_len,
                        sodium_base64_VARIANT_ORIGINAL) + 1;
    char *b64 = malloc(b64_sz);
    if (!b64) return NULL;
    if (proto_seal(msg, msg_len, enc_pk, b64, b64_sz) != 0) {
        free(b64);
        return NULL;
    }
    return b64;
}

unsigned char *proto_unseal_new(const char *data_b64,
                                const unsigned char *enc_pk,
                                const unsigned char *enc_sk,
                                size_t *out_len) {
    size_t b64_len = strlen(data_b64);
    unsigned char *cipher = malloc(b64_len ? b64_len : 1);
    if (!cipher) return NULL;

    size_t cipher_len = 0;
    if (sodium_base642bin(cipher, b64_len, data_b64, b64_len,
                          NULL, &cipher_len, NULL,
                          sodium_base64_VARIANT_ORIGINAL) != 0
        || cipher_len < crypto_box_SEALBYTES) {
        free(cipher);
        return NULL;
    }

    size_t plain_len = cipher_len - crypto_box_SEALBYTES;
    unsigned char *plain = malloc(plain_len + 1);
    if (!plain) { free(cipher); return NULL; }

    if (crypto_box_seal_open(plain, cipher, cipher_len, enc_pk, enc_sk) != 0) {
        free(cipher);
        free(plain);
        return NULL;
    }
    free(cipher);

    plain[plain_len] = '\0';
    if (out_len) *out_len = plain_len;
    return plain;
}

int proto_sign_challenge(const unsigned char *challenge, size_t clen,
                         const unsigned char *auth_sk,
                         unsigned char *sig) {
    unsigned long long sig_len;
    if (crypto_sign_detached(sig, &sig_len, challenge, clen, auth_sk) != 0)
        return -1;
    return 0;
}

int proto_verify_challenge(const unsigned char *challenge, size_t clen,
                           const unsigned char *sig,
                           const unsigned char *auth_pk) {
    return crypto_sign_verify_detached(sig, challenge, clen, auth_pk) == 0
           ? 0 : -1;
}
