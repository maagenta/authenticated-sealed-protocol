#include "crypto.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Read the first line of a file and decode it from base64. The caller is
 * told which of the three things went wrong; it decides whether and where to
 * report it, so nothing is printed here. */
static int read_b64_key(const char *path,
                        unsigned char *out, size_t expected_len) {
    FILE *f = fopen(path, "r");
    if (!f) return PROTO_E_KEY_OPEN;

    char line[512];
    if (!fgets(line, sizeof(line), f)) {
        fclose(f);
        return PROTO_E_KEY_EMPTY;
    }
    fclose(f);

    size_t l = strlen(line);
    while (l > 0 && (line[l-1] == '\n' || line[l-1] == '\r'))
        line[--l] = '\0';

    size_t bin_len = 0;
    if (sodium_base642bin(out, expected_len, line, l,
                          NULL, &bin_len, NULL,
                          sodium_base64_VARIANT_ORIGINAL) != 0
        || bin_len != expected_len)
        return PROTO_E_KEY_FORMAT;

    return PROTO_OK;
}

int proto_init(void) {
    return sodium_init() < 0 ? PROTO_E_SODIUM : PROTO_OK;
}

int proto_load_keys(const char *auth_sk_path,
                    const char *enc_sk_path,
                    proto_keys_t *out) {
    /* Ed25519 authentication private key (64 bytes). The code says what went
     * wrong but not which of the two files; call this once per file if that
     * distinction matters. */
    int rc = read_b64_key(auth_sk_path, out->auth_sk, AUTH_SK_LEN);
    if (rc != PROTO_OK) return rc;

    /* In libsodium, auth_sk = seed(32) || pubkey(32) */
    memcpy(out->auth_pk, out->auth_sk + 32, AUTH_PK_LEN);

    /* X25519 encryption private key (32 bytes) */
    rc = read_b64_key(enc_sk_path, out->enc_sk, ENC_SK_LEN);
    if (rc != PROTO_OK) return rc;

    crypto_scalarmult_base(out->enc_pk, out->enc_sk);
    return PROTO_OK;
}

int proto_load_pubkey_hex(const char *path, char *hex_out, size_t hex_sz) {
    /* sodium_bin2hex aborts the process on an undersized buffer, so check
     * before handing it one. */
    if (hex_sz < AUTH_PK_LEN * 2 + 1) return PROTO_E_BUFFER_TOO_SMALL;

    unsigned char pk[AUTH_PK_LEN];
    int rc = read_b64_key(path, pk, AUTH_PK_LEN);
    if (rc != PROTO_OK) return rc;

    sodium_bin2hex(hex_out, hex_sz, pk, AUTH_PK_LEN);
    return PROTO_OK;
}

int proto_seal(const unsigned char *msg, size_t msg_len,
               const unsigned char *enc_pk,
               char *out_b64, size_t out_b64_sz) {
    size_t cipher_len = msg_len + crypto_box_SEALBYTES;

    /* sodium_bin2base64 aborts the process on an undersized buffer, so check
     * before handing it one. */
    if (out_b64_sz < sodium_base64_ENCODED_LEN(cipher_len,
                         sodium_base64_VARIANT_ORIGINAL))
        return PROTO_E_BUFFER_TOO_SMALL;

    unsigned char *cipher = malloc(cipher_len);
    if (!cipher) return PROTO_E_NOMEM;

    if (crypto_box_seal(cipher, msg, msg_len, enc_pk) != 0) {
        free(cipher);
        return PROTO_E_CRYPTO;
    }

    sodium_bin2base64(out_b64, out_b64_sz,
                      cipher, cipher_len,
                      sodium_base64_VARIANT_ORIGINAL);
    free(cipher);
    return PROTO_OK;
}

char *proto_seal_new(const unsigned char *msg, size_t msg_len,
                     const unsigned char *enc_pk) {
    size_t cipher_len = msg_len + crypto_box_SEALBYTES;
    /* ENCODED_LEN already counts the trailing NUL; proto_seal checks against
     * the same figure, so adding 1 here would over-allocate and suggest the
     * check is too lax. */
    size_t b64_sz = sodium_base64_ENCODED_LEN(cipher_len,
                        sodium_base64_VARIANT_ORIGINAL);
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
    /* base64 is always longer than what it encodes (4 chars per 3 bytes), so
     * the encoded length is a safe upper bound for the decoded buffer.
     * malloc(0) is implementation-defined, hence the floor of 1. */
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
        return PROTO_E_CRYPTO;
    return PROTO_OK;
}

int proto_verify_challenge(const unsigned char *challenge, size_t clen,
                           const unsigned char *sig,
                           const unsigned char *auth_pk) {
    return crypto_sign_verify_detached(sig, challenge, clen, auth_pk) == 0
           ? PROTO_OK : PROTO_E_BAD_SIGNATURE;
}
