#ifndef PROTO_CRYPTO_H
#define PROTO_CRYPTO_H

#include <sodium.h>
#include <stddef.h>
#include "protocol.h"

/* Identity (Ed25519) + encryption (X25519) keypairs. */
typedef struct {
    unsigned char auth_pk[AUTH_PK_LEN];
    unsigned char auth_sk[AUTH_SK_LEN];
    unsigned char enc_pk[ENC_PK_LEN];
    unsigned char enc_sk[ENC_SK_LEN];
} proto_keys_t;

/* Initialize libsodium. Safe to call more than once. Returns 0/-1. */
int proto_init(void);

/* Load both private keys (base64, one per file) and derive the public keys.
 * Returns 0 on success, -1 on error. */
int proto_load_keys(const char *auth_sk_path,
                    const char *enc_sk_path,
                    proto_keys_t *out);

/* Read an Ed25519 public key file (base64) and hex-encode it into hex_out. */
int proto_load_pubkey_hex(const char *path, char *hex_out, size_t hex_sz);

/* Seal a message to enc_pk (anonymous sealed box), base64 into out_b64.
 * out_b64 must be >= sodium_base64_ENCODED_LEN(msg_len + crypto_box_SEALBYTES,
 * sodium_base64_VARIANT_ORIGINAL) + 1 bytes. Returns 0/-1. */
int proto_seal(const unsigned char *msg, size_t msg_len,
               const unsigned char *enc_pk,
               char *out_b64, size_t out_b64_sz);

/* Seal a message of any size and return a heap-allocated base64 string
 * (NUL-terminated, caller frees). Binary-safe. Returns NULL on error. */
char *proto_seal_new(const unsigned char *msg, size_t msg_len,
                     const unsigned char *enc_pk);

/* Open a base64 sealed box into a heap-allocated buffer (caller frees).
 * A trailing NUL is appended for text convenience; *out_len (if non-NULL)
 * receives the true plaintext length. Returns NULL on error. */
unsigned char *proto_unseal_new(const char *data_b64,
                                const unsigned char *enc_pk,
                                const unsigned char *enc_sk,
                                size_t *out_len);

/* Sign a challenge with the auth private key. sig must be >= AUTH_SIG_LEN. */
int proto_sign_challenge(const unsigned char *challenge, size_t clen,
                         const unsigned char *auth_sk,
                         unsigned char *sig);

/* Verify a detached challenge signature. Returns 0 if valid, -1 otherwise. */
int proto_verify_challenge(const unsigned char *challenge, size_t clen,
                           const unsigned char *sig,
                           const unsigned char *auth_pk);

#endif /* PROTO_CRYPTO_H */
