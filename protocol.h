#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <sodium.h>

/* Generic, application-agnostic protocol constants. App-specific values
 * (listening port, payload size limits, command set) belong in the app,
 * not here. */

#define CHALLENGE_LEN     32
#define MAX_LINE          16384

/* libsodium key sizes */
#define AUTH_PK_LEN       crypto_sign_PUBLICKEYBYTES   /* 32 bytes Ed25519 */
#define AUTH_SK_LEN       crypto_sign_SECRETKEYBYTES   /* 64 bytes Ed25519 */
#define AUTH_SIG_LEN      crypto_sign_BYTES             /* 64 bytes */
#define ENC_PK_LEN        crypto_box_PUBLICKEYBYTES    /* 32 bytes X25519 */
#define ENC_SK_LEN        crypto_box_SECRETKEYBYTES    /* 32 bytes X25519 */

/*
 * Shared handshake (text lines, binary as base64). Application commands are
 * layered on top by each project and are not defined here.
 *
 *   C->S: HELLO\n
 *   S->C: CHALLENGE <base64_32bytes>\n
 *   C->S: AUTH <auth_pubkey_b64> <signature_b64>\n
 *   S->C: OK\n  |  REGISTER\n  |  FAIL <reason>\n
 *
 *   (first connection, after REGISTER):
 *   C->S: REGISTER <encrypt_pubkey_b64>\n
 *   S->C: OK\n  |  FAIL <reason>\n
 *
 *   ... application commands ...
 *
 *   C->S: QUIT\n
 *   S->C: BYE\n
 */

#endif /* PROTOCOL_H */
