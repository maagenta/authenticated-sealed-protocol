#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <sodium.h>

/* Generic, application-agnostic protocol constants. App-specific values
 * (listening port, payload size limits, command set) belong in the app,
 * not here. */

#define CHALLENGE_LEN     32
#define MAX_LINE          16384

/*
 * Timeouts. Both are build-time policy: a consuming project overrides them
 * from its own Makefile without touching this file, e.g.
 *
 *     CFLAGS += -DHANDSHAKE_TIMEOUT_MS=30000 -DQUIT_TIMEOUT_MS=500
 *
 * The #ifndef makes the values here the defaults, used only when the build
 * says nothing. One more compile-time option of the same kind, READ_CHUNK,
 * is declared in wire.h instead: that module depends on libc alone, and
 * this header pulls in libsodium for the key sizes below.
 */

/* Bound on each handshake line, on either end. Three tiny round trips:
 * generous for a client on a poor link, short for a peer that connected
 * and went quiet. */
#ifndef HANDSHAKE_TIMEOUT_MS
#define HANDSHAKE_TIMEOUT_MS  10000
#endif

/* Courtesy wait for BYE after QUIT. The close that follows ends the
 * connection regardless, so this only bounds how long a polite goodbye
 * may take. */
#ifndef QUIT_TIMEOUT_MS
#define QUIT_TIMEOUT_MS        2000
#endif

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
