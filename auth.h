#ifndef PROTO_AUTH_H
#define PROTO_AUTH_H

#include "crypto.h"
#include "status.h"

/* An authenticated client session. */
typedef struct {
    int          fd;
    proto_keys_t keys;
    char         identity_hex[AUTH_PK_LEN * 2 + 1];  /* hex of auth pubkey */
} proto_conn_t;

/*
 * Client: resolve host, TCP-connect to the first of its addresses that
 * accepts (IPv6 or IPv4, in the resolver's order), run the handshake, and
 * on first connection register this identity's encryption public key.
 * conn->keys must be populated (e.g. via proto_load_keys) before calling.
 * Returns PROTO_OK, or the code for the stage that failed: PROTO_E_RESOLVE,
 * PROTO_E_SOCKET (no offered address family exists on this host),
 * PROTO_E_CONNECT (every address refused), PROTO_E_REJECTED,
 * PROTO_E_REGISTER_REJECTED, or whatever the handshake returned.
 */
int proto_connect(proto_conn_t *conn, const char *host, int port);

/* Send QUIT and close the connection. */
void proto_close(proto_conn_t *conn);

/*
 * Client primitive: run HELLO/CHALLENGE/AUTH on an already-connected fd.
 * Returns PROTO_OK if authenticated (server replied OK),
 * PROTO_REGISTER_REQUESTED if the server wants our encryption public key,
 * or a negative code on failure.
 */
int proto_auth_client(int fd, const proto_keys_t *keys);

/*
 * Server primitive: verify the handshake against allowed_hex (the single
 * authorized auth pubkey, hex). Returns the authenticated identity hex
 * (malloc, caller frees), or NULL on failure (a FAIL line has been sent).
 */
char *proto_auth_server(int fd, const char *allowed_hex);

#endif /* PROTO_AUTH_H */
