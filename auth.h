#ifndef PROTO_AUTH_H
#define PROTO_AUTH_H

#include "crypto.h"

/* An authenticated client session. */
typedef struct {
    int          fd;
    proto_keys_t keys;
    char         identity_hex[AUTH_PK_LEN * 2 + 1];  /* hex of auth pubkey */
} proto_conn_t;

/*
 * Client: TCP-connect to host:port, run the handshake, and on first
 * connection register this identity's encryption public key. conn->keys
 * must be populated (e.g. via proto_load_keys) before calling.
 * Returns 0 on success, -1 on any failure.
 */
int proto_connect(proto_conn_t *conn, const char *host, int port);

/* Send QUIT and close the connection. */
void proto_close(proto_conn_t *conn);

/*
 * Client primitive: run HELLO/CHALLENGE/AUTH on an already-connected fd.
 * Returns 0 if authenticated (server replied OK), 1 if the server requests
 * registration (replied REGISTER), or -1 on failure.
 */
int proto_auth_client(int fd, const proto_keys_t *keys);

/*
 * Server primitive: verify the handshake against allowed_hex (the single
 * authorized auth pubkey, hex). Returns the authenticated identity hex
 * (malloc, caller frees), or NULL on failure (a FAIL line has been sent).
 */
char *proto_auth_server(int fd, const char *allowed_hex);

#endif /* PROTO_AUTH_H */
