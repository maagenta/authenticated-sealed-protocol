#ifndef PROTO_SERVE_H
#define PROTO_SERVE_H

#include "error.h"

/*
 * Server-side connection handler. Called in a forked child once per
 * successfully authenticated client.
 *   fd            connected socket
 *   identity_hex  the client's auth pubkey (hex)
 *   ctx           opaque user data passed through from proto_serve
 */
typedef void (*proto_handler_fn)(int fd, const char *identity_hex, void *ctx);

/*
 * Turnkey server harness: init libsodium, ignore SIGPIPE, reap children,
 * bind/listen on port, then accept + fork per connection. Each connection is
 * authenticated against allowed_hex; handler is invoked only for authorized
 * clients. Blocks forever on success; on a fatal setup error returns
 * PROTO_E_NO_ALLOWLIST, PROTO_E_BAD_ALLOWLIST, PROTO_E_NO_HANDLER,
 * PROTO_E_SODIUM, PROTO_E_SOCKET, PROTO_E_PORT_IN_USE, PROTO_E_PERM_DENIED,
 * PROTO_E_BIND or PROTO_E_LISTEN.
 */
int proto_serve(int port, const char *allowed_hex,
                proto_handler_fn handler, void *ctx);

#endif /* PROTO_SERVE_H */
