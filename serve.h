#ifndef PROTO_SERVE_H
#define PROTO_SERVE_H

#include "status.h"

/*
 * Server-side connection handler. Called in a forked child once per
 * successfully authenticated client.
 *   fd            connected socket
 *   identity_hex  the client's auth pubkey (hex)
 *   ctx           opaque user data passed through from proto_serve
 */
typedef void (*proto_handler_fn)(int fd, const char *identity_hex, void *ctx);

/*
 * Server options. Zero every field you do not set — the idiom is a
 * designated initializer, which zeroes the rest for you:
 *
 *     proto_serve_opts_t opts = { .bind_addr = "127.0.0.1" };
 *
 * A zero field means the default; passing NULL instead of a struct means
 * every default. Fields are appended, never reordered, so a struct written
 * against this version keeps compiling and meaning the same thing.
 */
typedef struct {
    /* IPv4 address to listen on, as a dotted literal ("127.0.0.1"). NULL
     * listens on every interface. No name resolution: a bind address is a
     * deployment fact, and what a name resolves to at startup is not one. */
    const char *bind_addr;
} proto_serve_opts_t;

/*
 * Turnkey server harness: init libsodium, ignore SIGPIPE, reap children,
 * bind/listen on port, then accept + fork per connection. Each connection is
 * authenticated against allowed_hex; handler is invoked only for authorized
 * clients. opts may be NULL for the defaults. Blocks forever on success; on
 * a fatal setup error returns PROTO_E_NO_ALLOWLIST, PROTO_E_BAD_ALLOWLIST,
 * PROTO_E_NO_HANDLER, PROTO_E_BAD_PORT, PROTO_E_BAD_ADDRESS, PROTO_E_SODIUM,
 * PROTO_E_SOCKET, PROTO_E_PORT_IN_USE, PROTO_E_PERM_DENIED, PROTO_E_BIND or
 * PROTO_E_LISTEN.
 */
int proto_serve(int port, const char *allowed_hex,
                proto_handler_fn handler, void *ctx,
                const proto_serve_opts_t *opts);

#endif /* PROTO_SERVE_H */
