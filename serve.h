#ifndef PROTO_SERVE_H
#define PROTO_SERVE_H

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
 * clients. Blocks forever; returns -1 only on fatal setup error.
 */
int proto_serve(int port, const char *allowed_hex,
                proto_handler_fn handler, void *ctx);

#endif /* PROTO_SERVE_H */
