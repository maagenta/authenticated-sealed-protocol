# proto — authenticated, server-blind line protocol library

A small C library for building client/server programs that speak a simple,
newline-delimited text protocol with two guarantees:

1. **Only you can connect.** Clients authenticate with an Ed25519 keypair
   (`auth.key` / `auth.pub`) via challenge–response — no passwords, nothing
   replayable on the wire.
2. **The server can never read your data.** Payloads are encrypted client-side
   into X25519 sealed boxes (libsodium `crypto_box_seal`) addressed to the
   client's own encryption key (`enc.key`). The server stores and returns
   opaque ciphertext.

The library owns the transport, the crypto, and the handshake. Each
application defines only its own command verbs (e.g. `POST`, `GET`) on top.

## Features

- Line framing with binary-safe base64 payloads (text, images, audio — any bytes)
- Ed25519 challenge–response authentication, single-authorized-key model
- X25519 sealed-box encryption: write with the public key, read only with the secret key
- Turnkey client session: `proto_connect()` = TCP connect + authenticate + first-run registration
- Turnkey server harness: `proto_serve()` = bind/listen + fork-per-connection + per-client auth
- Low-level primitives stay public, so custom accept loops / transports are possible
- No size ceiling: dynamic line reads and length-based payload APIs
- Bundled `keygen` tool to provision an identity's key files
- Zero dependencies beyond **libsodium** and libc; no TLS stack required

## Requirements

- [libsodium](https://libsodium.org) (`-lsodium`)
- POSIX sockets (Linux, macOS)

The library is consumed **as source** — no archive to build or install. In a
consuming project's Makefile:

```make
CFLAGS  = -Wall -Wextra -O2 -I..           # so "protocol/xxx.h" resolves
LDFLAGS = -lsodium
SRCS    = main.c \
          ../protocol/wire.c ../protocol/crypto.c ../protocol/auth.c ../protocol/serve.c
```

(Clients don't need `serve.c`; servers need all four.)

## Generating keys

The repo ships `keygen/`, a standalone CLI tool that creates the key files
every consumer needs. Build it once, run it in the directory where the keys
should live:

```sh
make -C keygen                # produces keygen/keygen
cd ~/my-keys
/path/to/protocol/keygen/keygen
```

It writes three files (single-line base64, mode 0600):

- `auth.key` — Ed25519 secret key. Stays on the client. **Keep secret.**
- `auth.pub` — Ed25519 public key. Give it to the server: it is the allowlist.
- `enc.key` — X25519 secret key. Stays on the client. **Keep secret** —
  sealed payloads are unrecoverable without it.

There is no `enc.pub` file: the encryption public key is derived from
`enc.key` on load and reaches the server through the `REGISTER` step.
See [docs.md](docs.md#tool-keygen--generating-key-files) for details.

## Quick start

### Client

```c
#include "../protocol/auth.h"
#include "../protocol/crypto.h"
#include "../protocol/wire.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    proto_conn_t c = { .fd = -1 };
    if (proto_load_keys("auth.key", "enc.key", &c.keys) != 0) return 1;
    if (proto_connect(&c, "127.0.0.1", 5000) != 0) return 1;   /* auth + register */

    const char *msg = "hello";
    char *sealed = proto_seal_new((const unsigned char *)msg, strlen(msg),
                                  c.keys.enc_pk);              /* encrypt locally */
    proto_send_prefixed(c.fd, "PUT ", sealed, strlen(sealed));
    free(sealed);

    char reply[128];
    proto_recv_line(c.fd, reply, sizeof reply);
    printf("server said: %s\n", reply);

    proto_close(&c);
    return 0;
}
```

### Server

```c
#include "../protocol/serve.h"
#include "../protocol/crypto.h"
#include "../protocol/wire.h"
#include <stdlib.h>
#include <string.h>

static void on_client(int fd, const char *user, void *ctx) {
    (void)user; (void)ctx;
    proto_send_line(fd, "OK");                 /* greet after successful auth */
    char *line;
    while ((line = proto_recv_line_dyn(fd)) != NULL) {
        if (strncmp(line, "PUT ", 4) == 0) {
            /* line + 4 is opaque ciphertext — store it, you can't read it */
            proto_send_line(fd, "OK");
        } else if (strcmp(line, "QUIT") == 0) {
            proto_send_line(fd, "BYE"); free(line); break;
        } else {
            proto_send_line(fd, "FAIL unknown command");
        }
        free(line);
    }
}

int main(void) {
    if (proto_init() != 0) return 1;
    char allowed[AUTH_PK_LEN * 2 + 1];
    if (proto_load_pubkey_hex("auth.pub", allowed, sizeof allowed) != 0) return 1;
    return proto_serve(5000, allowed, on_client, NULL);   /* blocks forever */
}
```

## File map

| File | Purpose |
|---|---|
| `protocol.h` | Shared constants (key sizes, `MAX_LINE`, `CHALLENGE_LEN`) and the wire-format spec |
| `wire.h` / `wire.c` | Line framing: send/receive `\n`-terminated lines, fixed or dynamic buffers |
| `crypto.h` / `crypto.c` | Keypairs (`proto_keys_t`), key loading, sealed-box encrypt/decrypt, challenge sign/verify |
| `auth.h` / `auth.c` | Client session (`proto_conn_t`, `proto_connect`, `proto_close`) and the handshake primitives for both sides |
| `serve.h` / `serve.c` | Server harness: `proto_serve()` accept/fork loop with built-in authentication |
| `keygen/` | Standalone CLI tool that generates the key files (`auth.key`, `auth.pub`, `enc.key`) — not part of the library sources |

## Documentation

- **[architecture.md](architecture.md)** — design: layers, keypairs, handshake, trust model, what the library owns vs what your app owns
- **[docs.md](docs.md)** — complete API reference with examples, recipes, wire-protocol appendix, and troubleshooting
