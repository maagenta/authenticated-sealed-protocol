# API Reference

Complete reference for the `proto` library. For the design rationale see
[architecture.md](architecture.md); for a two-minute intro see
[README.md](README.md).

## Table of contents

- [Conventions](#conventions)
- [Key files & formats](#key-files--formats)
- [Constants (`protocol.h`)](#constants-protocolh)
- [Types](#types)
  - [`proto_keys_t`](#proto_keys_t)
  - [`proto_conn_t`](#proto_conn_t)
  - [`proto_handler_fn`](#proto_handler_fn)
- [Module `wire` — framing](#module-wire--framing)
  - [`proto_send_line`](#proto_send_line)
  - [`proto_recv_line`](#proto_recv_line)
  - [`proto_recv_line_dyn`](#proto_recv_line_dyn)
  - [`proto_send_prefixed`](#proto_send_prefixed)
- [Module `crypto` — keys and encryption](#module-crypto--keys-and-encryption)
  - [`proto_init`](#proto_init)
  - [`proto_load_keys`](#proto_load_keys)
  - [`proto_load_pubkey_hex`](#proto_load_pubkey_hex)
  - [`proto_seal`](#proto_seal)
  - [`proto_seal_new`](#proto_seal_new)
  - [`proto_unseal_new`](#proto_unseal_new)
  - [`proto_sign_challenge`](#proto_sign_challenge)
  - [`proto_verify_challenge`](#proto_verify_challenge)
- [Module `auth` — sessions and handshake](#module-auth--sessions-and-handshake)
  - [`proto_connect`](#proto_connect)
  - [`proto_close`](#proto_close)
  - [`proto_auth_client`](#proto_auth_client)
  - [`proto_auth_server`](#proto_auth_server)
- [Module `serve` — server harness](#module-serve--server-harness)
  - [`proto_serve`](#proto_serve)
- [Wire protocol appendix](#wire-protocol-appendix)
- [Recipes](#recipes)
- [Worked example: complete client](#worked-example-complete-client)
- [Worked example: complete server](#worked-example-complete-server)
- [Building a consuming project](#building-a-consuming-project)
- [Troubleshooting / FAQ](#troubleshooting--faq)

---

## Conventions

**Return values.**
- Functions returning `int`: `0` = success, `-1` = failure, unless documented
  otherwise (`proto_recv_line` returns a length; `proto_auth_client` has a
  three-way result).
- Functions returning a pointer: non-`NULL` = success, `NULL` = failure.
- Failures are indicated by return value only; `errno` is not reliably set.

**Memory ownership.**
- Any function whose name ends in `_new`, plus `proto_recv_line_dyn` and
  `proto_auth_server`, returns heap memory **the caller must `free()`**.
- Everything else writes into caller-provided buffers.

**Process model.**
- The library is synchronous and blocking. One `proto_conn_t` / one fd per
  connection; do not share a connection between threads.
- `proto_serve` forks one child per connection; your handler runs in the
  child. In-memory state is per-connection, not shared (see
  [architecture.md](architecture.md)).

**Error lines on the wire.**
- `proto_auth_server` sends a `FAIL <reason>` line to the peer *before*
  returning `NULL`, so the server application never needs to reply to a
  failed handshake.
- Application code is expected to follow the same convention for its own
  verbs: `OK[ data]` on success, `FAIL <reason>` on error.

**Encodings.**
- All base64 on the wire and in key files uses
  `sodium_base64_VARIANT_ORIGINAL` (standard alphabet, `+/`, with padding).
- Identity strings are lowercase hex of the 32-byte Ed25519 public key
  (64 chars + NUL).

**Initialization.**
- Call [`proto_init`](#proto_init) once before other calls. `proto_connect`
  and `proto_serve` call it internally, so turnkey users get it for free;
  call it yourself if you start with the low-level primitives.

---

## Key files & formats

All three key files have the same format: **a single line of base64**
(standard variant), optionally newline-terminated. Only the first line is
read.

| File | Contains | Decoded size | Kept by |
|---|---|---|---|
| `auth.key` | Ed25519 secret key (libsodium format: 32-byte seed ‖ 32-byte public key) | 64 bytes | client (secret!) |
| `auth.pub` | Ed25519 public key | 32 bytes | server (allowlist) |
| `enc.key` | X25519 secret key | 32 bytes | client (secret!) |

Notes:

- The Ed25519 **public** key is embedded in the last 32 bytes of `auth.key`,
  so the client only ever loads secret-key files; publics are derived
  (`proto_load_keys` does this).
- The X25519 public key is derived from `enc.key` via `crypto_scalarmult_base`
  — there is no `enc.pub` file. The server learns it through the `REGISTER`
  step instead.
- The **identity** of a client is `hex(auth_pk)`: 64 lowercase hex chars.
  This is what `proto_auth_server` returns, what `proto_conn_t.identity_hex`
  holds, and what servers should use as the user key in storage.
- Generate keys with any tool that emits raw libsodium keys base64-encoded on
  one line (the diary project ships a `keygen` utility that does exactly
  this: `crypto_sign_keypair` + `crypto_box_keypair`, base64 each secret).

---

## Constants (`protocol.h`)

| Constant | Value | Meaning / where it matters |
|---|---|---|
| `CHALLENGE_LEN` | 32 | Bytes of random challenge in the handshake. |
| `MAX_LINE` | 16384 | Suggested buffer size for **control** lines (handshake, `OK`/`FAIL`, headers). Not a payload limit — payload lines should be read with `proto_recv_line_dyn`. |
| `AUTH_PK_LEN` | `crypto_sign_PUBLICKEYBYTES` (32) | Ed25519 public key size. Identity hex buffers need `AUTH_PK_LEN * 2 + 1`. |
| `AUTH_SK_LEN` | `crypto_sign_SECRETKEYBYTES` (64) | Ed25519 secret key size. |
| `AUTH_SIG_LEN` | `crypto_sign_BYTES` (64) | Detached signature size. |
| `ENC_PK_LEN` | `crypto_box_PUBLICKEYBYTES` (32) | X25519 public key size. |
| `ENC_SK_LEN` | `crypto_box_SECRETKEYBYTES` (32) | X25519 secret key size. |

`protocol.h` also documents the shared handshake wire format (see
[appendix](#wire-protocol-appendix)).

Sealed-box overhead (from libsodium, used in buffer math):
`crypto_box_SEALBYTES` = 48 bytes added to every plaintext.

---

## Types

### `proto_keys_t`

```c
typedef struct {
    unsigned char auth_pk[AUTH_PK_LEN];  /* Ed25519 public  (32 B) */
    unsigned char auth_sk[AUTH_SK_LEN];  /* Ed25519 secret  (64 B) */
    unsigned char enc_pk[ENC_PK_LEN];    /* X25519 public   (32 B) */
    unsigned char enc_sk[ENC_SK_LEN];    /* X25519 secret   (32 B) */
} proto_keys_t;
```

Both keypairs of one identity. Filled by [`proto_load_keys`](#proto_load_keys)
(publics are derived from the secrets — you never load them separately).
Treat the whole struct as sensitive; it lives wherever you put it (typically
inside a `proto_conn_t` on the stack).

### `proto_conn_t`

```c
typedef struct {
    int          fd;                                 /* socket, -1 when closed */
    proto_keys_t keys;                               /* this identity's keys   */
    char         identity_hex[AUTH_PK_LEN * 2 + 1];  /* hex(auth_pk) + NUL     */
} proto_conn_t;
```

An authenticated client session. Lifecycle:

1. Zero it, set `fd = -1`.
2. Fill `keys` with [`proto_load_keys`](#proto_load_keys).
3. [`proto_connect`](#proto_connect) — on success `fd` is a connected,
   authenticated socket and `identity_hex` is set.
4. Talk using the `wire` functions on `conn.fd`.
5. [`proto_close`](#proto_close) — sends `QUIT`, closes, sets `fd = -1`.

`proto_connect` leaves `fd == -1` on failure, so `fd >= 0` doubles as an
"is connected" check.

### `proto_handler_fn`

```c
typedef void (*proto_handler_fn)(int fd, const char *identity_hex, void *ctx);
```

Your server's per-connection entry point, called by
[`proto_serve`](#proto_serve) **in a forked child**, **only after the client
authenticated successfully**.

- `fd` — the connected socket. Read commands with `proto_recv_line_dyn`,
  reply with `proto_send_line`. Do not close it; the harness does.
- `identity_hex` — the authenticated client's identity (64 hex chars). Use it
  as the user key in storage. Owned by the harness; copy if you keep it.
- `ctx` — the opaque pointer you passed to `proto_serve` (e.g. a DB path or
  config struct).

When the handler returns, the child closes the socket and exits. Anything the
handler changes in memory is lost — persist through your storage.

---

## Module `wire` — framing

`#include "wire.h"` — no dependencies besides libc. One message = one
`\n`-terminated line; `\r` is stripped on read.

### `proto_send_line`

```c
int proto_send_line(int fd, const char *line);
```

Write `line` followed by `\n`.

| Param | Description |
|---|---|
| `fd` | connected socket |
| `line` | NUL-terminated string, **must not contain `\n`** |

**Returns** `0` on success, `-1` on short write / error.

```c
proto_send_line(fd, "OK");
proto_send_line(fd, "FAIL entry not found");
```

### `proto_recv_line`

```c
int proto_recv_line(int fd, char *buf, size_t bufsz);
```

Read one line into a fixed buffer. The newline is not stored; `buf` is always
NUL-terminated.

| Param | Description |
|---|---|
| `fd` | connected socket |
| `buf` | caller buffer |
| `bufsz` | its size (must be ≥ 1) |

**Returns** the line length (≥ 0), or `-1` on error/EOF.

**Pitfall:** if the incoming line is longer than `bufsz - 1`, the read stops
early and **the rest of the line stays in the socket**, corrupting the next
read. Use it only for lines with a known small bound (handshake replies,
`OK`/`FAIL`, list headers). For payload rows use
[`proto_recv_line_dyn`](#proto_recv_line_dyn).

```c
char reply[MAX_LINE];
if (proto_recv_line(fd, reply, sizeof reply) < 0) goto disconnected;
if (strncmp(reply, "OK", 2) != 0) goto server_said_no;
```

### `proto_recv_line_dyn`

```c
char *proto_recv_line_dyn(int fd);
```

Read one line of **arbitrary length** into a heap buffer (grows by doubling,
starts at 4 KB). NUL-terminated, newline stripped.

**Returns** the line (caller **must `free()`**), or `NULL` on error/EOF.
`NULL` is the normal way to detect a disconnected peer in a server command
loop.

```c
char *line;
while ((line = proto_recv_line_dyn(fd)) != NULL) {
    dispatch(line);
    free(line);
}
/* NULL: client went away */
```

### `proto_send_prefixed`

```c
int proto_send_prefixed(int fd, const char *prefix,
                        const char *body, size_t body_len);
```

Write `<prefix><body>\n` in three writes, without assembling an intermediate
buffer — the standard way to send `VERB <big_base64_payload>`.

| Param | Description |
|---|---|
| `prefix` | e.g. `"PUT "` — NUL-terminated, include the trailing space yourself |
| `body` | payload bytes (typically base64 from `proto_seal_new`) |
| `body_len` | length of `body` (for base64, `strlen(body)` is safe) |

**Returns** `0` / `-1`.

```c
char *sealed = proto_seal_new(data, data_len, conn.keys.enc_pk);
proto_send_prefixed(conn.fd, "PUT ", sealed, strlen(sealed));
free(sealed);
```

---

## Module `crypto` — keys and encryption

`#include "crypto.h"` — wraps libsodium. Everything here is pure computation
plus key-file reading; no sockets.

### `proto_init`

```c
int proto_init(void);
```

Initialize libsodium. Call once at startup. Idempotent — safe to call again.
Called internally by `proto_connect` and `proto_serve`.

**Returns** `0` / `-1` (failure means libsodium could not initialize; abort).

### `proto_load_keys`

```c
int proto_load_keys(const char *auth_sk_path,
                    const char *enc_sk_path,
                    proto_keys_t *out);
```

Load both secret keys from files (see [Key files](#key-files--formats)) and
derive both public keys into `out`.

| Param | Description |
|---|---|
| `auth_sk_path` | path to `auth.key` (base64 Ed25519 secret, 64 B decoded) |
| `enc_sk_path` | path to `enc.key` (base64 X25519 secret, 32 B decoded) |
| `out` | filled on success |

**Returns** `0` / `-1`. On failure an explanatory message is printed to
`stderr` (missing file, empty file, bad base64/size).

```c
proto_conn_t c = { .fd = -1 };
if (proto_load_keys("auth.key", "enc.key", &c.keys) != 0) return 1;
```

### `proto_load_pubkey_hex`

```c
int proto_load_pubkey_hex(const char *path, char *hex_out, size_t hex_sz);
```

Read an Ed25519 **public** key file (`auth.pub`) and write its lowercase hex
into `hex_out`. This is how a server builds its allowlist string.

| Param | Description |
|---|---|
| `path` | path to `auth.pub` |
| `hex_out` | buffer of at least `AUTH_PK_LEN * 2 + 1` bytes |
| `hex_sz` | its size |

**Returns** `0` / `-1` (prints the reason to `stderr`).

```c
char allowed[AUTH_PK_LEN * 2 + 1];
if (proto_load_pubkey_hex("auth.pub", allowed, sizeof allowed) != 0) return 1;
```

### `proto_seal`

```c
int proto_seal(const unsigned char *msg, size_t msg_len,
               const unsigned char *enc_pk,
               char *out_b64, size_t out_b64_sz);
```

Encrypt `msg` into an anonymous sealed box addressed to `enc_pk`, then base64
it into a **caller-provided** buffer. Only needed when you want to control
allocation yourself; otherwise use [`proto_seal_new`](#proto_seal_new).

Required buffer size:
`sodium_base64_ENCODED_LEN(msg_len + crypto_box_SEALBYTES, sodium_base64_VARIANT_ORIGINAL) + 1`.

**Returns** `0` / `-1`. Binary-safe: `msg` may contain NUL bytes.

Note: sealing needs only the **public** key — any holder of `enc_pk` can
write blobs that only the `enc_sk` holder can read.

### `proto_seal_new`

```c
char *proto_seal_new(const unsigned char *msg, size_t msg_len,
                     const unsigned char *enc_pk);
```

Like `proto_seal`, but allocates the right-sized buffer for you.

| Param | Description |
|---|---|
| `msg`, `msg_len` | plaintext bytes — **any** bytes, any length (length-based, not `strlen`) |
| `enc_pk` | recipient's X25519 public key (usually your own: `keys.enc_pk`) |

**Returns** a NUL-terminated base64 string (caller **frees**), or `NULL`.

```c
/* text */
char *s1 = proto_seal_new((const unsigned char *)text, strlen(text), k.enc_pk);
/* binary (image bytes in buf/len — NULs are fine) */
char *s2 = proto_seal_new(buf, len, k.enc_pk);
```

### `proto_unseal_new`

```c
unsigned char *proto_unseal_new(const char *data_b64,
                                const unsigned char *enc_pk,
                                const unsigned char *enc_sk,
                                size_t *out_len);
```

Decode base64, open the sealed box, return the plaintext in a heap buffer.
A NUL is appended **after** the plaintext so text payloads can be used as C
strings directly; binary payloads should use `*out_len` and ignore the NUL.

| Param | Description |
|---|---|
| `data_b64` | the base64 ciphertext line/field |
| `enc_pk`, `enc_sk` | **both** halves of the recipient keypair (libsodium needs both to open a sealed box) |
| `out_len` | optional (may be `NULL`); receives the true plaintext length |

**Returns** plaintext (caller **frees**), or `NULL` on bad base64, truncated
ciphertext, or failed decryption (wrong key / corrupted data).

```c
size_t n;
unsigned char *plain = proto_unseal_new(b64, k.enc_pk, k.enc_sk, &n);
if (!plain) { /* wrong key or corrupt data */ }
fwrite(plain, 1, n, out);   /* binary-safe */
free(plain);
```

### `proto_sign_challenge`

```c
int proto_sign_challenge(const unsigned char *challenge, size_t clen,
                         const unsigned char *auth_sk,
                         unsigned char *sig);
```

Detached-sign `challenge` with the Ed25519 secret key. `sig` must be at least
`AUTH_SIG_LEN` (64) bytes. Used internally by the client handshake; public in
case you build a custom transport. **Returns** `0` / `-1`.

### `proto_verify_challenge`

```c
int proto_verify_challenge(const unsigned char *challenge, size_t clen,
                           const unsigned char *sig,
                           const unsigned char *auth_pk);
```

Verify a detached signature against a public key. The server-side twin of
`proto_sign_challenge`; used internally by `proto_auth_server`. **Returns**
`0` if the signature is valid, `-1` otherwise.

---

## Module `auth` — sessions and handshake

`#include "auth.h"` — pulls in `crypto.h` (for `proto_keys_t`). Both sides of
the handshake live here; clients use the first three functions, servers the
last (usually indirectly, via `proto_serve`).

### `proto_connect`

```c
int proto_connect(proto_conn_t *conn, const char *host, int port);
```

The turnkey client session opener. In one call:

1. initializes libsodium (`proto_init`),
2. resolves `host` (IPv4/IPv6) and TCP-connects,
3. runs the handshake (`HELLO` → `CHALLENGE` → `AUTH`),
4. if the server answers `REGISTER` (first connection), sends
   `REGISTER <enc_pk b64>` and expects `OK`,
5. fills `conn->identity_hex`.

**Precondition:** `conn->keys` must already be filled
([`proto_load_keys`](#proto_load_keys)).

| Param | Description |
|---|---|
| `conn` | session struct; on success `conn->fd` is ready for app commands |
| `host` | hostname or address |
| `port` | server port (application policy — the library has no default) |

**Returns** `0` on success; `-1` on any failure (DNS, connect, handshake
rejected, registration rejected), with `conn->fd` left at `-1` and the socket
closed.

**Pitfall:** the call is all-or-nothing; there is no way to distinguish
"network down" from "access denied" from the return code. For diagnostics,
drop to `proto_auth_client` (which separates transport from protocol errors).

### `proto_close`

```c
void proto_close(proto_conn_t *conn);
```

Graceful shutdown: sends `QUIT`, waits for the `BYE`, closes the socket, sets
`conn->fd = -1`. Safe to call on an already-closed conn (no-op when
`fd < 0`).

### `proto_auth_client`

```c
int proto_auth_client(int fd, const proto_keys_t *keys);
```

Client handshake **primitive**: runs `HELLO` → `CHALLENGE` → `AUTH` on an
already-connected fd, and stops at the server's verdict.

**Returns**
- `0` — authenticated; server replied `OK` (known user)
- `1` — authenticated; server replied `REGISTER` (it wants your enc pubkey
  next — send `REGISTER <b64(enc_pk)>` and expect `OK`)
- `-1` — failure (I/O error, malformed reply, or `FAIL …`)

Use when you manage the socket yourself (custom transport, proxy, test
harness). `proto_connect` is this plus socket setup plus the REGISTER step.

### `proto_auth_server`

```c
char *proto_auth_server(int fd, const char *allowed_hex);
```

Server handshake primitive: generates the 32-byte challenge, verifies the
client's signature, and compares the client's identity against
`allowed_hex`.

| Param | Description |
|---|---|
| `fd` | freshly accepted socket |
| `allowed_hex` | the one authorized identity — 64 hex chars, from [`proto_load_pubkey_hex`](#proto_load_pubkey_hex) |

**Returns** the authenticated identity hex (heap; caller **frees**), or
`NULL` on failure. On every failure path a descriptive `FAIL <reason>` line
has already been sent to the peer (`expected HELLO`, `invalid public key`,
`signature verification failed`, `access denied`, …), so the caller just
closes the socket.

Note the returned identity always equals `allowed_hex` in the current
single-user model; it is returned (rather than a bool) so multi-user
variants and storage code can key on it.

---

## Module `serve` — server harness

`#include "serve.h"` — the only server-only file.

### `proto_serve`

```c
int proto_serve(int port, const char *allowed_hex,
                proto_handler_fn handler, void *ctx);
```

The turnkey server. In one call:

1. initializes libsodium,
2. ignores `SIGPIPE`, installs a `SIGCHLD` reaper (no zombies),
3. creates the listening socket (`SO_REUSEADDR`, backlog 16, all interfaces),
4. loops forever: `accept` → `fork` → in the child, authenticate with
   [`proto_auth_server`](#proto_auth_server) → on success call
   `handler(fd, identity_hex, ctx)` → close and `_exit`.

| Param | Description |
|---|---|
| `port` | TCP port to listen on |
| `allowed_hex` | authorized identity (see `proto_load_pubkey_hex`) |
| `handler` | your per-connection function ([contract](#proto_handler_fn)) |
| `ctx` | passed through to the handler untouched (DB path, config, …) |

**Returns** never on success (blocks forever); `-1` on fatal setup errors
(libsodium, socket, bind, listen — e.g. port already in use).

**When not to use it:** threads instead of forks, event loops, several
authorized keys, pre-auth connection logging, or non-TCP transports — write
your own accept loop around `proto_auth_server` instead (recipe below).

```c
int main(void) {
    if (proto_init() != 0) return 1;
    char allowed[AUTH_PK_LEN * 2 + 1];
    if (proto_load_pubkey_hex("auth.pub", allowed, sizeof allowed) != 0) return 1;
    return proto_serve(5000, allowed, on_client, "/var/lib/app/data.db");
}
```

---

## Wire protocol appendix

Every message is one line: UTF-8 text, fields separated by single spaces,
terminated by `\n` (a lone `\r` before it is tolerated). Binary values are
base64 (standard alphabet, padded). Realistic sizes below.

### Handshake (owned by the library)

```
C→S   HELLO
S→C   CHALLENGE dGhpcyBpcyAzMiByYW5kb20gYnl0ZXMhISEhISEhISE=      (44 b64 chars = 32 B)
C→S   AUTH <auth_pk 44 chars> <signature 88 chars>
S→C   OK                                   (known identity)
      REGISTER                             (unknown identity: register now)
      FAIL <reason>                        (rejected; connection is dead)

-- only after REGISTER --
C→S   REGISTER <enc_pk 44 chars>
S→C   OK  |  FAIL <reason>

-- session end --
C→S   QUIT
S→C   BYE
```

`FAIL` reasons emitted by the library: `expected HELLO`, `expected AUTH`,
`invalid AUTH format`, `invalid public key`, `invalid signature`,
`signature verification failed`, `access denied`, `internal error`.

### Application verbs (owned by you)

The library imposes nothing beyond the handshake, but the conventions used by
existing consumers (and recommended) are:

- Request: `VERB [args...] [payload_b64]` — verb in caps, args
  space-separated, at most one payload and it goes last (base64 contains no
  spaces in this variant's output, but keeping it last means you can
  `strchr` for the args safely).
- Reply: `OK` or `OK <data>` on success; `FAIL <reason>` on error.
- Lists: a header `SOMETHING <count>`, then exactly `<count>` lines of
  `<fields...> <payload_b64>`.

Example — the diary application's verb set:

```
C→S   POST <sealed_b64>              S→C  OK <id> | FAIL <reason>
C→S   GET                            S→C  ENTRIES <n>  then n × "<id> <unix_ts> <sealed_b64>"
C→S   UPDATE <id> <sealed_b64>       S→C  OK | FAIL <reason>
C→S   DELETE <id>                    S→C  OK | FAIL <reason>
```

A sealed payload of `L` plaintext bytes becomes `ceil((L+48)/3)*4` base64
chars — ~1.37× the plaintext, e.g. a 100 KB image ≈ 137 KB line.

---

## Recipes

### Send a text payload

```c
char *b64 = proto_seal_new((const unsigned char *)text, strlen(text),
                           conn.keys.enc_pk);
if (!b64) return -1;
int rc = proto_send_prefixed(conn.fd, "POST ", b64, strlen(b64));
free(b64);

char reply[MAX_LINE];
if (rc != 0 || proto_recv_line(conn.fd, reply, sizeof reply) < 0) return -1;
/* reply is "OK <id>" or "FAIL <reason>" */
```

### Send a binary payload (image, audio, anything)

Identical — the API is length-based, so NUL bytes are fine. Just don't use
`strlen` on the *plaintext*:

```c
unsigned char *buf; size_t len;               /* e.g. read from a file */
char *b64 = proto_seal_new(buf, len, conn.keys.enc_pk);
proto_send_prefixed(conn.fd, "PUT ", b64, strlen(b64));   /* strlen OK on b64 */
free(b64);
```

And on the way back, take the length instead of treating it as a string:

```c
size_t plen;
unsigned char *plain = proto_unseal_new(b64_field, conn.keys.enc_pk,
                                        conn.keys.enc_sk, &plen);
fwrite(plain, 1, plen, f);
free(plain);
```

### Read a list response

Header with a fixed buffer, rows with dynamic lines (rows carry payloads and
can be arbitrarily large):

```c
proto_send_line(conn.fd, "GET");

char hdr[64];
if (proto_recv_line(conn.fd, hdr, sizeof hdr) < 0) return -1;
if (strncmp(hdr, "ENTRIES ", 8) != 0) return -1;
int n = atoi(hdr + 8);

for (int i = 0; i < n; i++) {
    char *row = proto_recv_line_dyn(conn.fd);          /* "<id> <ts> <b64>" */
    if (!row) return -1;
    char *sv = NULL;
    char *id  = strtok_r(row,  " ", &sv);
    char *ts  = strtok_r(NULL, " ", &sv);
    char *b64 = strtok_r(NULL, " ", &sv);
    if (id && ts && b64) {
        unsigned char *plain = proto_unseal_new(b64, conn.keys.enc_pk,
                                                conn.keys.enc_sk, NULL);
        /* use it ... */
        free(plain);
    }
    free(row);
}
```

### Handle first-connect registration (server side)

`proto_serve`/`proto_auth_server` authenticate; *whether this identity is
registered* is your storage's business. Standard pattern, first thing in the
handler:

```c
static void on_client(int fd, const char *user, void *ctx) {
    storage_open((const char *)ctx);

    if (!storage_user_exists(user)) {
        proto_send_line(fd, "REGISTER");
        char line[MAX_LINE];                       /* enc_pk line is small */
        if (proto_recv_line(fd, line, sizeof line) < 0) goto out;
        if (strncmp(line, "REGISTER ", 9) != 0) {
            proto_send_line(fd, "FAIL expected REGISTER <enc_pubkey_b64>");
            goto out;
        }
        /* optionally: base64-decode line+9 and check it's ENC_PK_LEN bytes */
        if (storage_register_user(user, line + 9) != 0) {
            proto_send_line(fd, "FAIL could not register user");
            goto out;
        }
        proto_send_line(fd, "OK");
    } else {
        proto_send_line(fd, "OK");
    }

    /* ... command loop ... */
out:
    storage_close();
}
```

(The client needs no code for this: `proto_connect` answers the `REGISTER`
request automatically.)

### Custom accept loop (bypassing `proto_serve`)

```c
int srv = socket(AF_INET, SOCK_STREAM, 0);
/* ... setsockopt, bind, listen as usual ... */
for (;;) {
    int cli = accept(srv, NULL, NULL);
    if (cli < 0) continue;
    /* your model here: thread, event loop, fork ... */
    char *user = proto_auth_server(cli, allowed_hex);
    if (user) {
        handle(cli, user);          /* your handler */
        free(user);
    }
    close(cli);                     /* FAIL already sent if auth failed */
}
```

---

## Worked example: complete client

A minimal but complete "vault" client: `./vault-client "text"` stores a note,
`./vault-client` lists all notes. Compiles as-is against the library.

```c
/* vault-client.c */
#include "protocol/auth.h"
#include "protocol/crypto.h"
#include "protocol/wire.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define VAULT_PORT 5000

int main(int argc, char *argv[]) {
    const char *note = (argc > 1) ? argv[1] : NULL;

    proto_conn_t c;
    memset(&c, 0, sizeof c);
    c.fd = -1;

    if (proto_load_keys("auth.key", "enc.key", &c.keys) != 0)
        return 1;
    if (proto_connect(&c, "127.0.0.1", VAULT_PORT) != 0) {
        fprintf(stderr, "could not connect or authenticate\n");
        return 1;
    }

    char reply[MAX_LINE];

    if (note) {                                    /* PUT one note */
        char *b64 = proto_seal_new((const unsigned char *)note,
                                   strlen(note), c.keys.enc_pk);
        if (!b64) { proto_close(&c); return 1; }
        proto_send_prefixed(c.fd, "PUT ", b64, strlen(b64));
        free(b64);

        if (proto_recv_line(c.fd, reply, sizeof reply) < 0) return 1;
        printf("%s\n", reply);                     /* OK <id> */
    } else {                                       /* GET all notes */
        proto_send_line(c.fd, "GET");
        if (proto_recv_line(c.fd, reply, sizeof reply) < 0) return 1;
        if (strncmp(reply, "ENTRIES ", 8) != 0) return 1;
        int n = atoi(reply + 8);

        for (int i = 0; i < n; i++) {
            char *row = proto_recv_line_dyn(c.fd);
            if (!row) return 1;
            char *sv = NULL;
            char *id  = strtok_r(row,  " ", &sv);
            char *b64 = strtok_r(NULL, " ", &sv);
            if (id && b64) {
                unsigned char *plain = proto_unseal_new(b64, c.keys.enc_pk,
                                                        c.keys.enc_sk, NULL);
                printf("[%s] %s\n", id, plain ? (char *)plain : "[locked]");
                free(plain);
            }
            free(row);
        }
    }

    proto_close(&c);
    return 0;
}
```

## Worked example: complete server

The matching server: append-only file storage, one authorized user, notes it
can never decrypt.

```c
/* vault-server.c */
#include "protocol/serve.h"
#include "protocol/crypto.h"
#include "protocol/wire.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define VAULT_PORT 5000

/* storage: "<id> <b64>\n" per line, ids ascending -------------------- */

static void handle_put(const char *path, int fd, const char *b64) {
    FILE *f = fopen(path, "a+");
    if (!f) { proto_send_line(fd, "FAIL storage"); return; }
    rewind(f);
    int id = 1; int ch;
    while ((ch = fgetc(f)) != EOF) if (ch == '\n') id++;
    fprintf(f, "%d %s\n", id, b64);
    fclose(f);
    char ok[32];
    snprintf(ok, sizeof ok, "OK %d", id);
    proto_send_line(fd, ok);
}

static void handle_get(const char *path, int fd) {
    FILE *f = fopen(path, "r");
    int n = 0;
    if (f) { int ch; while ((ch = fgetc(f)) != EOF) if (ch == '\n') n++; rewind(f); }

    char hdr[32];
    snprintf(hdr, sizeof hdr, "ENTRIES %d", n);
    proto_send_line(fd, hdr);

    if (f) {
        char *row = NULL; size_t cap = 0; ssize_t len;
        while ((len = getline(&row, &cap, f)) > 0) {
            if (row[len - 1] == '\n') row[len - 1] = '\0';
            proto_send_line(fd, row);
        }
        free(row);
        fclose(f);
    }
}

/* per-connection handler (runs in a forked child, post-auth) --------- */

static void on_client(int fd, const char *user, void *ctx) {
    (void)user;                          /* single-user: identity == allowlist */
    const char *path = (const char *)ctx;

    proto_send_line(fd, "OK");           /* no registration needed here */

    char *line;
    while ((line = proto_recv_line_dyn(fd)) != NULL) {
        if (strncmp(line, "PUT ", 4) == 0) {
            handle_put(path, fd, line + 4);
        } else if (strcmp(line, "GET") == 0) {
            handle_get(path, fd);
        } else if (strcmp(line, "QUIT") == 0) {
            proto_send_line(fd, "BYE");
            free(line);
            break;
        } else {
            proto_send_line(fd, "FAIL unknown command");
        }
        free(line);
    }
}

int main(void) {
    if (proto_init() != 0) return 1;

    char allowed[AUTH_PK_LEN * 2 + 1];
    if (proto_load_pubkey_hex("auth.pub", allowed, sizeof allowed) != 0)
        return 1;

    printf("vault-server listening on %d\n", VAULT_PORT);
    return proto_serve(VAULT_PORT, allowed, on_client, "vault.db");
}
```

*(For a registration-aware server — persisting the enc pubkey per identity —
see the [recipe above](#handle-first-connect-registration-server-side) and the
diary's `server/client_handler.c`, which is a full real-world consumer.)*

## Building a consuming project

With the library vendored (or as a git submodule) at `protocol/`:

```make
CC      = gcc
CFLAGS  = -Wall -Wextra -O2 -I.        # -I so "protocol/xxx.h" resolves
LDFLAGS = -lsodium

client: vault-client.c
	$(CC) $(CFLAGS) -o vault-client vault-client.c \
	      protocol/wire.c protocol/crypto.c protocol/auth.c $(LDFLAGS)

server: vault-server.c
	$(CC) $(CFLAGS) -o vault-server vault-server.c \
	      protocol/wire.c protocol/crypto.c protocol/auth.c protocol/serve.c $(LDFLAGS)
```

- The library is consumed **as source** — no `libproto.a`, no build ordering,
  no install step.
- Cross-compiling? It just works: point `CC` at your cross compiler and the
  library sources compile for the target along with your own (this is a key
  reason the source-inclusion model was chosen over a static archive).
- The include style in your code should match your `-I`: with `-I.` use
  `#include "protocol/auth.h"`; with `-I..` from a subdirectory use
  `#include "../protocol/auth.h"`.

## Troubleshooting / FAQ

**`proto_connect` returns -1 — which step failed?**
Could be DNS, TCP connect, handshake, or registration. For a quick
diagnosis run the server in the foreground and watch which `FAIL` it sends,
or replace `proto_connect` with your own socket + `proto_auth_client`, which
separates transport errors from protocol errors.

**Server replies `FAIL access denied`.**
The client authenticated with a key that isn't the one in the server's
`auth.pub`. Compare identities: hex of the last 32 bytes of the client's
decoded `auth.key` must equal hex of the decoded `auth.pub`.

**`FAIL signature verification failed`.**
The `auth.key` file is corrupt or not a libsodium Ed25519 secret key
(must decode to exactly 64 bytes: seed ‖ public).

**Entries come back as NULL / "could not decrypt".**
`proto_unseal_new` failed: you're decrypting with a different `enc.key` than
the one that sealed the data (new machine? regenerated keys?), or the stored
blob is truncated/corrupt. Sealed boxes cannot be recovered without the
original X25519 secret key — back it up.

**Large payloads arrive truncated / connection desyncs after one.**
Somewhere a payload line is being read with `proto_recv_line` into a fixed
buffer. Fixed-buffer reads stop at `bufsz-1` and leave the remainder in the
socket, desynchronizing everything after. Read any line that can carry a
payload with `proto_recv_line_dyn`.

**Error: could not open `auth.key`.**
Key paths are resolved relative to the process working directory. Pass
absolute paths or run from the directory containing the keys.

**Can two clients share one identity?**
Yes — copy both key files. They'll authenticate as the same user and decrypt
the same data. There is no session exclusivity.

**Is the connection encrypted?**
Payloads are; the command lines (verbs, ids, timestamps) are not, and the
server is not authenticated to the client. If metadata privacy or
server authentication matters, run the TCP connection through SSH/WireGuard.

**Why does `proto_unseal_new` need both `enc_pk` and `enc_sk`?**
libsodium's `crypto_box_seal_open` requires the recipient's public *and*
secret key (the public key is part of the sealed-box construction).
`proto_load_keys` always gives you both.
