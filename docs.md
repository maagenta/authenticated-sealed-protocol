# API Reference

Complete reference for the `proto` library. For the design rationale see
[architecture.md](architecture.md); for a two-minute intro see
[README.md](README.md).

## Table of contents

- [Conventions](#conventions)
- [Key files & formats](#key-files--formats)
- [Constants (`protocol.h`, `wire.h`)](#constants-protocolh-wireh)
- [Status codes](#status-codes)
- [Error codes](#error-codes)
- [Types](#types)
  - [`proto_keys_t`](#proto_keys_t)
  - [`proto_conn_t`](#proto_conn_t)
  - [`proto_handler_fn`](#proto_handler_fn)
  - [`proto_serve_opts_t`](#proto_serve_opts_t)
- [Module `wire` — framing](#module-wire--framing)
  - [`proto_send_line`](#proto_send_line)
  - [`proto_recv_line`](#proto_recv_line)
  - [`proto_recv_line_timeout`](#proto_recv_line_timeout)
  - [`proto_recv_line_dyn`](#proto_recv_line_dyn)
  - [`proto_recv_line_dyn_status`](#proto_recv_line_dyn_status)
  - [`proto_send_prefixed`](#proto_send_prefixed)
  - [`proto_keepalive`](#proto_keepalive)
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
  - [`proto_serve_stop`](#proto_serve_stop)
- [Tool `keygen` — generating key files](#tool-keygen--generating-key-files)
- [Wire protocol appendix](#wire-protocol-appendix)
- [Recipes](#recipes)
- [Worked example: complete client](#worked-example-complete-client)
- [Worked example: complete server](#worked-example-complete-server)
- [Building a consuming project](#building-a-consuming-project)
- [Troubleshooting / FAQ](#troubleshooting--faq)

---

## Conventions

**Return values.**
- Functions returning `int` report a [status code](#status-codes): negative
  = failure, `PROTO_OK` (`0`) = success, positive = success with something
  to act on. Test with `rc < 0`, which always means failure; `rc != 0` is
  safe only on functions that never return a positive. The negative values
  are the [error codes](#error-codes).
- Functions returning a pointer: non-`NULL` = success, `NULL` = failure.
  These carry no code — `proto_auth_server` reports the reason to the peer as
  a `FAIL` line instead.
- Failures are indicated by return value only; `errno` is not reliably set.
  Where `errno` distinguishes causes worth knowing (`bind` failing because
  the port is taken, say), the library reads it and hands you a code.

**Memory ownership.**
- Any function whose name ends in `_new`, plus `proto_recv_line_dyn`,
  `proto_recv_line_dyn_status` and `proto_auth_server`, returns heap memory
  **the caller must `free()`**.
- Everything else writes into caller-provided buffers.

**Process model.**
- The library is synchronous and blocking. One `proto_conn_t` / one fd per
  connection; do not share a connection between threads. A non-blocking fd
  is outside the contract: the send path treats `EAGAIN` as a failure.
- Blocking calls retry when a signal interrupts them, so an incidental
  signal — `SIGCHLD` in a forking server, `SIGWINCH` in a terminal client —
  does not turn into a spurious failure. The consequence is that a signal
  handler alone cannot break a caller out of a blocked read; the FAQ entry
  "My program ignores Ctrl-C while waiting for a line" shows how to cancel
  one. `proto_serve`'s own wait is the exception:
  [`proto_serve_stop`](#proto_serve_stop), called from your handler, ends
  it.
- The library's own writes never raise `SIGPIPE`: they use `send()` with
  `MSG_NOSIGNAL`, so a vanished peer surfaces as `PROTO_E_WRITE` and the
  process keeps running. This covers the library's calls only — a `write()`
  of your own to a dead socket is still yours to protect. On a platform
  without `MSG_NOSIGNAL` (none of the supported ones) the writes go out
  unprotected and the application must ignore `SIGPIPE` itself.
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
read. Each must be a regular file: a directory, a FIFO or a device is
refused with `PROTO_E_KEY_NOT_FILE` before anything is read from it.

The format is strict: the line holds the key and nothing else. What is
wrong with a line that does not is reported, never repaired, so that a key
has one spelling — and because most of it cannot be seen in an editor,
each kind has a code of its own:

- a blank first line, or an empty file: `PROTO_E_KEY_EMPTY`;
- something around the key — a space or a tab, a byte order mark an editor
  added, a non-breaking space pasted from a web page, quotes:
  `PROTO_E_KEY_STRAY`;
- characters inside the line that are not standard base64, the URL-safe
  variant, or missing `=` padding: `PROTO_E_KEY_FORMAT`;
- valid base64 of the wrong size: `PROTO_E_KEY_SIZE`, usually the wrong
  file. `enc.key` and `auth.pub` are both 32 bytes, so the size cannot tell
  those two apart.

| File | Contains | Decoded size | Kept by |
|---|---|---|---|
| `auth.key` | Ed25519 secret key (libsodium format: 32-byte seed ‖ 32-byte public key) | 64 bytes | client (secret!) |
| `auth.pub` | Ed25519 public key | 32 bytes | server (allowlist) |
| `enc.key` | X25519 secret key | 32 bytes | client (secret!) |

Notes:

- The Ed25519 **public** key is embedded in the last 32 bytes of `auth.key`,
  so the client only ever loads secret-key files; publics are derived
  (`proto_load_keys` does this). The embedded copy is checked against the
  key derived from the seed, and a file whose two halves disagree — one
  character changed while copying it by hand is enough — is refused with
  `PROTO_E_KEY_MISMATCH` instead of loading and being refused by the server
  later, where it would look like an authorization problem.
- The X25519 public key is derived from `enc.key` via `crypto_scalarmult_base`
  — there is no `enc.pub` file. The server learns it through the `REGISTER`
  step instead.
- The **identity** of a client is `hex(auth_pk)`: 64 lowercase hex chars.
  This is what `proto_auth_server` returns, what `proto_conn_t.identity_hex`
  holds, and what servers should use as the user key in storage.
- Generate the files with the bundled tool — see
  [Tool `keygen`](#tool-keygen--generating-key-files). Any other tool works
  too, as long as it emits raw libsodium keys base64-encoded on one line
  (`crypto_sign_keypair` + `crypto_box_keypair`, base64 each key).

---

## Constants (`protocol.h`, `wire.h`)

| Constant | Value | Meaning / where it matters |
|---|---|---|
| `CHALLENGE_LEN` | 32 | Bytes of random challenge in the handshake. |
| `MAX_LINE` | 16384 | Suggested buffer size for **control** lines (handshake, `OK`/`FAIL`, headers). Not a payload limit — payload lines should be read with `proto_recv_line_dyn`. |
| `CONNECT_TIMEOUT_MS` | 10000 | Deadline for connecting to **one** address. A name usually has two, tried in turn, so a host that answers nothing costs this much per address instead of the kernel's own limit (measured: 75 s on macOS). Overridable — see below. |
| `HANDSHAKE_TIMEOUT_MS` | 10000 | Deadline for each line of the handshake, on both ends. A peer that connects and goes silent fails the handshake after this long instead of holding a client, or a forked server child, forever. Overridable — see below. |
| `QUIT_TIMEOUT_MS` | 2000 | How long `proto_close` waits for `BYE` after sending `QUIT`. The socket is closed either way; this only bounds the courtesy. Overridable — see below. |
| `READ_CHUNK` **(in `wire.h`)** | 65536 | Most bytes of a line taken from the socket per system call. A ceiling, not a quantity: a 3-byte line costs 3 bytes. Overridable at compile time, but worth keeping between 64 KB and 256 KB — see below. |
| `MAX_PAYLOAD` **(in `wire.h`)** | 16 MB | Longest line the allocating readers accept, in characters. Past it they stop with `PROTO_E_LINE_TOO_LONG` instead of allocating for a peer that may never send a newline. A limit on one *message*, not on what an application can transfer — see below. Overridable at compile time. |
| `AUTH_PK_LEN` | `crypto_sign_PUBLICKEYBYTES` (32) | Ed25519 public key size. Identity hex buffers need `AUTH_PK_LEN * 2 + 1`. |
| `AUTH_SK_LEN` | `crypto_sign_SECRETKEYBYTES` (64) | Ed25519 secret key size. |
| `AUTH_SIG_LEN` | `crypto_sign_BYTES` (64) | Detached signature size. |
| `ENC_PK_LEN` | `crypto_box_PUBLICKEYBYTES` (32) | X25519 public key size. |
| `ENC_SK_LEN` | `crypto_box_SECRETKEYBYTES` (32) | X25519 secret key size. |

**Compile-time options.** Five of the constants above are policy rather
than fact: the three timeouts, `READ_CHUNK` and `MAX_PAYLOAD`. The right
values depend on the deployment (LAN vs. mobile links, how patient a server
should be with strangers, how big the messages are), and that is a decision
of the project that links the library, not of the library. All five are
wrapped in `#ifndef`, so a consuming application sets its own from its
Makefile — or any `-D` on the compiler line — without editing the library's
headers:

```make
# in the consuming project's Makefile
CFLAGS += -DHANDSHAKE_TIMEOUT_MS=30000 -DQUIT_TIMEOUT_MS=500
```

The values in the headers are the defaults, used only when the build says
nothing. Every source file must see the same value: put the `-D` in the
`CFLAGS` used for the whole build, not on a single object.

They live in **two** headers: `CONNECT_TIMEOUT_MS`, `HANDSHAKE_TIMEOUT_MS`
and `QUIT_TIMEOUT_MS` in `protocol.h`, `READ_CHUNK` and `MAX_PAYLOAD` in
`wire.h`. The split is deliberate —
`protocol.h` includes libsodium for the key sizes, and `wire` is the one
module that compiles against libc alone, so a constant it needs cannot come
from there. Where you write the `-D` makes no difference either way.

**Calibrating `READ_CHUNK`.** `CFLAGS += -DREAD_CHUNK=262144` overrides it
like the timeouts, but stay between **64 KB and 256 KB** unless you have
measured a reason not to. A peek never returns more than the socket is
holding, so past the receive buffer the extra size is simply never filled,
and the gain from a bigger chunk flattens well before the top of that
range. Reading one 64 MB line over a local socket:

| `READ_CHUNK` | time |
|---|---|
| 1 KB | 0.253 s |
| 4 KB | 0.158 s |
| 16 KB | 0.140 s |
| 64 KB (default) | 0.138 s |
| 256 KB | 0.138 s |

- **Raising it** above the default bought nothing here. It can help where
  the receive buffer is genuinely larger (`SO_RCVBUF` tuned up, or a system
  that auto-tunes it) — measure, and if the time does not move, the buffer
  was the limit, not the chunk.
- **Lowering it** buys nothing and costs system calls on long lines, and
  only on long lines: a short line moves its own length whatever the
  setting, and the value allocates no memory of its own — the peek goes
  straight into the buffer the line is being read into. Below ~4 KB the
  extra calls start to show.

Correctness does not depend on the value: any size ≥ 1 reads the same
lines — a chunk that cuts a line in half is the ordinary case, handled on
the next pass — so the choice is purely about cost.

**Choosing `MAX_PAYLOAD`.** This one is not about cost, it is about what a
peer can make you allocate. `proto_recv_line_dyn` grows its buffer as the
line arrives; without a limit, a peer that never sends a newline — broken
or hostile — makes the other side allocate until the system kills it, once
per connection on a forking server. Past the limit the read stops with
`PROTO_E_LINE_TOO_LONG` and nothing more is allocated.

It bounds **one message**, not what an application can transfer. Anything
larger is sent as several messages, which is what you want anyway: the
receiver holds a whole line in memory, and an application that unseals it
holds three things at once — the line (at most `MAX_PAYLOAD`), the base64
decoded into `cipher` (as much again), and the plaintext (about 0.75 of
it). The worst case is therefore close to **2.75 × `MAX_PAYLOAD` per
connection**, and a forking server has one per client. A 200 MB video as
one message would be some 550 MB in one server child, all-or-nothing on a
dropped connection. Chunked into 4 MB messages it is constant memory,
resumable, and each piece can be retried on its own:

```
C->S: PUT 42 1/128 <b64 of chunk 1>
S->C: OK
...
C->S: DONE 42
S->C: OK <id>
```

The default, 16 MB, carries a sealed box of about 11.6 MB of original data
(base64 costs a third more, the seal 48 bytes) — a photo or a voice note
without chunking. Raise it if your messages are genuinely bigger and you
have the memory for `2.75 ×` it per concurrent connection; lower it on a
server that only ever exchanges short commands, where it then also serves
as a cheap sanity limit.

Both options refuse nonsense **at build time**: `MAX_PAYLOAD` must be
between 64 bytes and 1 GiB, `READ_CHUNK` at least 1. A `0` slipping in from
an empty Makefile variable would otherwise leave every read failing —
`PROTO_E_LINE_TOO_LONG` for one, `PROTO_E_PEER_CLOSED` for the other —
with nothing to point at the cause. The timeouts are checked the same way,
and for a sharper reason: a negative `HANDSHAKE_TIMEOUT_MS` reads as *no
deadline* and would quietly restore the defect the constant exists to
prevent, leaving a silent peer holding a forked child for good.

`protocol.h` also documents the shared handshake wire format (see
[appendix](#wire-protocol-appendix)).

Sealed-box overhead (from libsodium, used in buffer math):
`crypto_box_SEALBYTES` = 48 bytes added to every plaintext.

---

## Status codes

`#include "status.h"` — the `proto_status_t` enum and one function.

```c
const char *proto_strerror(int code);
```

Every `int`-returning function reports how the call ended with one of these
values. The rule is the sign:

- **Negative** — the call failed. These are the [error codes](#error-codes),
  listed in the next section.
- **`0`** — `PROTO_OK`: success, nothing else to report.
- **Positive** — success, with something the caller may want to act on.

So `rc < 0` always means failure and is the test to reach for. `rc != 0` is
safe only on functions that never return a positive — three do, below.

Failure values are grouped in hundreds: the hundreds digit is the family
(`-1xx` caller mistakes, `-2xx` resources, `-3xx` key files, and so on, in
the order of the tables below), the rest is sequential within it, and a
value is never reused. A new code joins its family's range, so these tables
stay ordered as the library grows. Compare against the names in code, and
use the value to look up what a logged code meant.

**Positive statuses**

| Code | Value | Meaning | Returned by |
|---|---|---|---|
| `PROTO_REGISTER_REQUESTED` | `1` | authenticated; the server wants our encryption public key | `proto_auth_client` |
| `PROTO_KEEPALIVE_DEFAULTED` | `2` | probing is on, but a timing knob kept the system value | `proto_keepalive` |

`proto_recv_line` also returns a positive on success — the line length —
without a named constant.

**The library never prints.** `proto_strerror` gives you the text and your
application decides where it goes — stderr, syslog, a log file, a dialog:

```c
int rc = proto_serve(5000, allowed, on_client, &db, NULL);
if (rc < 0)
    my_log(LOG_ERR, "server: %s", proto_strerror(rc));   /* "port already in use" */
```

`proto_strerror` never returns `NULL`. It describes the successes too, and an
unrecognized value yields `"unknown status code"`, so any return value can be
passed straight through.

---

## Error codes

The negative members of `proto_status_t`, grouped by what went wrong. Each
is returned by the functions listed; see [Status codes](#status-codes) for
the sign rule and the successes.

**Caller mistakes**

| Code | Value | Meaning | Returned by |
|---|---|---|---|
| `PROTO_E_PARAM` | `-101` | invalid argument | `proto_recv_line` with `bufsz == 0`, `proto_serve` with a negative `opts->drain_ms`, `proto_load_keys` with a `NULL` path or `out`, `proto_load_pubkey_hex` with a `NULL` path |
| `PROTO_E_BUFFER_TOO_SMALL` | `-102` | caller buffer cannot hold the result | `proto_load_pubkey_hex`, `proto_seal` |
| `PROTO_E_NO_ALLOWLIST` | `-103` | `allowed_hex` is `NULL` | `proto_serve` |
| `PROTO_E_BAD_ALLOWLIST` | `-104` | `allowed_hex` is not 64 lowercase hex chars — uppercase is refused too, since it would match no identity | `proto_serve` |
| `PROTO_E_NO_HANDLER` | `-105` | `handler` is `NULL` | `proto_serve` |
| `PROTO_E_BAD_ADDRESS` | `-106` | `opts->bind_addr` is not an IPv4 dotted literal | `proto_serve` |
| `PROTO_E_BAD_PORT` | `-107` | `port` is outside 1–65535 | `proto_connect`, `proto_serve` |

**Resources and initialization**

| Code | Value | Meaning | Returned by |
|---|---|---|---|
| `PROTO_E_NOMEM` | `-201` | allocation failed | `proto_seal` |
| `PROTO_E_SODIUM` | `-202` | `sodium_init()` failed | `proto_init`, `proto_connect`, `proto_serve` |

**Key files**

| Code | Value | Meaning | Returned by |
|---|---|---|---|
| `PROTO_E_KEY_OPEN` | `-301` | `open()` failed for a reason other than those below — out of descriptors or memory | `proto_load_keys`, `proto_load_pubkey_hex` |
| `PROTO_E_KEY_EMPTY` | `-302` | the first line is blank: an empty file, or nothing but spaces and tabs before the newline | idem |
| `PROTO_E_KEY_FORMAT` | `-303` | the line is not base64: a character outside the standard alphabet inside it, the URL-safe variant, or missing `=` padding | idem |
| `PROTO_E_KEY_MISMATCH` | `-304` | `auth.key` is damaged: the public key it carries does not match the one its seed derives | `proto_load_keys` |
| `PROTO_E_KEY_NOT_FOUND` | `-305` | the path leads to no file: nothing there, a component that is not a directory, a symlink loop or a name too long. Check the path and the working directory | `proto_load_keys`, `proto_load_pubkey_hex` |
| `PROTO_E_KEY_DENIED` | `-306` | no permission to read the file: check its owner and mode, and the user the program runs as | idem |
| `PROTO_E_KEY_NOT_FILE` | `-307` | the path is not a regular file — a directory, a FIFO, a device. Refused before a byte is read, so a FIFO cannot hang the load | idem |
| `PROTO_E_KEY_READ` | `-308` | `read()` failed after the file was opened: a disk or filesystem error | idem |
| `PROTO_E_KEY_STRAY` | `-309` | something around the key on its line: a space or a tab, a byte order mark an editor added, a non-breaking space pasted from a web page, quotes. Usually invisible in an editor | idem |
| `PROTO_E_KEY_SIZE` | `-310` | valid base64 of the wrong size — usually the wrong file, such as `auth.pub` where `auth.key` belongs. Given to `proto_load_pubkey_hex`, it usually means `auth.key`, the client's secret, has been copied to the server | idem |

**Cryptography**

| Code | Value | Meaning | Returned by |
|---|---|---|---|
| `PROTO_E_CRYPTO` | `-401` | libsodium operation failed | `proto_seal`, `proto_sign_challenge` |
| `PROTO_E_BAD_SIGNATURE` | `-402` | signature did not verify | `proto_verify_challenge` |

**Sockets and addressing**

| Code | Value | Meaning | Returned by |
|---|---|---|---|
| `PROTO_E_SOCKET` | `-501` | `socket()` failed — in `proto_connect`, for every address the host resolved to; in `proto_serve`, also the `socketpair()` that [`proto_serve_stop`](#proto_serve_stop) wakes it through | `proto_connect`, `proto_serve` |
| `PROTO_E_RESOLVE` | `-502` | `getaddrinfo()` failed | `proto_connect` |
| `PROTO_E_CONNECT` | `-503` | `connect()` failed for every address the host resolved to | `proto_connect` |
| `PROTO_E_BIND` | `-504` | `bind()` failed for another reason | `proto_serve` |
| `PROTO_E_PORT_IN_USE` | `-505` | `bind()` failed with `EADDRINUSE` | `proto_serve` |
| `PROTO_E_PERM_DENIED` | `-506` | `bind()` denied — `EACCES` or `EPERM` | `proto_serve` |
| `PROTO_E_LISTEN` | `-507` | `listen()` failed | `proto_serve` |
| `PROTO_E_KEEPALIVE` | `-508` | `SO_KEEPALIVE` rejected — no probing at all | `proto_keepalive` |
| `PROTO_E_ACCEPT` | `-509` | `accept()` failed in a way no retry can fix: the listening socket is unusable | `proto_serve` (after startup) |
| `PROTO_E_CONNECT_TIMEOUT` | `-510` | no address answered — silence, not a refusal. Either `CONNECT_TIMEOUT_MS` passed, or the kernel gave up first, which is what happens when its own limit (75 s here) is shorter | `proto_connect` |

**Reading and writing lines**

| Code | Value | Meaning | Returned by |
|---|---|---|---|
| `PROTO_E_WRITE` | `-601` | `write()` failed | `proto_send_line`, `proto_send_prefixed` |
| `PROTO_E_READ` | `-602` | `read()` failed | `proto_recv_line` |
| `PROTO_E_PEER_CLOSED` | `-603` | the peer closed the connection | `proto_recv_line` |
| `PROTO_E_LINE_TOO_LONG` | `-604` | the line did not fit — the caller's buffer for `proto_recv_line`, `MAX_PAYLOAD` for the allocating readers; the rest is still unread either way | `proto_recv_line`, `proto_recv_line_timeout`, `proto_recv_line_dyn_status` |
| `PROTO_E_TIMEOUT` | `-605` | the deadline passed before the whole line arrived | `proto_recv_line_timeout`; surfaces from `proto_connect` and `proto_auth_client` when the server goes silent mid-handshake |

**Handshake, client side**

| Code | Value | Meaning | Returned by |
|---|---|---|---|
| `PROTO_E_UNEXPECTED_REPLY` | `-701` | the server said something else | `proto_auth_client` |
| `PROTO_E_BAD_CHALLENGE` | `-702` | challenge malformed or not 32 bytes | `proto_auth_client` |
| `PROTO_E_REJECTED` | `-703` | the server refused the handshake | `proto_auth_client`, `proto_connect` |
| `PROTO_E_REGISTER_REJECTED` | `-704` | the server refused our `REGISTER` | `proto_connect` |

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

An authenticated client session. One conn holds at most one connection.
Lifecycle:

1. Zero it, set `fd = -1`.
2. Fill `keys` with [`proto_load_keys`](#proto_load_keys).
3. [`proto_connect`](#proto_connect) — on success `fd` is a connected,
   authenticated socket and `identity_hex` is set.
4. Talk using the `wire` functions on `conn.fd`.
5. [`proto_close`](#proto_close) — sends `QUIT`, closes, sets `fd = -1`.

`proto_connect` leaves `fd == -1` on failure, so `fd >= 0` doubles as an
"is connected" check. To reconnect, call `proto_connect` again: if the conn
still holds a connection — live or dead — it is closed first, so the old
socket is never leaked (see [Recipes](#recipes)).

**Why `fd = -1` and not just `{0}`.** Zero is a valid descriptor (stdin),
so a `{0}` struct claims to hold a connection it never made. The library
defends itself — before closing anything in `fd` it asks the kernel whether
the number is a socket at all, and leaves stdin alone — but the defence has
one blind spot: a program whose stdin *is* a socket (one started by
`inetd`, or with a socket redirected into it). `-1` needs no judgement.

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
  config struct). Only the address is passed, and the handler runs in a
  forked child, so what it points to is the child's copy: changes made
  through `ctx` do not reach the parent or other connections. State that
  must be shared across connections needs shared memory (`mmap` with
  `MAP_SHARED`) set up before `proto_serve` is called.

When the handler returns, the child closes the socket and exits. Anything the
handler changes in memory is lost — persist through your storage.

**Signals in the child.** `SIGPIPE` is ignored, so a write of your own to a
closed peer fails with `EPIPE` instead of killing the child. `SIGCHLD` is at
its default: the parent's reaper is not inherited, so a handler that runs
other programs — `popen`/`pclose`, `system`, its own `fork` and `waitpid` —
gets their exit status as in any C program. The signal handlers you
installed before `proto_serve` are inherited as they are; one that calls
[`proto_serve_stop`](#proto_serve_stop) ends the child at once, as the
signal would have without it.

### `proto_serve_opts_t`

```c
typedef struct {
    const char *bind_addr;   /* IPv4 literal to listen on; NULL = all interfaces */
    int drain_ms;            /* after a stop, wait for connections; 0 = no wait */
} proto_serve_opts_t;
```

Deployment options for [`proto_serve`](#proto_serve). Every field has a
default, and **zero means default**: `NULL` for a pointer, `0` for a
number. Passing `NULL` instead of a struct means every default — that is
what most callers do.

| Field | Default | Meaning |
|---|---|---|
| `bind_addr` | `NULL` (every interface) | IPv4 address to listen on, as a dotted literal such as `"127.0.0.1"` or `"10.0.0.5"`. No name resolution; anything `inet_pton` rejects fails `proto_serve` with `PROTO_E_BAD_ADDRESS` before the port is touched. |
| `drain_ms` | `0` (no wait) | Once [`proto_serve_stop`](#proto_serve_stop) is called, how long `proto_serve` waits for the connections in progress before it returns, in milliseconds; it returns sooner if the last one ends first. A connection still open when the time runs out is left running. Keep it below your supervisor's grace period — Docker allows 10 s, systemd 90 s by default — or the wait ends in `SIGKILL`. A negative value fails `proto_serve` with `PROTO_E_PARAM` before the port is touched. |

**Always use a designated initializer.** It zeroes every field you do not
name, which is what makes "zero means default" safe, and it keeps compiling
when a field is added in a later version:

```c
proto_serve_opts_t opts = { .bind_addr = "127.0.0.1" };
return proto_serve(5000, allowed, on_client, ctx, &opts);
```

A struct declared without an initializer holds garbage; passing it is
undefined behaviour, not "the defaults". Fields are only ever appended, so
positional initializers are also a trap — name the field.

---

## Module `wire` — framing

`#include "wire.h"` — no dependencies besides libc. One message = one
`\n`-terminated line; `\r` is stripped on read.

**How lines are read.** The readers keep no state between calls — they work
on a bare fd — yet never take a byte of the next line: each step peeks at
what the socket holds (`MSG_PEEK`, up to [`READ_CHUNK`](#constants-protocolh-wireh)
bytes), finds the newline, and then consumes exactly up to it. A long line
costs two system calls per chunk rather than one per byte; a short line
costs its own length.

On a descriptor that is not a socket there is no `MSG_PEEK`, so the readers
fall back to one byte at a time — the only way to stop at the newline
without swallowing what follows it. That is the case for a pipe: a protocol
tunnelled through another program's standard input and output, and most
test harnesses. The peek is attempted once per line, not once per byte, so
such a descriptor costs what it did before peeking existed: one system call
per byte. Sockets are what the fast path is for.

### `proto_send_line`

```c
int proto_send_line(int fd, const char *line);
```

Write `line` followed by `\n`.

| Param | Description |
|---|---|
| `fd` | connected socket |
| `line` | NUL-terminated string, **must not contain `\n`** |

**Returns** `PROTO_OK` or `PROTO_E_WRITE`. A short write is resumed and an
interrupted one retried, so success means the whole line reached the socket
and failure means the connection broke — never a half-sent line. Writing to
a peer that has closed returns `PROTO_E_WRITE`; it does not raise `SIGPIPE`,
so the caller gets to save its state and close the socket instead of being
killed.

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
| `bufsz` | its size; must be ≥ 1, and `0` is rejected with `PROTO_E_PARAM`. It holds a line of up to `bufsz - 1` characters, that many exactly included — `char[5]` takes `"abcd"` |

**Returns** the line length (≥ 0), or a negative [code](#error-codes):
`PROTO_E_PEER_CLOSED` if the peer closed, `PROTO_E_READ` on a socket error,
`PROTO_E_LINE_TOO_LONG` if the line did not fit, `PROTO_E_PARAM` if `bufsz`
is `0`. On every error path `buf` is still NUL-terminated.

**Pitfall:** if the incoming line is longer than `bufsz - 1`, the read stops
early and **the rest of the line stays in the socket**, corrupting the next
read. Use it only for lines with a known small bound (handshake replies,
`OK`/`FAIL`, list headers). For payload rows use
[`proto_recv_line_dyn`](#proto_recv_line_dyn).

The limit is exact, and costs one character to establish: when the buffer
is full the reader takes one more character to see whether the line ended
there. So a line of exactly `bufsz - 1` characters is returned, and a
longer one is `PROTO_E_LINE_TOO_LONG` with everything after that one
character still unread — the stream is past saving either way, which is
what the pitfall is about.

```c
char reply[MAX_LINE];
if (proto_recv_line(fd, reply, sizeof reply) < 0) goto disconnected;
if (strncmp(reply, "OK", 2) != 0) goto server_said_no;
```

### `proto_recv_line_timeout`

```c
int proto_recv_line_timeout(int fd, char *buf, size_t bufsz, int ms);
```

[`proto_recv_line`](#proto_recv_line) with a deadline. If the whole line has
not arrived within `ms` milliseconds the call gives up with
`PROTO_E_TIMEOUT`; everything else — parameters, return values, the
too-long pitfall — is as for `proto_recv_line`.

| Param | Description |
|---|---|
| `fd`, `buf`, `bufsz` | as for `proto_recv_line` |
| `ms` | deadline in milliseconds for the **whole line**; `< 0` means no deadline (identical to `proto_recv_line`) |

The deadline is per line, not per byte: it is set once when the call starts
and checked before every read, so a peer trickling one byte at a time cannot
stretch it. A signal that interrupts the wait resumes it with the time that
remains. On timeout `buf` holds whatever arrived so far, NUL-terminated, and
the bytes after it are still in the socket — the stream is no longer at a
line boundary, so the sensible reaction is to close the connection.

This is what bounds the handshake: every handshake read in `auth` uses it
with [`HANDSHAKE_TIMEOUT_MS`](#constants-protocolh-wireh), and `proto_close` uses
it with `QUIT_TIMEOUT_MS`. Applications may use it for their own commands
where a silent peer must not block a thread or a forked child; for a peer
that has *vanished* rather than gone quiet, see
[`proto_keepalive`](#proto_keepalive) — the two detect different things.

```c
char reply[MAX_LINE];
int rc = proto_recv_line_timeout(fd, reply, sizeof reply, 5000);
if (rc == PROTO_E_TIMEOUT) goto peer_too_slow;
if (rc < 0)                goto disconnected;
```

### `proto_recv_line_dyn`

```c
char *proto_recv_line_dyn(int fd);
```

Read one line of up to [`MAX_PAYLOAD`](#constants-protocolh-wireh)
characters into a heap buffer (grows by doubling, starts at 4 KB, never
past the limit). NUL-terminated, newline stripped.

**Returns** the line (caller **must `free()`**), or `NULL` on error, on
end of stream, or when the line is longer than `MAX_PAYLOAD`. `NULL` is the
normal way to detect a disconnected peer in a server command loop; when the
reason matters, use
[`proto_recv_line_dyn_status`](#proto_recv_line_dyn_status).

```c
char *line;
while ((line = proto_recv_line_dyn(fd)) != NULL) {
    dispatch(line);
    free(line);
}
/* NULL: client went away, or sent a line past MAX_PAYLOAD */
```

### `proto_recv_line_dyn_status`

```c
char *proto_recv_line_dyn_status(int fd, int *status);
```

[`proto_recv_line_dyn`](#proto_recv_line_dyn) that says why it failed.
`status` may be `NULL`, in which case the two are identical.

| Param | Description |
|---|---|
| `fd` | connected socket |
| `status` | set to `PROTO_OK` on success, or to the reason for the `NULL`: `PROTO_E_LINE_TOO_LONG` (over `MAX_PAYLOAD`), `PROTO_E_PEER_CLOSED`, `PROTO_E_READ`, `PROTO_E_NOMEM` |

Use it where the reason changes what the application does. Telling "the
client is gone" from "the client sent something too big" is the usual case:
the second deserves an answer before the connection closes.

```c
int rc;
char *line = proto_recv_line_dyn_status(fd, &rc);
if (!line) {
    if (rc == PROTO_E_LINE_TOO_LONG)
        proto_send_line(fd, "FAIL message too large");   /* then close */
    return;                                              /* peer gone: nothing to say */
}
```

**After `PROTO_E_LINE_TOO_LONG` the connection is finished.** The rest of
the oversized line is still in the socket — the reader stops rather than
draining it, because draining is exactly the unbounded work the limit
exists to prevent — so the stream is no longer at a line boundary. Answer
if you want to, then close.

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

**Returns** `PROTO_OK` / `PROTO_E_WRITE`. As with `proto_send_line`, a peer
that has closed yields `PROTO_E_WRITE` rather than `SIGPIPE`.

```c
char *sealed = proto_seal_new(data, data_len, conn.keys.enc_pk);
proto_send_prefixed(conn.fd, "PUT ", sealed, strlen(sealed));
free(sealed);
```

---

### `proto_keepalive`

```c
int proto_keepalive(int fd, int idle_s, int intvl_s, int count);
```

Ask the kernel to probe `fd` once it goes idle, so a peer that vanishes
without closing eventually fails the socket instead of leaving a `read()`
blocked forever. Nothing in the library calls this for you: a connection has
no keepalive until you enable it, on either end.

**Recommended on servers.** A forking server has the most to lose: every
client that vanishes without closing leaves a child blocked in `read()`
forever, holding a socket and whatever per-connection state you keep, and
those accumulate — one immortal process per lost peer. A client can bound its
own waits and exit; a server never knows which peer will disappear. Enable it
in your handler unless you have a specific reason not to.

| Param | Description |
|---|---|
| `fd` | a connected socket — `conn.fd` on the client, the handler's `fd` on the server |
| `idle_s` | seconds of silence before the first probe (`<= 0` = system default, ~7200) |
| `intvl_s` | seconds between probes once one goes unanswered (`<= 0` = system default, 75) |
| `count` | unanswered probes before the connection is declared dead (`<= 0` = system default, 8–9) |

Worst-case detection is `idle_s + intvl_s * count`; with every knob left at
its default, about two hours. When it fires, the blocked `read()` returns -1
with `errno == ETIMEDOUT`, so existing teardown paths run unchanged. A peer
whose host is alive but whose process died answers `RST` instead, and the
connection fails immediately without waiting for `count` probes.

**Returns** `PROTO_OK`; `PROTO_KEEPALIVE_DEFAULTED` (a positive value, not a
failure) if probing is on but a timing knob was rejected and kept the system
value; `PROTO_E_KEEPALIVE` if the socket refused probing altogether.

**Not a read timeout.** This is a backstop against blocking forever, not a way
to give up promptly — it says nothing about how long *you* wait for a reply.
Reads stay plain and blocking: no `SO_RCVTIMEO`, no `errno` inspection, no
partial-line hazard. Keepalive detects a peer that *vanished* (host gone,
cable cut); a peer that is alive but *silent* answers every probe and is
never flagged. For that case use
[`proto_recv_line_timeout`](#proto_recv_line_timeout), which is what the
library itself does during the handshake.

```c
/* client — this connection will sit idle, so let the kernel watch it */
proto_connect(&conn, host, port);
proto_keepalive(conn.fd, 60, 10, 3);        /* dead peer noticed in ~90 s */

/* server — same call, on the handler's fd */
static void handler(int fd, const char *identity_hex, void *ctx) {
    proto_keepalive(fd, 0, 0, 0);           /* system defaults */
    /* ... */
}
```

**The handshake is covered separately.** `proto_serve` authenticates in a
forked child *before* calling your handler, so probing enabled there starts
only after the handshake. That window is bounded on its own: every handshake
read gives up after [`HANDSHAKE_TIMEOUT_MS`](#constants-protocolh-wireh), whether
the peer vanished or merely went quiet, so a child never outlives it.

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

**Returns** `PROTO_OK` / `PROTO_E_SODIUM` (libsodium could not initialize;
there is no way to continue — abort).

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
| `out` | filled on success; wiped on failure, including a key that had loaded before the other file failed, so there is nothing to clean up |

**Returns** `PROTO_OK`, `PROTO_E_PARAM` for a `NULL` path or `out`, or one
of the [key file codes](#error-codes), each pointing at a different thing to
check: the path (`PROTO_E_KEY_NOT_FOUND`, `PROTO_E_KEY_NOT_FILE`), the
permissions (`PROTO_E_KEY_DENIED`), the system (`PROTO_E_KEY_OPEN`,
`PROTO_E_KEY_READ`) or the contents (`PROTO_E_KEY_EMPTY`,
`PROTO_E_KEY_STRAY`, `PROTO_E_KEY_FORMAT`, `PROTO_E_KEY_SIZE`). The code says
what went wrong but not which of the two files: call it once per file if you
need that distinction. The exception is `PROTO_E_KEY_MISMATCH`, which only
`auth.key` can cause: its public half does not match its seed, so the file
is damaged. On any failure `out` is wiped, so nothing that had loaded is
left behind. Nothing is printed — pass the code to
[`proto_strerror`](#error-codes) and log it where you want.

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

**Returns** `PROTO_OK`, one of the `PROTO_E_KEY_*` codes (as for
[`proto_load_keys`](#proto_load_keys)), `PROTO_E_PARAM` for a `NULL` path,
or `PROTO_E_BUFFER_TOO_SMALL` if `hex_sz` is below `AUTH_PK_LEN * 2 + 1`.
Handed `auth.key` by mistake, it fails with `PROTO_E_KEY_SIZE`: that file is
the client's secret and must not stay on the server.

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
`sodium_base64_ENCODED_LEN(msg_len + crypto_box_SEALBYTES, sodium_base64_VARIANT_ORIGINAL)`.
The macro already counts the trailing NUL — do not add 1. (This differs from
`sodium_bin2hex`, whose size argument is `len * 2 + 1` with the NUL added by
the caller.)

**Returns** `PROTO_OK`, `PROTO_E_BUFFER_TOO_SMALL` if `out_b64_sz` is below
the size given above, `PROTO_E_NOMEM`, or `PROTO_E_CRYPTO`. Binary-safe:
`msg` may contain NUL bytes.

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
case you build a custom transport. **Returns** `PROTO_OK` / `PROTO_E_CRYPTO`.

### `proto_verify_challenge`

```c
int proto_verify_challenge(const unsigned char *challenge, size_t clen,
                           const unsigned char *sig,
                           const unsigned char *auth_pk);
```

Verify a detached signature against a public key. The server-side twin of
`proto_sign_challenge`; used internally by `proto_auth_server`. **Returns**
`PROTO_OK` if the signature is valid, `PROTO_E_BAD_SIGNATURE` otherwise.

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

0. if `conn` still holds a connection, closes it as
   [`proto_close`](#proto_close) would — one conn, one connection, so
   reconnecting never leaks the previous socket,
1. initializes libsodium (`proto_init`),
2. resolves `host` and TCP-connects to the first of its addresses that
   accepts — a name usually has an IPv6 and an IPv4, tried in the
   resolver's order, each given `CONNECT_TIMEOUT_MS`, so a server
   reachable on only one of them still connects and a silent one does not
   hold the call,
3. runs the handshake (`HELLO` → `CHALLENGE` → `AUTH`),
4. if the server answers `REGISTER` (first connection), sends
   `REGISTER <enc_pk b64>` and expects `OK`,
5. fills `conn->identity_hex`.

**Precondition:** `conn->keys` must already be filled
([`proto_load_keys`](#proto_load_keys)), and `conn->fd` must be `-1` or a
socket this library opened — see [`proto_conn_t`](#proto_conn_t).

| Param | Description |
|---|---|
| `conn` | session struct; on success `conn->fd` is ready for app commands. A connection it still holds is closed first |
| `host` | hostname or address |
| `port` | server port, 1–65535 (application policy — the library has no default) |

**Returns** `PROTO_OK` on success, or the code for the stage that failed —
`PROTO_E_BAD_PORT`, `PROTO_E_RESOLVE`, `PROTO_E_SOCKET`, `PROTO_E_CONNECT`,
`PROTO_E_CONNECT_TIMEOUT`, `PROTO_E_REJECTED`, `PROTO_E_REGISTER_REJECTED`,
or whatever the handshake returned. On failure `conn->fd` is left at `-1`
and the socket is closed.

The code says which stage failed, and each points the user somewhere
different:

| Code | What happened | What to look at |
|---|---|---|
| `PROTO_E_BAD_PORT` | `port` outside 1–65535, checked before anything is resolved — a port parsed from an empty variable is `0`, and this says so rather than blaming a hostname that was fine | the configuration |
| `PROTO_E_RESOLVE` | the name has no addresses | the name, DNS |
| `PROTO_E_SOCKET` | none of the address families offered exists on this host | IPv6 availability |
| `PROTO_E_CONNECT_TIMEOUT` | no address answered — the deadline passed, or the kernel gave up first | the network, a firewall, whether the host is up |
| `PROTO_E_CONNECT` | an address answered, refusing | whether the server is running, and on which port |
| `PROTO_E_TIMEOUT` | connected, then the server went silent mid-handshake | the server process itself |
| `PROTO_E_REJECTED` | the server declined the handshake | the allowlist — is this identity authorized |
| `PROTO_E_REGISTER_REJECTED` | it declined the registration | the server's registration policy |

A refusal anywhere outweighs silence: if one address refuses and another
never answers, the result is `PROTO_E_CONNECT`, because something being
there and saying no is the more useful fact. Pass any of them to
[`proto_strerror`](#error-codes) for the message.

**Silent addresses cost time, but a bounded amount.** An address that
refuses fails at once; one that answers nothing — a firewall dropping
packets — is given [`CONNECT_TIMEOUT_MS`](#constants-protocolh-wireh)
(10 s) before the next address is tried. Without that bound it would be
the kernel's own limit: measured at 75 s per address on macOS, and about
twice that on Linux. The deadline is per address, not per call, because
the point of trying them all is that a dead one must not hide a live one;
a name with two silent addresses therefore waits twice.

### `proto_close`

```c
void proto_close(proto_conn_t *conn);
```

Graceful shutdown: sends `QUIT`, waits up to
[`QUIT_TIMEOUT_MS`](#constants-protocolh-wireh) for the `BYE`, closes the socket,
sets `conn->fd = -1`. The wait is a courtesy: a server that never answers,
or one to which `QUIT` cannot even be sent, does not delay the close beyond
that bound. Safe to call on an already-closed conn (no-op when `fd < 0`),
and on a dead one: the `QUIT` fails, the wait is skipped, the socket is
closed. If `fd` holds a number that is not a socket (a `{0}` struct that
never connected has stdin there) nothing is closed; `fd` is just set to
`-1`.

### `proto_auth_client`

```c
int proto_auth_client(int fd, const proto_keys_t *keys);
```

Client handshake **primitive**: runs `HELLO` → `CHALLENGE` → `AUTH` on an
already-connected fd, and stops at the server's verdict.

**Returns**
- `PROTO_OK` — authenticated; server replied `OK` (known user)
- `PROTO_REGISTER_REQUESTED` — authenticated; server replied `REGISTER` (it
  wants your enc pubkey next — send `REGISTER <b64(enc_pk)>` and expect `OK`)
- a negative code — `PROTO_E_REJECTED` if the server declined with a
  `FAIL …` line at any point (after `AUTH`: unknown key, bad signature;
  before the challenge: `FAIL server busy` when it cannot fork, or
  `FAIL internal error` when its allowlist is unusable),
  `PROTO_E_UNEXPECTED_REPLY` if the reply to `HELLO` was neither
  `CHALLENGE` nor `FAIL`, `PROTO_E_BAD_CHALLENGE` if the challenge line was
  malformed, `PROTO_E_TIMEOUT` if the server went silent for longer than
  [`HANDSHAKE_TIMEOUT_MS`](#constants-protocolh-wireh) on any line, or another
  transport code from the underlying read or write

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
| `allowed_hex` | the one authorized identity — 64 lowercase hex chars, from [`proto_load_pubkey_hex`](#proto_load_pubkey_hex). `NULL`, or anything else — uppercase, not hex, the wrong length — is rejected with `FAIL internal error` before the handshake starts |

**Returns** the authenticated identity hex (heap; caller **frees**), or
`NULL` on failure. On every failure path a descriptive `FAIL <reason>` line
has already been sent to the peer (`expected HELLO`, `invalid public key`,
`signature verification failed`, `access denied`, …), so the caller just
closes the socket. Each read waits at most
[`HANDSHAKE_TIMEOUT_MS`](#constants-protocolh-wireh): a peer that connects and
says nothing gets `NULL` after that, not a caller blocked for good.

Note the returned identity always equals `allowed_hex` in the current
single-user model; it is returned (rather than a bool) so multi-user
variants and storage code can key on it.

---

## Module `serve` — server harness

`#include "serve.h"` — the only server-only file.

### `proto_serve`

```c
int proto_serve(int port, const char *allowed_hex,
                proto_handler_fn handler, void *ctx,
                const proto_serve_opts_t *opts);
```

The turnkey server. In one call:

1. initializes libsodium,
2. ignores `SIGPIPE`, installs a `SIGCHLD` reaper in the parent (no zombies),
3. creates the listening socket (`SO_REUSEADDR`, backlog 16, on
   `opts->bind_addr` or every interface),
4. loops: `accept` → `fork` → in the child, restore `SIGCHLD`'s default
   (see [signals in the child](#proto_handler_fn)), authenticate with
   [`proto_auth_server`](#proto_auth_server) → on success call
   `handler(fd, identity_hex, ctx)` → close and `_exit`,
5. until [`proto_serve_stop`](#proto_serve_stop): then it accepts no one
   else, closes the port, gives the connections in progress up to
   `opts->drain_ms` to finish, and returns `PROTO_OK`.

**Under pressure.** Running out of descriptors or processes does not stop
the server. An `accept` that fails for lack of a descriptor or memory is
retried after 100 ms (a child exiting frees what is missing; retrying at
once would spin at full CPU on Linux, where the pending connection stays
queued). A `fork` that fails answers the client `FAIL server busy` and
closes, so the client sees a refusal it can retry, not a network error —
the parent reads the client's `HELLO` first (waiting at most 100 ms),
because closing with data unread would reset the connection and lose the
reply.

| Param | Description |
|---|---|
| `port` | TCP port to listen on, 1–65535. `0` is refused too: the kernel would pick a free port, but `proto_serve` has no way to tell you which, so the server would run where no client can find it |
| `allowed_hex` | authorized identity, 64 lowercase hex chars (see `proto_load_pubkey_hex`); anything else fails with `PROTO_E_BAD_ALLOWLIST` |
| `handler` | your per-connection function ([contract](#proto_handler_fn)) |
| `ctx` | passed through to the handler untouched (DB path, config, …) |
| `opts` | deployment options ([`proto_serve_opts_t`](#proto_serve_opts_t)); `NULL` for all defaults |

**Returns** `PROTO_OK` after [`proto_serve_stop`](#proto_serve_stop): the
port is closed and the connections in progress have had `opts->drain_ms`
to finish, so the code after the call runs — close your storage, log,
exit 0. Otherwise only when it cannot serve. At startup:
`PROTO_E_NO_ALLOWLIST`, `PROTO_E_BAD_ALLOWLIST`, `PROTO_E_NO_HANDLER`,
`PROTO_E_BAD_PORT`, `PROTO_E_BAD_ADDRESS`, `PROTO_E_PARAM` (a negative
`drain_ms`), `PROTO_E_SODIUM`, `PROTO_E_SOCKET`, `PROTO_E_PORT_IN_USE`,
`PROTO_E_PERM_DENIED`, `PROTO_E_BIND` or `PROTO_E_LISTEN`. Later:
`PROTO_E_ACCEPT`, when `accept` fails in a way no retry can fix — the
listening socket itself has become unusable — so the application can log
it and decide, rather than the loop spinning forever in silence. The
allowlist, handler, port, bind address and drain time are checked first,
before the port is bound, so a misconfigured server fails at startup
instead of rejecting every connection — or, worse, running on a port nobody
expects.

**When not to use it:** threads instead of forks, event loops, several
authorized keys, pre-auth connection logging, or non-TCP transports — write
your own accept loop around `proto_auth_server` instead (recipe below).

**One per process.** Run one `proto_serve` at a time in a process.
[`proto_serve_stop`](#proto_serve_stop) is safe to call from any thread, but
there is one stop per process, not one per server: with two servers running
in two threads, a stop could end only one of them. Two ports, two specific
interfaces or two keys are better served by two processes — each has its
own stop — or by your own accept loop around `proto_auth_server` (recipe
below).

```c
int main(void) {
    if (proto_init() != 0) return 1;
    char allowed[AUTH_PK_LEN * 2 + 1];
    if (proto_load_pubkey_hex("auth.pub", allowed, sizeof allowed) != 0) return 1;
    return proto_serve(5000, allowed, on_client, "/var/lib/app/data.db", NULL);
}
```

Behind a reverse proxy or an SSH tunnel, listen on loopback only:

```c
proto_serve_opts_t opts = { .bind_addr = "127.0.0.1" };
return proto_serve(5000, allowed, on_client, "/var/lib/app/data.db", &opts);
```

### `proto_serve_stop`

```c
void proto_serve_stop(void);
```

Asks the running [`proto_serve`](#proto_serve) to stop. It accepts no one
else, closes the port — free at once for the next instance — gives the
connections in progress up to [`opts->drain_ms`](#proto_serve_opts_t) to
finish, and returns `PROTO_OK`, so the code after the call runs.

The library takes no signal for itself; route the ones you want here from
a handler of your own:

```c
static void on_term(int sig) { (void)sig; proto_serve_stop(); }

int main(void) {
    /* ... load the allowlist, open storage ... */
    signal(SIGTERM, on_term);            /* kill, systemctl stop, docker stop */
    signal(SIGINT,  on_term);            /* Ctrl-C */

    proto_serve_opts_t opts = { .drain_ms = 5000 };
    int rc = proto_serve(5000, allowed, on_client, &db, &opts);
    if (rc < 0) { my_log(LOG_ERR, "server: %s", proto_strerror(rc)); return 1; }
    close_storage(&db);                  /* asked to stop: finish cleanly */
    return 0;
}
```

**Why it is needed.** A handler of your own cannot do this alone.
`proto_serve` waits inside the library, which resumes the wait when a
signal interrupts it, so control never comes back to your code to look at
a flag: the signal is swallowed, and the process neither dies nor stops.

**Where it is safe.** In a signal handler, and on any thread. It sets a
flag, writes one byte to a channel that wakes `proto_serve`, and leaves
`errno` as it found it. That channel is a socket pair the first
`proto_serve` creates and the parent never closes — a stop on another
thread can then never write to a number that has since been reused for
another file — so from then on the process holds two descriptors of the
library's. Leave them open: code that closes every descriptor it did not
open itself must spare these two. There is one stop per process, not one
per server ([one per process](#proto_serve)).

**When it takes effect.**

- While `proto_serve` is serving: at once. A client still waiting to be
  accepted is not: closing the port resets its connection.
- Before `proto_serve` has started — the signal arrives while you are still
  loading keys — the stop is kept. `proto_serve` sets up, sees it, closes
  the port and returns `PROTO_OK`. Setting up first is deliberate: a port
  that cannot be opened is still reported, so a broken deployment shows up
  now rather than at the next start.
- While `proto_serve` is draining: it is part of the stop in progress.
  After `proto_serve` has returned: it is kept for the next call.

**What happens to the connections.** They are not told to finish.

- The parent waits up to `drain_ms` (default `0`, no wait) and returns as
  soon as the last child has ended. A connection still open when the time
  runs out is left running and ends when its client leaves.
- The wait counts every child of the process, including any you forked
  yourself: the kernel does not tell them apart.
- A child that receives the signal itself — `kill` on its pid, Ctrl-C
  reaching the whole process group, systemd's default `KillMode` — runs
  the handler it inherited, and there `proto_serve_stop` ends the child at
  once, as the signal would have without your handler. Children behave as
  they did before v1.2.
- Ending a child gracefully — between two messages, with a `BYE` to its
  client — comes with bidirectionality, in v2.0 (see `TODO.md`).

---

## Tool `keygen` — generating key files

`keygen/keygen.c` — a standalone CLI tool, **not part of the library
sources**. It lives in its own subdirectory precisely so that `protocol/*.c`
globs never pick up its `main()`. It depends only on libsodium and
`protocol.h` (for the key-size constants), so it builds even where the rest
of the library isn't compiled.

### Build

```sh
make -C keygen              # produces keygen/keygen
make -C keygen arm64        # cross-build (aarch64-linux-gnu-gcc)
make -C keygen BUILD=/out   # place the binary elsewhere
```

Or by hand: `cc -O2 -o keygen keygen/keygen.c -lsodium`.

### Run

```sh
cd ~/my-keys        # keys are written to the current directory
/path/to/protocol/keygen/keygen
```

No arguments. It generates one complete identity:

| Step | libsodium call | Files written |
|---|---|---|
| Ed25519 authentication keypair | `crypto_sign_keypair` | `auth.key` (secret, 64 B), `auth.pub` (public, 32 B) |
| X25519 encryption keypair | `crypto_box_keypair` | `enc.key` (secret, 32 B) — the public half is discarded, it is re-derived on load |

Each file is a single line of base64 (standard variant), created with mode
`0600` (owner only) from the moment it exists, in exactly the format
[`proto_load_keys`](#proto_load_keys) and
[`proto_load_pubkey_hex`](#proto_load_pubkey_hex) parse — the tool is the
writing half of the key-file contract those functions read.

### Notes

- **Existing files are never overwritten.** If any of the three exists the
  tool stops with `already exists; refusing to overwrite a key` and creates
  nothing. A new identity means the server won't recognize you (`FAIL
  access denied` until it gets the new `auth.pub`), and data sealed to the
  old `enc.key` becomes permanently unreadable — so regenerating is a
  deliberate act: back the old files up, delete them, run again.
- **Filesystems without permissions.** On FAT, some network mounts and
  similar, `0600` cannot be enforced and the files would be readable by
  every user of the machine. The tool checks *before* writing anything —
  it creates and removes a probe file — and if so, prints a warning and
  asks `Create the key files here anyway? [y/N]`. Anything but `y` aborts
  with nothing written. With no terminal on stdin (a script, a
  Dockerfile) the answer is always no; generate the keys on a filesystem
  that can protect them and copy them afterwards.
- A write error (disk full, and so on) is reported and the partial file
  removed, so a truncated key never sits on disk looking valid.
- Distribute the files as the [key-file table](#key-files--formats) says:
  both `.key` files stay with the client; `auth.pub` goes to the server.
- One run = one identity. For several devices sharing an identity, copy the
  files; for separate identities, run the tool once per directory.

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

### Reconnect after the connection drops

Call `proto_connect` again on the same conn. It closes whatever the conn
still holds before opening the new socket, so nothing leaks whether the
old connection was dead (a read returned `PROTO_E_PEER_CLOSED`) or merely
slow (`PROTO_E_TIMEOUT` on a read of yours):

```c
int rc = proto_recv_line_timeout(conn.fd, reply, sizeof reply, 5000);
if (rc == PROTO_E_PEER_CLOSED || rc == PROTO_E_TIMEOUT) {
    rc = proto_connect(&conn, host, port);      /* old socket closed for you */
    if (rc < 0) return rc;
    /* redo whatever was in flight: the server has no memory of it */
}
```

Only the socket is replaced; `conn.keys` and `conn.identity_hex` are
untouched. Any per-session state the *application* kept on the server —
a write slot, a cursor — is gone with the old connection, and the new
one starts from the handshake.

**What an interrupted message costs.** TCP hides the small failures: lost,
reordered or corrupted packets are retransmitted, so a brief glitch only
makes the read take longer. What it does not hide is the connection
breaking — then the read fails, whatever had arrived of the line is
discarded, and there is no resume. A message is delivered whole or not at
all, which is what keeps a half-received photo from ever reaching storage,
but it means a 16 MB message lost at 99% is resent from the start. Two
consequences worth designing for:

- **`PROTO_OK` from a send is not an acknowledgment.** It means the bytes
  reached the kernel's send buffer, not the peer. The only acknowledgment
  is the reply your protocol defines (`OK`/`FAIL`).
- **A retry can duplicate.** If the connection dies after the server acted
  but before its `OK` arrives, the client cannot tell that from "never
  arrived", and will resend. Give commands that change state an
  application-level id — `PUT 42 3/128` is safe to repeat, a bare
  `POST <text>` is not.

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
#include <signal.h>
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

/* stop on SIGTERM or Ctrl-C, letting commands in progress finish ----- */

static void on_term(int sig) { (void)sig; proto_serve_stop(); }

int main(void) {
    if (proto_init() != 0) return 1;

    char allowed[AUTH_PK_LEN * 2 + 1];
    if (proto_load_pubkey_hex("auth.pub", allowed, sizeof allowed) != 0)
        return 1;

    signal(SIGTERM, on_term);
    signal(SIGINT,  on_term);

    printf("vault-server listening on %d\n", VAULT_PORT);
    proto_serve_opts_t opts = { .drain_ms = 5000 };
    int rc = proto_serve(VAULT_PORT, allowed, on_client, "vault.db", &opts);
    if (rc < 0) {
        fprintf(stderr, "vault-server: %s\n", proto_strerror(rc));
        return 1;
    }
    printf("vault-server stopped\n");
    return 0;
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
	      protocol/status.c protocol/wire.c protocol/crypto.c protocol/auth.c $(LDFLAGS)

server: vault-server.c
	$(CC) $(CFLAGS) -o vault-server vault-server.c \
	      protocol/status.c protocol/wire.c protocol/crypto.c protocol/auth.c \
	      protocol/serve.c $(LDFLAGS)
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
socket, desynchronizing everything after. That read returns
`PROTO_E_LINE_TOO_LONG`, so check for it — and read any line that can carry a
payload with `proto_recv_line_dyn`.

**My program ignores Ctrl-C while waiting for a line.**
Blocking reads retry when a signal interrupts them, so setting a flag from
the handler is not enough — the read never returns to let your loop check
it. This bites clients waiting for a reply and server handlers waiting for
the next command alike:

```c
static volatile sig_atomic_t stop = 0;
static void on_int(int s) { (void)s; stop = 1; }   /* not enough on its own */

while (!stop) {
    char *line = proto_recv_line_dyn(fd);          /* still blocked */
    ...
}
```

Cancel the pending call by shutting the socket down from the handler.
`shutdown()` is safe to call there, and it makes the blocked read return at
once:

```c
static int g_fd = -1;                              /* set once connected */

static void on_int(int s) {
    (void)s;
    stop = 1;
    shutdown(g_fd, SHUT_RDWR);                     /* unblocks the read */
}
```

The read then returns `PROTO_E_PEER_CLOSED` (or `NULL` from
`proto_recv_line_dyn`) — the descriptor really is unusable at that point,
so the code is honest. A client that would rather poll its own state while
idle can instead wait with a bound and check the flag between waits; that is
what `proto_wait` is for, with bidirectionality, in v2.0.

This is about reads. To stop the server itself — `proto_serve`, waiting for
clients — call [`proto_serve_stop`](#proto_serve_stop) from the handler
instead; it needs no `shutdown()`.

**`proto_load_keys` returns `PROTO_E_KEY_NOT_FOUND`.**
Key paths are resolved relative to the process working directory. Pass
absolute paths or run from the directory containing the keys. The library
does not print anything — feed the code to
[`proto_strerror`](#error-codes) and log it yourself. (Before v1.2 this was
reported as `PROTO_E_KEY_OPEN`, along with every other reason a file could
not be opened.)

**`proto_load_keys` returns `PROTO_E_KEY_DENIED`.**
The file is there but this process may not read it. The usual cause is a
service running as a different user from the one who created the keys —
the keys are created `0600`, readable by their owner only. Give the files to
the user the service runs as rather than opening up their mode.

**Can two clients share one identity?**
Yes — copy both key files. They'll authenticate as the same user and decrypt
the same data. There is no session exclusivity.

**Is the connection encrypted?**
Payloads are; the command lines (verbs, ids, timestamps) are not, and the
server is not authenticated to the client. Nobody without `enc.key` can
read an entry, but someone who can intercept the connection can relay the
handshake and act as the user for that session — delete, overwrite, put
old entries back — without `auth.key`. A tunnel (SSH, WireGuard) closes
that and hides the metadata; it is recommended on any network you do not
trust. See the [trust model](architecture.md#trust-model).

**Why does `proto_unseal_new` need both `enc_pk` and `enc_sk`?**
libsodium's `crypto_box_seal_open` requires the recipient's public *and*
secret key (the public key is part of the sealed-box construction).
`proto_load_keys` always gives you both.
