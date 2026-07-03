# Architecture

How the library is structured, why it looks this way, and where your
application plugs in.

## The problem it solves

Every project built on this library shares one architecture:

- A client proves its identity with an Ed25519 keypair (`auth.key`).
- The client sends and receives data that the server **stores but can never
  read** (X25519 sealed boxes).
- Commands travel as human-readable text lines; binary data rides inside the
  lines as base64.

The library implements everything that is identical across such projects —
framing, crypto, authentication, and the server accept loop — and nothing
that varies (command verbs, storage, registration policy).

## Layered modules

```
            ┌──────────────────────────────┐
  server    │  serve    proto_serve()      │   accept/fork harness (server only)
            └───────────────┬──────────────┘
                            │ calls proto_auth_server()
            ┌───────────────▼──────────────┐
  both      │  auth     proto_connect()    │   handshake, client session
            │           proto_auth_*()     │
            └───────┬──────────────┬───────┘
                    │              │
            ┌───────▼──────┐ ┌─────▼────────┐
  both      │  wire        │ │  crypto      │   framing / keys, seal, sign
            └──────────────┘ └─────┬────────┘
                                   │
                             ┌─────▼────────┐
            constants        │  protocol.h  │
                             └──────────────┘
```

Dependencies point strictly downward — no cycles. `auth` never knows `serve`
exists, so you can replace the harness without touching the handshake.

**Who links what:**

| Side | Sources to compile |
|---|---|
| Client | `wire.c crypto.c auth.c` |
| Server | `wire.c crypto.c auth.c serve.c` |

## What each file contains

Nine files, four modules plus one constants header. Full signatures and
per-function semantics are in [docs.md](docs.md); this is the map of what
lives where and why.

### `protocol.h` — the contract

No code — only the shared constants and, in a comment, the wire-format
specification of the handshake. It defines:

- `CHALLENGE_LEN` (32) and `MAX_LINE` (16384, a guideline for *control*
  lines, not a payload limit);
- the libsodium key-size aliases (`AUTH_PK_LEN`, `AUTH_SK_LEN`,
  `AUTH_SIG_LEN`, `ENC_PK_LEN`, `ENC_SK_LEN`).

Everything else includes it, directly or transitively. Deliberately contains
**no application constants** — ports, size limits, and command sets belong to
each consuming app.

### `wire.h` / `wire.c` — framing

The lowest layer: how bytes become messages. Four functions, no crypto, no
protocol knowledge, dependencies on libc only:

| Function | Role |
|---|---|
| `proto_send_line` | write `line + '\n'` |
| `proto_recv_line` | read one line into a fixed buffer (short control lines) |
| `proto_recv_line_dyn` | read one line of unbounded size onto the heap (payload lines) |
| `proto_send_prefixed` | write `<prefix><body>\n` without assembling a buffer (large payloads) |

If the framing ever changed (e.g. a binary variant), this is the only module
that would be replaced.

### `crypto.h` / `crypto.c` — keys and cryptography

Pure computation plus key-file reading; no sockets. Wraps libsodium so
applications never call it directly. Contains:

- **`proto_keys_t`** — the two keypairs of one identity (Ed25519 auth +
  X25519 encryption).
- **Lifecycle**: `proto_init` (libsodium init), `proto_load_keys` (read both
  secret-key files, derive publics), `proto_load_pubkey_hex` (read
  `auth.pub` into the hex allowlist string servers use).
- **Payload encryption**: `proto_seal` / `proto_seal_new` (sealed box →
  base64, fixed vs heap buffer) and `proto_unseal_new` (base64 → open box →
  heap plaintext with true length).
- **Handshake primitives**: `proto_sign_challenge` / `proto_verify_challenge`
  (detached Ed25519 sign/verify — the client and server halves of the same
  operation).

### `auth.h` / `auth.c` — sessions and handshake

The protocol conversation itself, built on `wire` + `crypto`. Both sides
live here so the handshake logic can never drift apart:

- **`proto_conn_t`** — an authenticated client session (fd + keys +
  identity hex).
- **Client turnkey**: `proto_connect` (resolve, TCP-connect, handshake,
  auto-answer `REGISTER` on first contact) and `proto_close` (`QUIT`, close).
- **Client primitive**: `proto_auth_client` — just the
  `HELLO → CHALLENGE → AUTH` exchange on an existing fd, for custom
  transports.
- **Server primitive**: `proto_auth_server` — generate the challenge, verify
  the signature, compare against the allowlist; returns the authenticated
  identity or sends `FAIL …` and returns NULL.

Note the asymmetry: the client side has a turnkey call, the server side only
the primitive — because the server's turnkey wrapper is the next module.

### `serve.h` / `serve.c` — server harness

The only server-only file, and the only one that knows about `fork`. One
function and one type:

- **`proto_handler_fn`** — the contract for an application's per-connection
  handler (authenticated fd + identity + opaque ctx, running in a child
  process).
- **`proto_serve`** — bind/listen, `SIGPIPE`/`SIGCHLD` handling, then
  accept → fork → `proto_auth_server` → handler, forever.

It contains no application logic and no storage; it exists purely so that
every server's `main` collapses to "load allowlist, call `proto_serve`".
Applications with different process models skip this file entirely and use
`proto_auth_server` in their own loop.

## The two keypairs

Each identity consists of two keypairs with different jobs:

| Keypair | Algorithm | Files | Job |
|---|---|---|---|
| Authentication | Ed25519 (signing) | `auth.key` (secret, 64 B), `auth.pub` (public, 32 B) | Prove *who you are*. The hex of the public key **is** your identity/username. |
| Encryption | X25519 (box) | `enc.key` (secret, 32 B; public key derived) | Protect *what you store*. Payloads are sealed to this public key; only the secret key opens them. |

Why two? Signing keys can't encrypt and encryption keys can't sign, and
keeping them separate means the server can hold your **encryption public
key** (needed so anyone — including you on another device — can write blobs
addressed to you) without that key having any authority to authenticate.

## Handshake sequence

All lines end in `\n`; binary values are base64.

```
Client                                Server
──────                                ──────
HELLO                        ──────►
                             ◄──────  CHALLENGE <32 random bytes, b64>
(sign challenge w/ auth.key)
AUTH <auth_pk b64> <sig b64> ──────►
                                      (verify sig; compare pk against auth.pub)
             known user:     ◄──────  OK
             new user:       ◄──────  REGISTER
REGISTER <enc_pk b64>        ──────►          (first connection only)
                             ◄──────  OK

...application commands (yours)...

QUIT                         ──────►
                             ◄──────  BYE
```

Properties:

- **Replay-proof:** the client signs a fresh server-chosen nonce, so a captured
  `AUTH` line is useless for a later connection.
- **Allowlist:** the server accepts exactly one identity — the key in
  `auth.pub`. Everyone else gets `FAIL access denied`.
- **Auto-registration:** on first connect the server learns (and persists) the
  client's encryption public key. The client side of this is built into
  `proto_connect()`; the server side (persisting the key) is application code,
  because storage is application-specific.

## Trust model

The server is an *authenticated dumb blob store*:

- It verifies who is talking, then stores/returns ciphertext it cannot open.
- Entry contents are encrypted with `crypto_box_seal` to the client's X25519
  public key. Decryption requires `enc.key`, which **never leaves the client**.
- A passive eavesdropper sees: command verbs, ids, timestamps, public keys,
  and base64 ciphertext. They do not see payload contents.
- There is deliberately **no TLS**: confidentiality of the payload comes from
  the sealed boxes, not the channel. What TLS would add is hiding the
  *metadata* (verbs, ids, timing) and authenticating the *server*; if either
  matters for a given deployment, tunnel the connection (SSH/WireGuard/stunnel).
- Compromise of the server loses **availability and metadata, not contents**.
- Compromise of `auth.key` lets an attacker connect and delete/overwrite;
  compromise of `enc.key` lets them decrypt blobs they obtain. Guard both.

## Framing rules

- One message = one `\n`-terminated line. `\r` is ignored on read.
- Binary data travels base64-encoded (`sodium_base64_VARIANT_ORIGINAL`) inside
  a line — base64 never contains `\n`, so framing is preserved.
- Two read paths:
  - `proto_recv_line()` — fixed caller buffer; for short control lines
    (`OK`, `FAIL …`, headers).
  - `proto_recv_line_dyn()` — heap-growing; for payload lines of unbounded
    size. **Use this whenever a line might carry a sealed blob.**
- The payload API is length-based (`msg`, `msg_len`), never `strlen`-based, so
  payloads may contain NUL bytes — images and audio work unmodified. There is
  no size ceiling in the library; size limits are application policy.

## Base64 on the wire

The protocol is text lines, but half of what it carries is raw binary:
random challenges, public keys, signatures, and — above all — encrypted
payloads. Base64 is the bridge: every binary value is base64-encoded so it
can travel *inside* a text line without breaking the framing.

### Why base64 at all

The framing rule is "one message = one `\n`-terminated line". Raw binary
data can contain the byte `0x0A` (`\n`) anywhere, so sending it verbatim
would end the line in the middle of the payload and desynchronize the
connection. Base64's output alphabet — `A–Z a–z 0–9 + / =` — contains no
newline, no carriage return, no NUL, and no space, so *any* byte sequence
becomes one safe, splittable field on one line.

This buys three properties:

1. **Framing safety** — a sealed 1 MB image is still exactly one line.
2. **Field safety** — base64 output has no spaces, so commands can keep the
   simple `VERB <arg> <payload>` shape and be parsed with `strtok`/`strchr`.
3. **Debuggability** — the whole protocol is printable ASCII. You can watch
   or hand-drive a session with `nc`/`telnet` and read every message.

### What is encoded and what is not

| On the wire | Form |
|---|---|
| Verbs and replies (`HELLO`, `PUT`, `OK`, `FAIL …`) | plain text |
| ids, counts, timestamps | plain decimal text |
| Challenge (32 random bytes) | base64 (44 chars) |
| Ed25519 public key / signature | base64 (44 / 88 chars) |
| X25519 public key (`REGISTER`) | base64 (44 chars) |
| Sealed payloads | base64 (grows with content) |

The same encoding is used on disk: `auth.key`, `auth.pub`, and `enc.key` are
each a single line of base64.

### Encoding variant

Everything uses libsodium's `sodium_base64_VARIANT_ORIGINAL`: the standard
RFC 4648 alphabet (`+` and `/`, with `=` padding). Key files, handshake
fields, and payloads all match, so one decoder handles everything. Keep this
in mind when writing a client in another language — use *standard* base64,
not the URL-safe variant.

### Order matters: encrypt first, then encode

For payloads, base64 is applied to the **ciphertext**, never to the
plaintext. The journey of an image:

```
photo.jpg (raw bytes, may contain \n, NUL, anything)
    │
    ▼  crypto_box_seal            (proto_seal_new does both steps)
ciphertext (+48 bytes overhead — random-looking, still unsendable binary)
    │
    ▼  base64 encode
one printable line  ──►  PUT R29vZCBtb3JuaW5nIQf3k2...Zz09\n
```

If the order were reversed (encode, then encrypt), the result would still be
binary ciphertext and unsendable. And base64 alone is **not** protection —
it is a transport encoding, trivially reversible by anyone. Confidentiality
comes entirely from the sealed box; base64 only makes the sealed box
line-safe. What an eavesdropper sees is base64 of ciphertext, which decodes
to noise.

On the receiving side the steps unwind: split the line into fields → base64
decode the payload field → `crypto_box_seal_open` with the secret key →
original bytes, exact to the byte (`proto_unseal_new` does all three and
returns the true length, since binary payloads can't be measured with
`strlen`).

### The cost: ~37% size overhead

Base64 encodes 3 bytes as 4 characters, so payloads grow by one third; the
sealed box adds a fixed 48 bytes before that. A payload of `L` plaintext
bytes therefore travels as roughly:

```
wire_chars = ceil((L + 48) / 3) * 4          ≈ 1.37 × L
```

| Plaintext | On the wire |
|---|---|
| 100 B note | ~200 chars |
| 64 KB entry | ~88 KB |
| 1 MB photo | ~1.37 MB |
| 10 MB audio | ~13.7 MB |

### Why not a binary framing layer?

The obvious alternative to text-plus-base64 is length-prefixed binary
framing, where each message is raw bytes preceded by its size:

```
[ 4 bytes: payload length N ][ 1 byte: message type ][ N bytes: raw payload ]
```

The receiver reads the header, learns `N`, then reads exactly `N` bytes. No
delimiter is needed, so binary (including `\n`) travels unencoded. Its real
advantages: no 33% inflation (a 1 MB image travels as ~1 MB), no
encode/decode CPU passes or duplicate base64 copy in memory, and payloads
can be streamed to disk as they arrive instead of accumulated as one line.

Text framing was chosen anyway, for five reasons:

1. **Debuggability.** The whole protocol is printable ASCII: you can drive a
   session by hand with `nc`, watch traffic in `tcpdump -A`, and a bug
   report is a greppable string like `FAIL invalid signature`. A binary
   protocol needs a custom dissector or hexdump archaeology every time.

2. **Implementation simplicity — which is correctness.** The entire framing
   layer (`wire.c`) is ~60 lines: read until `\n`. Length-prefixed framing
   needs endianness conventions, a message-type registry, partial reads of
   the header itself, sanity caps on the declared length (a malicious 4 GB
   length field is a classic DoS), and versioning of the frame format. Each
   is a place to write a bug; for a security-sensitive library, less parsing
   surface is a feature.

3. **Self-recovery.** Text lines are self-delimiting: after a malformed
   message the receiver can still find the next `\n` and resynchronize. In a
   length-prefixed protocol, one corrupted length field means the position
   of every subsequent message is unknown — the connection is unrecoverable.

4. **The overhead doesn't matter at this scale.** The trade is ~37% on
   payloads. For personal-scale applications syncing entries and occasional
   media, 1.37 MB instead of 1 MB is imperceptible. Binary framing starts to
   win only for bulk data at volume (video, backups, many users on metered
   links).

5. **Half the protocol wants text anyway.** Verbs, ids, and counts are
   naturally text, and the handshake's binary fields are tiny. A binary
   layer would either make those unreadable too, or force a hybrid
   (text commands + binary payloads) with two framing modes to keep in
   sync — more complex than either pure approach.

There is precedent at far larger scale: SMTP, IMAP, HTTP/1, Redis, and Git's
smart protocol are all line-oriented text carrying encoded binary, and ran
for decades. HTTP/2 went binary only when multiplexing at massive scale
justified the tooling cost.

In short: base64-over-lines trades ~37% payload bandwidth and some CPU for a
tiny auditable implementation, human-readable debugging, and self-delimiting
robustness. If a future project genuinely needs to move gigabytes, the
layered design leaves room to add a binary framing module alongside `wire`
without touching `crypto`, `auth`, or `serve` — but don't build it before a
project demands it.

## What the library owns vs what your app owns

| Concern | Library | Your app |
|---|---|---|
| TCP connect / accept / fork / reaping | ✔ (`proto_connect`, `proto_serve`) | — |
| Challenge–response authentication | ✔ | — |
| First-connect registration (client side) | ✔ (inside `proto_connect`) | — |
| First-connect registration (server side) | — | persist the enc pubkey your way |
| Line framing | ✔ | — |
| Payload encryption/decryption | ✔ (`proto_seal_new` / `proto_unseal_new`) | call them |
| Command verbs and reply formats | — | yours entirely |
| Storage | — | yours entirely |
| Size limits / quotas | — | yours (policy) |
| Port number | — | yours (pass to `proto_connect` / `proto_serve`) |

## Extension points

**Adding verbs (the normal case).** Define commands as prefixed lines and
dispatch on them in your handler — see the diary's `POST`/`GET`/`UPDATE`/
`DELETE` or the worked examples in [docs.md](docs.md). Conventions used so
far: requests are `VERB [args] [payload_b64]`, replies are `OK[ data]` or
`FAIL <reason>`, lists are a `HEADER <count>` line followed by `<count>` rows.

**Bypassing the harness.** `proto_serve()` bakes in fork-per-connection and a
single allowed key. If you need threads, an event loop, multiple authorized
keys, or pre-auth logging, write your own accept loop and call
`proto_auth_server(fd, allowed_hex)` directly — it is a public primitive and
all the harness uses itself. The same applies client-side:
`proto_auth_client(fd, keys)` runs the handshake on any connected fd if you
need a custom transport.

**Fork model caveat.** With `proto_serve()`, each connection is handled in a
forked child process: per-connection state is naturally isolated, but
in-memory state is **not shared** between clients — share through your
database/files instead.
