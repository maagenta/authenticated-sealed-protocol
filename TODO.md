# TODO

Work this library has decided on and deliberately not done yet, with the
reason for the delay. Anything here has a design; what it lacks is the
right moment.

## Graceful shutdown of `proto_serve`, child side — with bidirectionality, v2.0

**What is missing.** Telling the children to wrap up, so that a stop lands
*between* messages and never inside one. The readers already guarantee half
of that — `proto_recv_line*` returns a line only once it has seen the
newline, and `write_all` resumes short writes — so no message is ever cut
unless a process is killed. The other half has three parts.

- **Reaching them.** A signal sent to the whole group (Ctrl-C, systemd's
  default `KillMode`) reaches the children through the handler they
  inherit; one sent to the parent alone (`kill`, `docker stop`) does not,
  and the parent keeps no pids. Rather than keep them — and make sure never
  to signal one the reaper has collected and the system has handed to
  another process — the parent holds the write end of a pipe whose read
  end every child inherits, and closes it on a stop: every child sees
  end-of-file at once, with no pids and no signals. The write end must be
  the parent's alone, closed in each child and close-on-exec.
- **Noticing.** The stop is one more source the child waits on, consulted
  at line boundaries only, where the reader returns a new
  `PROTO_E_STOPPING`. Mid-line, the read finishes the line and delivers it
  as usual; the stop is seen on the next call. A command already executing
  is never interrupted: the handler finishes it and sends its reply before
  it reads again.
- **Leaving.** The handler's loop ends on `PROTO_E_STOPPING` as it ends on
  any failed read, and the library, not the handler, says `BYE` once the
  handler returns — as it says `FAIL` during the handshake — so existing
  handlers need no change. It then closes without leaving client data
  unread: `shutdown` for writing, then read until end-of-file or
  `QUIT_TIMEOUT_MS`. A close with data unread makes the kernel reset the
  connection, and the reset can discard the `BYE`; it is the same reason
  the busy path reads `HELLO` before its `FAIL`.

**What `BYE` says.** Nothing beyond itself: the bare word that already
answers `QUIT`. In a lock-step protocol its position says it all: every
command the server executed was answered before the `BYE`, and a `BYE`
where a reply was expected means that command was not executed.

    C: PUT …    S: OK 42    executed and answered
                (stop)
    C: PUT …    S: BYE      not executed

A `BYE` that named the last thing done would repeat what the client already
has. Where the client really is left in doubt — a server killed, crashed or
cut off mid-command — there is no `BYE` at all; that case is closed by
idempotent commands, which are the application's. On the client,
`proto_recv_reply` recognizes an unprompted `BYE` as the library's word,
like its handshake lines, and reports it as a status — likely the same
`PROTO_E_STOPPING` — instead of handing it over as a reply. A v1.x client
sees an unexpected reply, then end-of-file.

**Why this half waits.** It depends on the shape of the child's read loop,
and bidirectionality changes that shape. A child that can be pushed
messages must wait on two sources at once — its client and whatever
produces the pushes — which means it will poll, as the `proto_wait` loop
documented on the `temp-docs-bidirectional` branch does. Once it polls, the
stop is one more source to wait on: the pipe needs no pids, and the poll
needs no signal to wake it. Telling an unprompted `BYE` from a reply is
likewise the problem bidirectionality solves for pushes. Building the
signal-and-flag machinery now would mean discarding it then.

**Set aside for v1.2.** Keeping pids, signalling each child, and having a
handler the library installs in the child call `shutdown(fd, SHUT_RD)`.
Measured on macOS: a read waiting for the next command returns end-of-file
at once, and the child can still write `BYE`, which the client receives;
a command sent but not yet read is discarded, so the client gets `BYE` in
its place, as the rule above says; a client that sends after the stop
still reads the `BYE`. On Linux the unread command would be read and
answered instead (reasoned, not measured). It works, but it doubles the
v1.2 change, takes `SIGTERM` from the application in every child, makes a
stop look like "client gone" to the handler, and v2.0's poll replaces it.
It is the fallback if v2.0 slips.

**Until then.** With v1.2, a stop frees the port and waits up to
`drain_ms` for the children, but cannot ask one to finish: a child still
serving when `drain_ms` runs out is left running. A child that receives the
signal itself ends at once — `proto_serve_stop()`, called from the
application's handler it inherited, exits — which is what the signal would
have done without that handler, so children behave as they did before v1.2.

## Authenticating the server and protecting the channel — v2.0

**What is missing.** The handshake proves the client to the server and
never the server to the client, and nothing after it is protected: the
client signs a challenge that says nothing about which server asked, or on
which connection. Someone who can steer the client's connection — a forged
DNS answer, a hostile Wi-Fi, a compromised router — relays it:

1. The client connects to the attacker, believing it is the server.
2. The attacker connects to the real server and receives a challenge.
3. It hands the challenge to the client, which signs it.
4. It hands the signature to the server, which answers `OK` — to it.

The attacker now holds a session as the user without ever having had
`auth.key`. It cannot read an entry, since `enc.key` never travels, but it
can do everything else: delete entries; answer the client's `PUT` with
`OK` and never forward it, so that the client believes lost data saved;
move, duplicate, or put old ciphertexts back in place of newer ones; and
fetch the whole stored history, where a passive eavesdropper sees only
what one session transfers. Reasoned from the handshake in `auth.c`, not
demonstrated.

**Signing more is not enough.** Having the server sign its challenge, or
binding the client's signature to the server's identity, does not stop it:
the attacker forwards both signatures untouched, both ends authenticate
each other through it, and the commands that follow travel unprotected,
open to injection. What stops it is a session key that the handshake
establishes and the attacker cannot compute even seeing every byte, with
every message after the handshake encrypted and authenticated under it.
The attacker can then cut the connection, and nothing more.

**The decision.**

| Option | New key | Cost |
|---|---|---|
| The tunnel is the design | none in the library; the tunnel's own (SSH host key, WireGuard keys) | documentation and deployment |
| A secure channel of the library's own | `server.key` / `server.pub` | a protocol redesign, and an outside review |
| TLS inside the library | a certificate | a dependency, and the end of "No TLS by design" |

- **The tunnel.** SSH, WireGuard or stunnel, required on any network that
  is not trusted. No code; the deployment carries the burden, and an
  application that skips the tunnel is exposed without knowing it.
- **A channel of the library's own.** A third key pair, the server's:
  `server.key` stays on the server, `server.pub` goes to every client —
  copied like `auth.pub` in reverse, or recorded at the first connection
  and checked ever after, as ssh's `known_hosts` does. Per connection, an
  ephemeral X25519 exchange (`crypto_kx`) with each side's ephemeral key
  bound to its long-term key; after it, every message sealed with
  `crypto_secretstream_xchacha20poly1305`, which also detects messages
  reordered, dropped or cut short. A known pattern, Noise `KK` or `XK`,
  rather than a design of our own. Messages can stay base64 lines, so that
  one message is still one line. `keygen` would create the server's pair,
  and loading it would join the key file codes.
- **TLS.** OpenSSL or mbedTLS, certificates and their renewal, and a
  dependency on top of libsodium.

Whichever is chosen breaks the wire with v1.x, so it waits for the version
that breaks it anyway, and the channel must carry bidirectionality's
pushes and the child's `BYE` (above) inside it. With the second option the
keys would be:

| Pair | Secret | Public | For | Today |
|---|---|---|---|---|
| Authentication (Ed25519) | `auth.key`, on the client | `auth.pub`, the server's allowlist | who the client is | yes |
| Encryption (X25519) | `enc.key`, on the client | sent to the server by `REGISTER` | the entries | yes |
| Server (Ed25519) | `server.key`, on the server | `server.pub`, on every client | who the server is | new |
| Session (X25519) | in memory, one per connection | — | every message of that connection | new, never a file |

**Until then.** The tunnel is required on any network that is not trusted.
The trust model in `architecture.md` is to say so in v1.2 (below).

## Signed entries — v2.0

**What is missing.** A sealed box is anonymous: anyone holding `enc_pk` can
make one that opens, and opening it says nothing about who made it. The
server holds `enc_pk` — `REGISTER` sends it there — so a compromised
server, or its operator, can add entries that decrypt as genuine, and so
can an attacker who saw a `REGISTER` go by. Nor is a box bound to the
place it is stored: moved to another entry, duplicated, or an old one put
back over a newer one, it still opens, and that needs no key at all.
"Compromise of the server loses availability and metadata, not contents"
holds for reading the contents, not for trusting them. No channel fixes
this: it is the server itself that can do it.

**The design.** The client signs every entry before sealing it, with the
`auth.key` it already has — no new key. The signature covers a context tag
of its own, so that an entry signature can never pass for a handshake
response or the other way round; a context the application supplies,
since entry ids and versions are its business, not the library's; and the
plaintext. On opening, the client checks the signature against its own
`auth_pk` and the context against where it found the entry: a forged entry
fails the signature, a moved or replayed one fails the context. In the
library, a pair such as `proto_seal_signed` / `proto_unseal_verified`,
taking that context as opaque bytes. The handshake signs its raw challenge
today, with no context; the protocol change of v2.0 is the moment to give
it one as well.

**Its limits.** Per-entry signatures cannot see the whole store rolled
back to an older but consistent state — every entry as it was a month
ago, each correctly signed. Catching that needs something the client keeps
itself, such as the last version it saw, or a signed manifest of the store.

**Why v2.0.** It changes what a stored entry holds, so every application
on the library changes, and entries stored before it carry no signature:
a format marker has to tell old from new, or a first v2.0 run re-signs
them. It is independent of the channel decision above, and it protects
against the one party a channel cannot: the server.

## Other pending work

- **Tests.** The structure and `test.h` are agreed; nothing is written.
  Every fix in v1.1 was verified by a one-off program, which is evidence
  but not a suite.
- **CI — v1.2.** No `.github/workflows/ci.yml`. The build has only ever been
  exercised on macOS with clang; the Linux paths (`TCP_KEEPIDLE`, the
  busy-loop `accept` case, the kernel's own connect timeout) are reasoned
  about, not measured.
- **`crypto.c` has never been read line by line — v1.2.** Its absence from
  the fixed list means nobody looked, not that it is clean.
- **The trust model understates an active attacker — v1.2.**
  `architecture.md` says only someone holding `auth.key` can delete or
  overwrite, and offers the tunnel as optional, for metadata. Against the
  relay above neither holds, and a compromised server can forge entries
  (signed entries, above). The trust model, and the FAQ entry "Is the
  connection encrypted?", should say what is protected — reading — and
  what is not — deleting, forging, rolling back — and that the tunnel is
  required on any network that is not trusted.
