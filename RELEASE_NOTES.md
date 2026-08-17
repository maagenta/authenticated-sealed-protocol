# Release notes

## v1.1 — Error codes, keepalive and fixes [Unreleased]

Three things: every `int`-returning function now returns a named reason instead of `-1`, connections can opt into TCP keepalive, and four defects carried over from v1.0 are fixed.

**Consuming projects must add `error.c` to their source list.** That is the only breaking change — existing C code compiles and behaves the same, because every error code is negative and the old `rc < 0` / `rc != 0` tests still hold.

### Error codes

New module `error` — the `proto_err_t` enum (31 values) and `proto_strerror()`, which turns any of them into a sentence.

- **`rc < 0` means failure, always.** Failures are negative; success is `0` or positive. `proto_recv_line` returns a line length, `proto_auth_client` returns `PROTO_REGISTER_REQUESTED` when the server wants our encryption key, and `proto_keepalive` returns `PROTO_KEEPALIVE_DEFAULTED` when probing works but a timing knob kept the system value. Adopting the codes costs a recompile, not an audit.
- **The library stopped printing.** `crypto.c` used to write "Error: could not open …" to `stderr`, deciding for every consumer where its diagnostics appeared — useless to a daemon with structured logging or to a GUI. The reason now travels in the return value and the application formats it.
- **A documented pitfall is gone.** `proto_connect` could not distinguish "network down" from "access denied"; `PROTO_E_RESOLVE`, `PROTO_E_CONNECT`, `PROTO_E_REJECTED` and `PROTO_E_REGISTER_REJECTED` now say which stage failed.
- **`bind` failures are classified.** `PROTO_E_PORT_IN_USE` and `PROTO_E_PERM_DENIED` come from reading `errno` before `close()` can clobber it — between them they cover almost every real startup failure.
- **EOF is distinguishable from an error.** `PROTO_E_PEER_CLOSED` for a clean close, `PROTO_E_READ` for a failed read.

Numbering is sequential with no structure encoded in the value; the name says which family a code belongs to. Values are stable from this release on. Every code has a message, and `proto_strerror` answers for unknown values too, so any return value can be passed straight through.

### Keepalive

`wire` grows from four functions to five: `proto_keepalive(fd, idle_s, intvl_s, count)` turns on TCP keepalive probing for a connection and sets its timing. Any argument `<= 0` leaves that knob at the system default.

A peer that vanishes without closing — a suspended laptop, a phone off the network — sends nothing, so the other side blocks in `read()` indefinitely. On a forking server that leaves a child alive forever, holding a socket and whatever per-connection state the application keeps. Keepalive makes the kernel probe an idle connection and fail the socket when the peer stops answering, which ends the read and lets the existing teardown path run.

- **Nothing is on by default.** `proto_connect` and `proto_serve` set no keepalive; a connection behaves exactly as in v1.0 until an application asks otherwise. One rule for both ends, and no policy imposed on a consumer that did not want it. Clients call it on `conn.fd` after connecting, servers on the handler's fd.
- **Known limitation: the handshake window.** `proto_serve` accepts, forks and authenticates before the application sees the fd, so a peer that vanishes mid-handshake still leaves that child blocked in `read()`. Applications that need that window covered run their own accept loop around `proto_auth_server` and enable probing on the socket themselves.
- **The platform difference lives in the library.** The first knob is spelled `TCP_KEEPIDLE` on Linux and `TCP_KEEPALIVE` on macOS; `proto_keepalive` absorbs that `#ifdef` so consumers do not repeat it. The other two (`TCP_KEEPINTVL`, `TCP_KEEPCNT`) are spelled the same everywhere.
- **Not a read timeout.** It does not touch read semantics: no `SO_RCVTIMEO`, no partial-line hazard. Detection takes about two hours at system defaults — a backstop against blocking forever, not a way to give up promptly.
- **The kernel handles both sides.** Probes are answered by the peer's TCP stack, so no application, on either end, needs to know or be updated. Nothing is added to the wire protocol: a v1.0 peer interoperates unchanged.

### Fixes

- **Out-of-bounds write in `proto_recv_line`.** `bufsz` is a `size_t`, so the loop bound `bufsz - 1` underflowed to `SIZE_MAX` when a caller passed `0`, and the function wrote incoming bytes into a buffer with no capacity. It now rejects `bufsz == 0` and bounds the loop with `i + 1 < bufsz`, which cannot underflow.
- **Segfault on an unusable allowlist.** `proto_auth_server` ran the whole handshake and then called `strcmp(hex, allowed_hex)` without checking it, so a server configured from an environment variable or a zeroed struct died of `SIGSEGV` in every forked child — silently, since the parent survived and the reaper collected the corpse. `proto_serve` now refuses to start on a `NULL` or wrong-length allowlist or a `NULL` handler, before the port is bound; `proto_auth_server` sends `FAIL internal error` and returns `NULL` before reading `HELLO`.
- **Two aborts became return values.** `sodium_bin2hex` and `sodium_bin2base64` kill the process when handed an undersized buffer, and `proto_load_pubkey_hex` and `proto_seal` passed caller-supplied sizes straight through. Both now check first and return `PROTO_E_BUFFER_TOO_SMALL`. `docs.md` claimed `proto_seal` returned `-1` in that case; it did not.
- **Silent line truncation.** `proto_recv_line` returned a length whether or not the line fit, so a truncation — which leaves the rest of the line in the socket and desynchronizes every read after it — looked exactly like success. It now returns `PROTO_E_LINE_TOO_LONG`, and NUL-terminates `buf` on every error path.

Documentation: `docs.md` gains an "Error codes" section and a reference entry for `proto_keepalive`, and every `Returns` line lists its codes; `architecture.md` documents the new module and why the library does not print.

## v1.0 — Extraction (e33b181) [2026-07-03]

First release of `proto` as a standalone library, extracted from the diary project for reuse: everything identical across projects that share its architecture (authenticated clients, server as encrypted blob store, text-line protocol), and nothing that varies (verbs, storage, policy).

- **Four modules, 17 entry points, strictly layered** (dependencies point downward only): `wire` — line framing (`proto_send_line`, `proto_recv_line`, `proto_recv_line_dyn`, `proto_send_prefixed`); `crypto` — keys and libsodium wrappers (`proto_init`, `proto_load_keys`, `proto_load_pubkey_hex`, `proto_seal`, `proto_seal_new`, `proto_unseal_new`, `proto_sign_challenge`, `proto_verify_challenge`); `auth` — sessions and handshake (`proto_connect`, `proto_close`, `proto_auth_client`, `proto_auth_server`); `serve` — fork-per-connection harness (`proto_serve`).
- **The contract** (`protocol.h`): one message = one `\n`-terminated line; binary travels base64 inside lines; `HELLO → CHALLENGE → AUTH [→ REGISTER]` handshake; `QUIT`/`BYE` teardown; application commands layered on top by each project.
- **Trust model**: Ed25519 challenge-response identity (the public key is the username), X25519 sealed-box payloads the server stores but cannot read. No TLS by design — payload confidentiality comes from the sealed boxes; tunnel if metadata privacy matters.
- **`keygen/`** — bundled, de-branded key provisioning tool writing `auth.key`, `auth.pub`, `enc.key`; lives in the library because the key-file format is part of its contract. X25519 keys generated via `crypto_box_keypair`.
- **Documentation set**: `README.md` (intro), `architecture.md` (design rationale), `docs.md` (complete API reference with worked examples).
