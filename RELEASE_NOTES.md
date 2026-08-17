# Release notes

## v1.1 — Keepalive on connections [Unreleased]

`wire` grows from four functions to five: `proto_keepalive` turns on TCP keepalive probing for a connection and sets its timing. Nothing in the library enables it on its own — both ends opt in by calling it.

A peer that vanishes without closing — a suspended laptop, a phone off the network — sends nothing, so the other side blocks in `read()` indefinitely. On a forking server that leaves a child alive forever, holding a socket and whatever per-connection state the application keeps. Keepalive makes the kernel probe an idle connection and fail the socket when the peer stops answering, which ends the read and lets the existing teardown path run.

- **`proto_keepalive(fd, idle_s, intvl_s, count)`** — enable probing and set its timing on an existing connection. Any argument `<= 0` leaves that knob at the system default. Returns 0, or -1 if the socket rejected an option.

Design:

- **Nothing is on by default.** `proto_connect` and `proto_serve` set no keepalive; a connection behaves exactly as in v1.0 until an application asks otherwise. One rule for both ends, and no policy imposed on a consumer that did not want it. Clients call it on `conn.fd` after connecting, servers on the handler's fd.
- **Known limitation: the handshake window.** `proto_serve` accepts, forks and authenticates before the application sees the fd, so a peer that vanishes mid-handshake still leaves that child blocked in `read()`. Applications that need that window covered run their own accept loop around `proto_auth_server` and enable probing on the socket themselves.
- **The platform difference lives in the library.** The first knob is spelled `TCP_KEEPIDLE` on Linux and `TCP_KEEPALIVE` on macOS; `proto_keepalive` absorbs that `#ifdef` so consumers do not repeat it. The other two (`TCP_KEEPINTVL`, `TCP_KEEPCNT`) are spelled the same everywhere.
- **Not a read timeout.** It does not touch read semantics: no `SO_RCVTIMEO`, no `errno` inspection, no partial-line hazard. Detection takes about two hours at system defaults — a backstop against blocking forever, not a way to give up promptly.
- **The kernel handles both sides.** Probes are answered by the peer's TCP stack, so no application, on either end, needs to know or be updated. Nothing is added to the wire protocol: a v1.0 peer interoperates unchanged.
- **Three dependency-free includes** (`<sys/socket.h>`, `<netinet/in.h>`, `<netinet/tcp.h>`) in `wire.c`.

Documentation: `docs.md` gains a reference entry for the new function; `architecture.md` records the socket-housekeeping split between `serve` and `wire`.

## v1.0 — Extraction (e33b181) [2026-07-03]

First release of `proto` as a standalone library, extracted from the diary project for reuse: everything identical across projects that share its architecture (authenticated clients, server as encrypted blob store, text-line protocol), and nothing that varies (verbs, storage, policy).

- **Four modules, 17 entry points, strictly layered** (dependencies point downward only): `wire` — line framing (`proto_send_line`, `proto_recv_line`, `proto_recv_line_dyn`, `proto_send_prefixed`); `crypto` — keys and libsodium wrappers (`proto_init`, `proto_load_keys`, `proto_load_pubkey_hex`, `proto_seal`, `proto_seal_new`, `proto_unseal_new`, `proto_sign_challenge`, `proto_verify_challenge`); `auth` — sessions and handshake (`proto_connect`, `proto_close`, `proto_auth_client`, `proto_auth_server`); `serve` — fork-per-connection harness (`proto_serve`).
- **The contract** (`protocol.h`): one message = one `\n`-terminated line; binary travels base64 inside lines; `HELLO → CHALLENGE → AUTH [→ REGISTER]` handshake; `QUIT`/`BYE` teardown; application commands layered on top by each project.
- **Trust model**: Ed25519 challenge-response identity (the public key is the username), X25519 sealed-box payloads the server stores but cannot read. No TLS by design — payload confidentiality comes from the sealed boxes; tunnel if metadata privacy matters.
- **`keygen/`** — bundled, de-branded key provisioning tool writing `auth.key`, `auth.pub`, `enc.key`; lives in the library because the key-file format is part of its contract. X25519 keys generated via `crypto_box_keypair`.
- **Documentation set**: `README.md` (intro), `architecture.md` (design rationale), `docs.md` (complete API reference with worked examples).
