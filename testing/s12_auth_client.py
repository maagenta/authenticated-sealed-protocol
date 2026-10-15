"""XIV. proto_auth_client (T-212 to T-230), against a scripted server."""

import os
import signal
import socket
import time

import harness
import keyfiles
import lib
import libsodium as ls
import net
import peers
from harness import FINDING, PIN, case, check, eq, in_child, slack_ms
from keyfiles import make_identity
from net import Peer

REJECTED, UNEXPECTED, BAD_CHALLENGE = -703, -701, -702
TIMEOUT, PEER_CLOSED, TOO_LONG, WRITE = -605, -603, -604, -601


def b64(raw):
    return ls.b64(raw).encode()


def offer(peer, challenge=None):
    """Send the CHALLENGE line; returns the 32 bytes."""
    challenge = os.urandom(32) if challenge is None else challenge
    peer.send_line(b"CHALLENGE " + b64(challenge))
    return challenge


def keys_of(P):
    ident = make_identity()
    rc, keys = P.load_keys(ident.auth_key, ident.enc_key)
    eq(rc, 0, "proto_load_keys")
    return keys


def run(server_fn, P=None, keys=None):
    """proto_auth_client against server_fn(Peer) in a thread.

    Returns (rc, what the server function returned, milliseconds, keys)."""
    P = P or lib.proto()
    keys = keys or keys_of(P)
    a, b = net.sockpair()
    worker = net.Worker(server_fn, Peer(b))
    t0 = net.now()
    rc = P.auth_client(a.fileno(), keys)
    took = net.ms_since(t0)
    a.close()                                     # the server function sees end of stream
    return rc, worker.finish(), took, keys


def verdict_server(reply):
    """A server that completes the handshake and answers reply after AUTH."""
    def server(peer):
        peer.recv_line()
        offer(peer)
        peer.recv_line()
        peer.send_line(reply)
    return server


@case("T-212")
def t212():
    """The client speaks first, with exactly HELLO\\n."""
    def server(peer):
        first = peer.recv_exact(6)
        quiet = peer.silent_for(0.15)
        offer(peer)
        peer.recv_line()
        peer.send_line(b"OK")
        return first, quiet
    rc, (first, quiet), _, _ = run(server)
    eq(rc, 0, "proto_auth_client")
    eq(first, b"HELLO\n", "the first bytes")
    check(quiet, "the client sent something besides HELLO before the challenge")


@case("T-213")
def t213():
    """The AUTH line has the documented shape."""
    def server(peer):
        peer.recv_line()
        challenge = offer(peer)
        auth = peer.recv_line()
        peer.send_line(b"OK")
        return challenge, auth
    rc, (challenge, auth), _, keys = run(server)
    eq(rc, 0, "proto_auth_client")
    eq(len(auth), 138, "length of the AUTH line")
    eq(auth[:5], b"AUTH ", "the verb")
    eq(auth[49:50], b" ", "the space between the fields")
    pk_b64, sig_b64 = auth[5:49], auth[50:]
    eq(len(sig_b64), 88, "length of the signature field")
    eq(ls.b64d(pk_b64), bytes(keys.auth_pk), "the public key field")
    sig = ls.b64d(sig_b64)
    check(ls.verify_detached(sig, challenge, bytes(keys.auth_pk)), "the signature does not verify over the 32 challenge bytes")
    check(not ls.verify_detached(sig, b64(challenge), bytes(keys.auth_pk)), "the signature verifies over the base64 text")


@case("T-214")
def t214():
    """OK is PROTO_OK."""
    for reply in (b"OK", b"OK\r"):
        eq(run(verdict_server(reply))[0], 0, "reply %r" % reply)


@case("T-215")
def t215():
    """REGISTER is PROTO_REGISTER_REQUESTED."""
    for reply in (b"REGISTER", b"REGISTER\r"):
        eq(run(verdict_server(reply))[0], 1, "reply %r" % reply)


@case("T-216")
def t216():
    """Anything else after AUTH is PROTO_E_REJECTED."""
    for reply in (b"FAIL access denied", b"OK ", b"BYE", b""):
        eq(run(verdict_server(reply))[0], REJECTED, "reply %r" % reply)


def reply_in_place_of_challenge(reply):
    def server(peer):
        peer.recv_line()
        peer.send_line(reply)
        return peer.recv_line()                     # None: the client sends nothing more
    return server


@case("T-217")
def t217():
    """A FAIL in place of the challenge is PROTO_E_REJECTED."""
    for reply in (b"FAIL server busy", b"FAIL internal error", b"FAIL "):
        eq(run(reply_in_place_of_challenge(reply))[0], REJECTED, "reply %r" % reply)


@case("T-218", PIN)
def t218():
    """A bare FAIL in place of the challenge is PROTO_E_UNEXPECTED_REPLY."""
    eq(run(reply_in_place_of_challenge(b"FAIL"))[0], UNEXPECTED, "a bare FAIL before the challenge")
    eq(run(verdict_server(b"FAIL"))[0], REJECTED, "the same line after AUTH")


@case("T-219")
def t219():
    """A reply that is neither CHALLENGE nor FAIL is PROTO_E_UNEXPECTED_REPLY."""
    for reply in (b"CHALLENGE", b"challenge x", b"", b"HI"):
        eq(run(reply_in_place_of_challenge(reply))[0], UNEXPECTED, "reply %r" % reply)


@case("T-220")
def t220():
    """A malformed challenge is PROTO_E_BAD_CHALLENGE."""
    ch = os.urandom(32)
    plus_slash = None
    while plus_slash is None:                        # a challenge whose base64 has + or /
        c = os.urandom(32)
        if b"+" in b64(c) or b"/" in b64(c):
            plus_slash = c
    cases = {
        "two spaces": b"CHALLENGE  " + b64(ch),
        "not base64": b"CHALLENGE !!!notbase64!!!",
        "31 bytes": b"CHALLENGE " + b64(os.urandom(31)),
        "33 bytes": b"CHALLENGE " + b64(os.urandom(33)),
        "a trailing space": b"CHALLENGE " + b64(ch) + b" ",
        "missing padding": b"CHALLENGE " + b64(ch).rstrip(b"="),
        "URL-safe characters": b"CHALLENGE " + b64(plus_slash).replace(b"+", b"-").replace(b"/", b"_"),
        "one byte": b"CHALLENGE AA==",
    }
    for what, line in cases.items():
        rc, signed, _, _ = run(reply_in_place_of_challenge(line))
        eq(rc, BAD_CHALLENGE, what)
        check(signed is None, "%s: the client signed it all the same" % what)


@case("T-221", PIN)
def t221():
    """The client signs any well-formed 32 bytes."""
    def server(peer):
        peer.recv_line()
        challenge = offer(peer, b"\0" * 32)
        auth = peer.recv_line()
        peer.send_line(b"OK")
        return challenge, auth
    rc, (challenge, auth), _, keys = run(server)
    eq(rc, 0, "an all-zero challenge")
    sig = ls.b64d(auth[50:])
    check(ls.verify_detached(sig, challenge, bytes(keys.auth_pk)), "the signature over zeros does not verify")


def silent_after(stage):
    def server(peer):
        peer.recv_line()
        if stage >= 1:
            offer(peer)
            peer.recv_line()
        return peer.recv_line()                      # None once the client has given up
    return server


@case("T-222")
def t222():
    """Silence after HELLO is PROTO_E_TIMEOUT."""
    P = lib.proto()
    rc, _, took, _ = run(silent_after(0), P)
    eq(rc, TIMEOUT, "silence after HELLO")
    ms = P.macros["HANDSHAKE_TIMEOUT_MS"]
    check(net.in_window(took, ms), "the deadline took %.0f ms, not %d" % (took, ms))


@case("T-223")
def t223():
    """Silence after AUTH is PROTO_E_TIMEOUT."""
    P = lib.proto()
    rc, _, took, _ = run(silent_after(1), P)
    eq(rc, TIMEOUT, "silence after AUTH")
    check(net.in_window(took, P.macros["HANDSHAKE_TIMEOUT_MS"]), "the deadline took %.0f ms" % took)


@case("T-224")
def t224():
    """A server that closes mid-handshake is PROTO_E_PEER_CLOSED."""
    def after_hello(peer):
        peer.recv_line()
        peer.close()

    def after_auth(peer):
        peer.recv_line()
        offer(peer)
        peer.recv_line()
        peer.close()
    eq(run(after_hello)[0], PEER_CLOSED, "a close after HELLO")
    eq(run(after_auth)[0], PEER_CLOSED, "a close after AUTH")


@case("T-225")
def t225():
    """A challenge line of 16384 characters or more is PROTO_E_LINE_TOO_LONG."""
    def long_line(n):
        def server(peer):
            peer.recv_line()
            peer.send(b"CHALLENGE " + b"A" * (n - 10) + b"\n")
            peer.recv_line()
        return server
    eq(run(long_line(16384))[0], TOO_LONG, "a line of 16384 characters")
    check(run(long_line(16383))[0] != TOO_LONG, "a line of 16383 characters is too long")


@case("T-226", FINDING)
def t226():
    """The reason for a refusal can be read."""
    P = lib.proto()
    keys = keys_of(P)
    a, b = net.sockpair()
    peer = Peer(b)

    def server():
        peer.recv_line()
        offer(peer)
        peer.recv_line()
        peer.send_line(b"FAIL access denied")
    w = net.Worker(server)
    rc = P.auth_client(a.fileno(), keys)
    w.finish()
    eq(rc, REJECTED, "proto_auth_client")
    rc2, reason = P.recv_line_timeout(a.fileno(), 300)
    eq((rc2, reason), (18, b"FAIL access denied"), "the reason, read off the wire after the refusal")


@case("T-227")
def t227():
    """A server that trickles bytes cannot hold the client past the deadline."""
    P = lib.proto()

    def server(peer):
        peer.recv_line()
        line = b"CHALLENGE " + b64(os.urandom(32)) + b"\n"
        try:
            for i in range(len(line)):
                peer.send(line[i:i + 1])
                time.sleep(0.05)
        except OSError:
            pass
    rc, _, took, _ = run(server, P)
    eq(rc, TIMEOUT, "a challenge one byte every 50 ms")
    check(net.in_window(took, P.macros["HANDSHAKE_TIMEOUT_MS"]), "the deadline took %.0f ms" % took)


@case("T-228", PIN)
def t228():
    """A FAIL sent before HELLO is read gives one code or the other."""
    P = lib.proto()
    keys = keys_of(P)
    seen = {}
    for _ in range(20):
        ls_ = net.listener()
        port = ls_.getsockname()[1]

        def server():
            conn, _ = ls_.accept()
            conn.sendall(b"FAIL internal error\n")
            conn.close()
        w = net.Worker(server)
        c = socket.create_connection(("127.0.0.1", port))
        rc = P.auth_client(c.fileno(), keys)
        w.finish()
        c.close()
        ls_.close()
        seen[rc] = seen.get(rc, 0) + 1
    harness.note("outcomes in 20 runs: %r" % seen)
    check(set(seen) <= {REJECTED, WRITE}, "unexpected codes: %r" % seen)


@case("T-229", PIN)
def t229():
    """keys == NULL crashes after HELLO has gone out."""
    P = lib.proto()

    def child():
        a, b = net.sockpair()
        net.Worker(lambda: (lambda p: (p.recv_line(), offer(p), p.recv_line()))(Peer(b)))
        P.c_auth_client(a.fileno(), None)
    how, code = in_child(child)
    check(how == "signal" and code in (signal.SIGSEGV, signal.SIGBUS),
          "a NULL keys pointer no longer crashes (%s %s): decide with T-051" % (how, code))


def secret_forms(secret):
    """A secret as it could appear in a stream: raw, two base64 spellings, two hex cases."""
    import base64
    return {
        "raw": secret,
        "base64": base64.b64encode(secret),
        "urlsafe base64": base64.urlsafe_b64encode(secret),
        "hex": secret.hex().encode(),
        "HEX": secret.hex().upper().encode(),
    }


def session_bytes(P, keys, reply):
    """Everything the client sends in one proto_connect session; reply is REGISTER or OK."""
    ls_ = net.listener()
    port = ls_.getsockname()[1]
    captured = {}

    def server():
        conn, _ = ls_.accept()
        peer = Peer(conn)
        peers.server_handshake(peer, reply=reply)
        if reply == b"REGISTER":
            peer.recv_line()
            peer.send_line(b"OK")
        while True:
            line = peer.recv_line(10)
            if line is None:
                break
            if line == b"QUIT":
                peer.send_line(b"BYE")
        captured["rx"] = bytes(peer.rx)
    w = net.Worker(server)
    conn = lib.Conn.new(keys)
    rc = P.connect(conn, "127.0.0.1", port)
    eq(rc, 0, "proto_connect")
    P.close(conn)
    w.finish()
    ls_.close()
    return captured["rx"]


@case("T-230")
def t230():
    """No secret crosses the wire."""
    P = lib.proto()
    keys = keys_of(P)
    auth_sk, enc_sk, enc_pk, auth_pk = (bytes(keys.auth_sk), bytes(keys.enc_sk),
                                        bytes(keys.enc_pk), bytes(keys.auth_pk))
    registered = session_bytes(P, keys, b"REGISTER")
    plain = session_bytes(P, keys, b"OK")
    for stream, what in ((registered, "a session with registration"), (plain, "a session without")):
        for name, secret in (("auth_sk", auth_sk), ("its seed", auth_sk[:32]), ("enc_sk", enc_sk)):
            for form, needle in secret_forms(secret).items():
                check(needle not in stream, "%s: %s appears in the stream as %s" % (what, name, form))
        eq(stream.count(b64(auth_pk)), 1, "%s: occurrences of auth_pk" % what)
        check(b"AUTH " + b64(auth_pk) + b" " in stream, "%s: auth_pk is not in the AUTH line" % what)
    eq(registered.count(b64(enc_pk)), 1, "occurrences of enc_pk in a session with registration")
    check(b"REGISTER " + b64(enc_pk) + b"\n" in registered, "enc_pk is not in the REGISTER line")
    eq(plain.count(b64(enc_pk)), 0, "occurrences of enc_pk when no registration was asked for")
