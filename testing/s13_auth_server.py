"""XV. proto_auth_server (T-231 to T-253), driven by a scripted client."""

import os
import socket
import time

import harness
import keyfiles
import lib
import libsodium as ls
import net
import runprobe
import servers
from harness import FINDING, PIN, case, check, eq, slack_ms
from keyfiles import make_identity
from net import Peer

FAIL_REASONS = {b"expected HELLO", b"expected AUTH", b"invalid AUTH format", b"invalid public key",
                b"invalid signature", b"signature verification failed", b"access denied",
                b"internal error", b"server busy"}


def b64(raw):
    return ls.b64(raw).encode()


def serve_one(client_fn, allowed, P=None):
    """proto_auth_server on one end of a socketpair, client_fn(Peer) on the other.

    Returns (identity or None, what client_fn returned, milliseconds)."""
    P = P or lib.proto()
    a, b = net.sockpair()
    worker = net.Worker(client_fn, Peer(a))
    t0 = net.now()
    got = P.auth_server(b.fileno(), allowed)
    took = net.ms_since(t0)
    b.close()                                       # what proto_serve's child does next
    return got, worker.finish(), took


def read_challenge(peer):
    line = peer.recv_line()
    check(line is not None and line.startswith(b"CHALLENGE "), "no challenge: %r" % (line,))
    check(len(line) == 54, "the challenge line has %d characters, not 54" % len(line))
    return ls.b64d(line[10:])


def auth_fields(ident, challenge):
    sig = ls.sign_detached(challenge, ident.auth_sk)
    return b64(ident.auth_pk), b64(sig)


def handshake(peer, ident, line_for=None):
    """HELLO, read the challenge, send an AUTH line; returns the server's next line."""
    peer.send_line(b"HELLO")
    ch = read_challenge(peer)
    pk, sig = auth_fields(ident, ch)
    peer.send_line(line_for(pk, sig) if line_for else b"AUTH " + pk + b" " + sig)
    return peer.recv_line()


def after_challenge(send):
    """A client that sends `send` (bytes) in place of AUTH; returns the reply."""
    def client(peer):
        peer.send_line(b"HELLO")
        read_challenge(peer)
        peer.send_line(send)
        return peer.recv_line()
    return client


@case("T-231")
def t231():
    """A valid handshake returns the identity, on the heap."""
    ident = make_identity()
    got, rest, _ = serve_one(lambda p: (handshake(p, ident), p.recv_all())[1], ident.hex)
    eq(got, ident.hex.encode(), "the identity")
    eq(rest, b"", "what the server wrote after the challenge")


@case("T-232")
def t232():
    """On success the server writes nothing after CHALLENGE."""
    ident = make_identity()
    got, next_line, _ = serve_one(lambda p: handshake(p, ident), ident.hex)
    eq(got, ident.hex.encode(), "the identity")
    eq(next_line, None, "a line the server wrote after the challenge")
    # The verdict belongs to the handler: one that never writes leaves
    # proto_connect waiting for it until the handshake deadline.
    P = lib.proto()
    with servers.Server(ident.hex, handler="silent") as srv:
        rc, conn, keys = servers.connect(P, ident, srv.port)
        eq(rc, -605, "proto_connect to a handler that never writes")


@case("T-233", timeout=120)
def t233():
    """Every session gets a fresh challenge."""
    ident = make_identity()
    seen = []
    with servers.Server(ident.hex, handler="ok") as srv:
        for _ in range(100):
            c = socket.create_connection(("127.0.0.1", srv.port))
            peer = Peer(c)
            peer.send_line(b"HELLO")
            line = peer.recv_line()
            check(line is not None and line.startswith(b"CHALLENGE ") and len(line) == 54,
                  "unexpected challenge line %r" % (line,))
            eq(len(ls.b64d(line[10:])), 32, "challenge length")
            seen.append(line)
            c.close()
    eq(len(set(seen)), 100, "distinct challenges in 100 sessions, each in a fresh fork")


@case("T-234")
def t234():
    """A captured AUTH line cannot be replayed."""
    ident = make_identity()
    captured = []

    def first(peer):
        peer.send_line(b"HELLO")
        ch = read_challenge(peer)
        pk, sig = auth_fields(ident, ch)
        captured.append(b"AUTH " + pk + b" " + sig)
        peer.send_line(captured[0])
        return peer.recv_all()
    got, _, _ = serve_one(first, ident.hex)
    eq(got, ident.hex.encode(), "the first session")
    got, reply, _ = serve_one(after_challenge(captured[0]), ident.hex)
    eq(got, None, "the replayed session")
    eq(reply, b"FAIL signature verification failed", "the reply to a replayed AUTH")


@case("T-235")
def t235():
    """A valid signature by a key that is not allowlisted is refused."""
    mine, stranger = make_identity(), make_identity()
    got, reply, _ = serve_one(lambda p: handshake(p, stranger), mine.hex)
    eq(got, None, "a stranger's handshake")
    eq(reply, b"FAIL access denied", "the reply")


@case("T-236")
def t236():
    """Anything but exactly HELLO is refused."""
    ident = make_identity()
    for line in (b"hello", b"HELLO ", b"HELLO x", b""):
        def client(peer, line=line):
            peer.send_line(line)
            return peer.recv_line()
        got, reply, _ = serve_one(client, ident.hex)
        eq((got, reply), (None, b"FAIL expected HELLO"), "the line %r" % line)


@case("T-237", PIN)
def t237():
    """HELLO\\0junk is taken for HELLO."""
    ident = make_identity()

    def client(peer):
        peer.send_line(b"HELLO\0junk")
        return peer.recv_line()
    got, reply, _ = serve_one(client, ident.hex)
    check(reply is not None and reply.startswith(b"CHALLENGE "), "HELLO\\0junk was refused: %r" % (reply,))


@case("T-238")
def t238():
    """A line that does not begin with AUTH is refused."""
    ident = make_identity()
    for line in (b"auth pk sig", b"HELLO", b"", b"AUTHX pk sig"):
        got, reply, _ = serve_one(after_challenge(line), ident.hex)
        eq((got, reply), (None, b"FAIL expected AUTH"), "the line %r" % line)


@case("T-239")
def t239():
    """An AUTH line without its two fields is refused."""
    ident = make_identity()
    for line in (b"AUTH onefield", b"AUTH " + b64(os.urandom(32)) + b"\t" + b64(os.urandom(64)), b"AUTH "):
        got, reply, _ = serve_one(after_challenge(line), ident.hex)
        eq((got, reply), (None, b"FAIL invalid AUTH format"), "the line %r" % line[:30])


@case("T-240", PIN)
def t240():
    """The spacing of AUTH is lenient."""
    ident = make_identity()
    shapes = {
        "a third field": lambda pk, sig: b"AUTH " + pk + b" " + sig + b" extra junk",
        "extra spaces between": lambda pk, sig: b"AUTH   " + pk + b"    " + sig,
        "a trailing space": lambda pk, sig: b"AUTH " + pk + b" " + sig + b" ",
        "an extra space before": lambda pk, sig: b"AUTH  " + pk + b" " + sig,
    }
    for what, shape in shapes.items():
        got, reply, _ = serve_one(lambda p, shape=shape: handshake(p, ident, shape), ident.hex)
        eq(got, ident.hex.encode(), "AUTH with %s" % what)


@case("T-241")
def t241():
    """A bad public key is refused."""
    ident = make_identity()
    urlsafe = None
    while urlsafe is None:
        raw = os.urandom(32)
        if b"+" in b64(raw) or b"/" in b64(raw):
            urlsafe = b64(raw).replace(b"+", b"-").replace(b"/", b"_")
    sig = b64(os.urandom(64))
    for what, pk in (("not base64", b"!!!notbase64!!!"), ("URL-safe characters", urlsafe),
                     ("31 bytes", b64(os.urandom(31))), ("33 bytes", b64(os.urandom(33)))):
        got, reply, _ = serve_one(after_challenge(b"AUTH " + pk + b" " + sig), ident.hex)
        eq((got, reply), (None, b"FAIL invalid public key"), what)


@case("T-242")
def t242():
    """A bad signature is refused."""
    ident = make_identity()
    pk = b64(ident.auth_pk)
    for what, sig in (("not base64", b"!!!notbase64!!!"), ("63 bytes", b64(os.urandom(63))),
                      ("65 bytes", b64(os.urandom(65)))):
        got, reply, _ = serve_one(after_challenge(b"AUTH " + pk + b" " + sig), ident.hex)
        eq((got, reply), (None, b"FAIL invalid signature"), what)


@case("T-243")
def t243():
    """A signature over anything but this challenge is refused."""
    ident = make_identity()

    def over(what):
        def client(peer):
            peer.send_line(b"HELLO")
            ch = read_challenge(peer)
            signed = os.urandom(32) if what == "another challenge" else b64(ch)
            sig = ls.sign_detached(signed, ident.auth_sk)
            peer.send_line(b"AUTH " + b64(ident.auth_pk) + b" " + b64(sig))
            return peer.recv_line()
        return client
    for what in ("another challenge", "the challenge's base64 text"):
        got, reply, _ = serve_one(over(what), ident.hex)
        eq((got, reply), (None, b"FAIL signature verification failed"), "a signature over " + what)


@case("T-244")
def t244():
    """An all-zero key with an all-zero signature is refused."""
    ident = make_identity()
    line = b"AUTH " + b64(b"\0" * 32) + b" " + b64(b"\0" * 64)
    got, reply, _ = serve_one(after_challenge(line), ident.hex)
    eq((got, reply), (None, b"FAIL signature verification failed"), "all zeros")


@case("T-245")
def t245():
    """An unusable allowlist is refused before anything is read."""
    P = lib.proto()
    bad = {
        "NULL": None,
        "63 characters": b"a" * 63,
        "65 characters": b"a" * 65,
        "uppercase": b"A" * 64,
        "a g": b"g" + b"a" * 63,
        "a NUL at position 32": b"a" * 32 + b"\0" + b"a" * 31,
    }
    for what, allowed in bad.items():
        a, b = net.sockpair()
        peer = Peer(a)
        got = P._take(P.c_auth_server(b.fileno(), allowed))
        b.close()
        eq(got, None, "the result for " + what)
        eq(peer.recv_line(), b"FAIL internal error", "what the client is told for " + what)


@case("T-246", FINDING)
def t246():
    """A client that says nothing is sent a FAIL."""
    ident = make_identity()
    got, line, took = serve_one(lambda p: p.recv_line(5), ident.hex)
    eq(got, None, "a client that says nothing")
    check(line is not None and line.startswith(b"FAIL "), "a silent client was sent %r, not a FAIL" % (line,))

    def after_hello(peer):
        peer.send_line(b"HELLO")
        read_challenge(peer)
        return peer.recv_line(5)
    got, line, took = serve_one(after_hello, ident.hex)
    check(line is not None and line.startswith(b"FAIL "), "a client silent after the challenge was sent %r" % (line,))


@case("T-247", FINDING)
def t247():
    """An oversized HELLO or AUTH is answered with a FAIL."""
    P = lib.proto()
    ident = make_identity()
    for stage in ("HELLO", "AUTH"):
        ls_ = net.listener()
        client = socket.create_connection(ls_.getsockname())
        server_side, _ = ls_.accept()
        peer = Peer(client)

        def talk():
            if stage == "AUTH":
                peer.send_line(b"HELLO")
                read_challenge(peer)
            peer.send(b"x" * 20000 + b"\n")
        w = net.Worker(talk)
        got = P.auth_server(server_side.fileno(), ident.hex)
        w.finish()
        server_side.close()                          # with the rest of the line unread
        eq(got, None, "an oversized %s" % stage)
        line = peer.recv_line(3)
        check(line is not None and line.startswith(b"FAIL "),
              "an oversized %s was answered with %r, not a FAIL" % (stage, line))
        ls_.close()


@case("T-248")
def t248():
    """A client that leaves mid-handshake ends the child at once."""
    ident = make_identity()

    def client(peer):
        peer.send_line(b"HELLO")
        peer.close()
    got, _, took = serve_one(client, ident.hex)
    eq(got, None, "a client that closes after HELLO")
    check(took < 250 + slack_ms(250), "it took %.0f ms" % took)


@case("T-249")
def t249():
    """Nothing echoes the client, and every FAIL is the last line."""
    ident, stranger = make_identity(), make_identity()
    marker = b"ECHO-MARKER-12345"
    scripts = {
        "a bad HELLO": lambda p: p.send_line(b"hello " + marker),
        "a bad AUTH verb": after_challenge(b"auth " + marker),
        "an AUTH with one field": after_challenge(b"AUTH " + marker),
        "a bad public key": after_challenge(b"AUTH " + marker + b" " + b64(os.urandom(64))),
        "a bad signature": after_challenge(b"AUTH " + b64(ident.auth_pk) + b" " + marker),
        "a stranger": lambda p: handshake(p, stranger),
        "a second HELLO": after_challenge(b"HELLO " + marker),
    }
    P = lib.proto()
    for what, script in scripts.items():
        a, b = net.sockpair()
        peer = Peer(a)
        w = net.Worker(script, peer)
        P.auth_server(b.fileno(), ident.hex)
        b.close()
        w.finish()
        peer.recv_all()                                # until end of stream
        data = bytes(peer.rx)
        lines = [l for l in data.split(b"\n") if l]
        check(marker not in data, "%s: the server echoed the client: %r" % (what, data[:80]))
        fails = [i for i, l in enumerate(lines) if l.startswith(b"FAIL ")]
        for l in lines:
            ok = (l.startswith(b"CHALLENGE ") and len(l) == 54) or (l.startswith(b"FAIL ") and l[5:] in FAIL_REASONS)
            check(ok, "%s: an undocumented line from the server: %r" % (what, l))
        if fails:
            eq(fails, [len(lines) - 1], "%s: lines after the FAIL" % what)


@case("T-250")
def t250():
    """A client that trickles bytes cannot keep the child past the deadline."""
    P = lib.proto()
    ident = make_identity()

    gap = 0.1 * max(1.0, harness.SLACK)   # the deadline is stretched by SLACK, so is the trickle
    def client(peer):
        try:
            for ch in b"HELLO\n":
                peer.send(bytes([ch]))
                time.sleep(gap)
        except OSError:
            pass
        return peer.recv_line(2)
    got, _, took = serve_one(client, ident.hex, P)
    eq(got, None, "a client sending HELLO a byte every %d ms" % (gap * 1000))
    check(net.in_window(took, P.macros["HANDSHAKE_TIMEOUT_MS"]), "the server gave up after %.0f ms" % took)


@case("T-251")
def t251():
    """The identity is compared exactly."""
    ident = make_identity()
    last = "0" if ident.hex[-1] != "0" else "1"
    other = ident.hex[:-1] + last
    got, reply, _ = serve_one(lambda p: handshake(p, ident), other)
    eq((got, reply), (None, b"FAIL access denied"), "an allowlist that differs in its last digit")


@case("T-252", tags=("seam",))
def t252():
    """An allocation failure is answered with FAIL internal error."""
    runprobe.must_pass("seam_auth", ["server_alloc"], seams=runprobe.AUTH_SEAMS, threads=True)


@case("T-253")
def t253():
    """The two halves of the library agree."""
    P = lib.proto()
    ident = make_identity()
    rc, keys = P.load_keys(ident.auth_key, ident.enc_key)
    eq(rc, 0, "proto_load_keys")
    a, b = net.sockpair()

    def server():
        who = P.auth_server(b.fileno(), ident.hex)
        if who:
            P.send_line(b.fileno(), "OK")
        return who
    w = net.Worker(server)
    rc = P.auth_client(a.fileno(), keys)
    who = w.finish()
    eq(rc, 0, "proto_auth_client")
    eq(who, ident.hex.encode(), "the identity proto_auth_server returned")
