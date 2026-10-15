"""XVII. proto_close (T-282 to T-291)."""

import os
import signal
import stat
import time

import harness
import lib
import net
import peers
import runprobe
import servers
from harness import FINDING, PIN, case, check, eq, in_child, slack_ms
from keyfiles import make_identity
from net import Peer
from s14_connect import connect_to, new_conn


@case("T-282")
def t282():
    """proto_close says QUIT, waits for one line, and closes."""
    P = lib.proto()
    ident = make_identity()
    with servers.Server(ident.hex, "ok") as srv:
        rc, conn = connect_to(P, ident, srv.port)
        eq(rc, 0, "proto_connect")
        t0 = net.now()
        P.close(conn)
        took = net.ms_since(t0)
        eq(conn.fd, -1, "conn.fd")
        srv.wait_log("rx QUIT")
        srv.wait_log("eof")
        check(took < P.macros["QUIT_TIMEOUT_MS"], "it waited %.0f ms for a BYE that came at once" % took)
    # The wire, from a peer written here: HELLO, AUTH, QUIT, and BYE in answer.
    ls_ = net.listener()
    w = net.Worker(peers.accept_and_serve, ls_, ident.auth_pk, b"OK")
    rc, conn = connect_to(P, ident, ls_.getsockname()[1])
    eq(rc, 0, "proto_connect to a scripted server")
    P.close(conn)
    info = w.finish()
    eq(info["lines"][0], b"HELLO", "first line")
    eq(info["lines"][-1], b"QUIT", "last line")


@case("T-283")
def t283():
    """A server that never answers costs QUIT_TIMEOUT_MS, no more."""
    P = lib.proto()
    ident = make_identity()
    with servers.Server(ident.hex, "ok_silent") as srv:
        rc, conn = connect_to(P, ident, srv.port)
        eq(rc, 0, "proto_connect")
        t0 = net.now()
        P.close(conn)
        took = net.ms_since(t0)
        eq(conn.fd, -1, "conn.fd")
        check(net.in_window(took, P.macros["QUIT_TIMEOUT_MS"]), "proto_close took %.0f ms" % took)


@case("T-284")
def t284():
    """A dead peer costs no wait."""
    P = lib.proto()
    ident = make_identity()
    signal.signal(signal.SIGPIPE, signal.SIG_DFL)
    for how in ("close", "reset"):
        ls_ = net.listener()

        def server(how=how, ls_=ls_):
            conn, _ = ls_.accept()
            peer = Peer(conn)
            peers.server_handshake(peer, ident.auth_pk, b"OK")
            if how == "reset":
                net.reset_close(conn)
            else:
                conn.close()
        w = net.Worker(server)
        rc, conn = connect_to(P, ident, ls_.getsockname()[1])
        eq(rc, 0, "proto_connect")
        w.finish()
        time.sleep(0.05)
        t0 = net.now()
        P.close(conn)
        took = net.ms_since(t0)
        eq(conn.fd, -1, "conn.fd after a peer that did a %s" % how)
        check(took < 150 + slack_ms(250), "proto_close took %.0f ms with a dead peer (%s)" % (took, how))


@case("T-285")
def t285():
    """A second call does nothing."""
    P = lib.proto()
    ident = make_identity()
    with servers.Server(ident.hex, "ok") as srv:
        rc, conn = connect_to(P, ident, srv.port)
        eq(rc, 0, "proto_connect")
        P.close(conn)
        eq(conn.fd, -1, "conn.fd after the first call")
        a, b = net.sockpair()                         # likely to take the number the connection had
        P.close(conn)
        eq(conn.fd, -1, "conn.fd after the second call")
        a.getsockname()                               # still open
        a.send(b"x")
        eq(b.recv(1), b"x", "the socket that may have taken the old number")


@case("T-286", tags=("seam",))
def t286():
    """fd == -1 returns without a system call."""
    runprobe.must_pass("seam_auth", ["close_noop"], seams=runprobe.AUTH_SEAMS, threads=True)


@case("T-287")
def t287():
    """fd == 0 that is not a socket is left open."""
    P = lib.proto()
    d = harness.tmpdir("stdin")
    path = os.path.join(d, "stdin")
    fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    os.dup2(fd, 0)
    os.close(fd)
    conn = lib.Conn()
    P.close(conn)                                     # {0}: fd is 0
    eq(conn.fd, -1, "conn.fd")
    eq(os.fstat(0).st_size, 0, "what proto_close wrote into stdin")
    r, w = os.pipe()
    os.dup2(r, 0)
    conn = lib.Conn()
    P.close(conn)
    eq(conn.fd, -1, "conn.fd with a pipe as stdin")
    check(stat.S_ISFIFO(os.fstat(0).st_mode), "stdin is no longer the pipe")
    os.write(w, b"still open")
    eq(os.read(0, 100), b"still open", "the pipe on stdin")


@case("T-288")
def t288():
    """QUIT_TIMEOUT_MS=0 does not wait."""
    P = lib.proto("quit0")
    ident = make_identity()
    with servers.Server(ident.hex, "ok_silent") as srv:
        rc, conn = connect_to(P, ident, srv.port)
        eq(rc, 0, "proto_connect")
        t0 = net.now()
        P.close(conn)
        took = net.ms_since(t0)
        eq(conn.fd, -1, "conn.fd")
        check(took < 100 + slack_ms(150), "proto_close took %.0f ms with QUIT_TIMEOUT_MS=0" % took)


@case("T-289")
def t289():
    """A long answer in place of BYE does not hold the close."""
    P = lib.proto()
    ident = make_identity()
    with servers.Server(ident.hex, "long_answer") as srv:
        rc, conn = connect_to(P, ident, srv.port)
        eq(rc, 0, "proto_connect")
        t0 = net.now()
        P.close(conn)
        took = net.ms_since(t0)
        eq(conn.fd, -1, "conn.fd")
        check(took < 150 + slack_ms(150), "proto_close took %.0f ms" % took)


@case("T-290", FINDING)
def t290():
    """proto_close(NULL) is a no-op."""
    P = lib.proto()
    P.c_close(None)


@case("T-291", PIN)
def t291():
    """An unread reply is taken for the goodbye."""
    P = lib.proto()
    ident = make_identity()
    ls_ = net.listener()
    seen = {}

    def server():
        conn, _ = ls_.accept()
        peer = Peer(conn)
        peers.server_handshake(peer, ident.auth_pk, b"OK")
        seen["ping"] = peer.recv_line(5)
        peer.send_line(b"PONG")
        seen["next"] = peer.recv_line(5)                 # QUIT
        peer.send_line(b"BYE")
        seen["ended"] = peer.wait_eof(5)
        seen["reset"] = peer.reset
    w = net.Worker(server)
    rc, conn = connect_to(P, ident, ls_.getsockname()[1])
    eq(rc, 0, "proto_connect")
    P.send_line(conn.fd, "PING")                          # and the reply is left unread
    time.sleep(0.1)
    t0 = net.now()
    P.close(conn)
    took = net.ms_since(t0)
    w.finish()
    eq(conn.fd, -1, "conn.fd")
    check(took < 150 + slack_ms(250), "proto_close waited %.0f ms: it should take PONG for the goodbye" % took)
    eq((seen["ping"], seen["next"]), (b"PING", b"QUIT"), "what the server read")
    check(seen["ended"], "the connection never ended")
    harness.note("the server saw %s" % ("a reset" if seen["reset"] else "an orderly end of stream"))
