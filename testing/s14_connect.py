"""XVI. proto_connect (T-254 to T-281)."""

import ctypes
import fcntl
import os
import signal
import socket
import time

import harness
import lib
import libsodium as ls
import net
import peers
import runprobe
import servers
from harness import FINDING, PIN, PLATFORM, case, check, eq, in_child, skip, slack_ms
from keyfiles import make_identity

REJECTED, REGISTER_REJECTED, TIMEOUT = -703, -704, -605
INT_MIN, INT_MAX = -2 ** 31, 2 ** 31 - 1


def new_conn(P, ident):
    rc, keys = P.load_keys(ident.auth_key, ident.enc_key)
    eq(rc, 0, "proto_load_keys")
    return lib.Conn.new(keys)


def connect_to(P, ident, port, host="127.0.0.1"):
    conn = new_conn(P, ident)
    rc = P.connect(conn, host, port)
    return rc, conn


def disposition(sig):
    """The OS-level disposition of a signal, read by setting it to the default and back."""
    c = lib.libc
    c.signal.restype = ctypes.c_void_p
    c.signal.argtypes = [ctypes.c_int, ctypes.c_void_p]
    prev = c.signal(sig, 0)
    c.signal(sig, prev)
    return prev or 0


@case("T-254")
def t254():
    """A full connection is PROTO_OK and fills the conn."""
    P = lib.proto()
    ident = make_identity()
    with servers.Server(ident.hex, "ok") as srv:
        rc, conn = connect_to(P, ident, srv.port)
        eq(rc, 0, "proto_connect")
        check(conn.fd >= 0, "no descriptor")
        eq(conn.identity_hex, ident.hex.encode(), "identity_hex")
        check(not net.is_nonblocking(conn.fd), "the socket is left non-blocking")
        eq(servers.command(P, conn, "PING"), (4, b"PONG"), "a command on the new session")
        P.close(conn)


@case("T-255")
def t255():
    """Registration is answered automatically."""
    P = lib.proto()
    ident = make_identity()
    with servers.Server(ident.hex, "register") as srv:
        rc, conn = connect_to(P, ident, srv.port)
        eq(rc, 0, "proto_connect (not PROTO_REGISTER_REQUESTED)")
        line = srv.wait_log("rx REGISTER ")[0][3:]
        eq(len(line), 9 + 44, "length of the REGISTER line")
        eq(ls.b64d(line[9:]), ident.enc_pk, "the key in the REGISTER line")
        P.close(conn)


@case("T-256")
def t256():
    """A refused registration is PROTO_E_REGISTER_REJECTED."""
    P = lib.proto()
    ident = make_identity()
    with servers.Server(ident.hex, "register_fail") as srv:
        rc, conn = connect_to(P, ident, srv.port)
        eq(rc, REGISTER_REJECTED, "proto_connect")
        eq(conn.fd, -1, "conn.fd")
        srv.wait_log("eof")                                  # the server sees the connection close


@case("T-257")
def t257():
    """Only OK completes a registration."""
    P = lib.proto()
    ident = make_identity()
    with servers.Server(ident.hex, "register_okcr") as srv:
        rc, conn = connect_to(P, ident, srv.port)
        eq(rc, 0, "OK followed by a carriage return")
        P.close(conn)
    with servers.Server(ident.hex, "register_okextra") as srv:
        rc, conn = connect_to(P, ident, srv.port)
        eq(rc, REGISTER_REJECTED, "OK extra")
        eq(conn.fd, -1, "conn.fd")


@case("T-258")
def t258():
    """Silence after REGISTER is PROTO_E_TIMEOUT."""
    P = lib.proto()
    ident = make_identity()
    with servers.Server(ident.hex, "register_silent") as srv:
        rc, conn = connect_to(P, ident, srv.port)
        eq(rc, TIMEOUT, "proto_connect")
        eq(conn.fd, -1, "conn.fd")


@case("T-259")
def t259():
    """An identity that is not allowlisted is PROTO_E_REJECTED."""
    P = lib.proto()
    mine, other = make_identity(), make_identity()
    with servers.Server(other.hex, "ok") as srv:
        rc, conn = connect_to(P, mine, srv.port)
        eq(rc, REJECTED, "proto_connect")
        eq(conn.fd, -1, "conn.fd")


@case("T-260", PIN)
def t260():
    """identity_hex is filled even when the handshake fails."""
    P = lib.proto()
    mine, other = make_identity(), make_identity()
    with servers.Server(other.hex, "ok") as srv:
        rc, conn = connect_to(P, mine, srv.port)
        eq(rc, REJECTED, "proto_connect")
        eq(conn.identity_hex, mine.hex.encode(), "identity_hex after a refusal")


@case("T-261", tags=("seam",))
def t261():
    """An out-of-range port is PROTO_E_BAD_PORT, before any resolution."""
    runprobe.must_pass("seam_auth", ["bad_port"], seams=runprobe.AUTH_SEAMS, threads=True)


@case("T-262", FINDING)
def t262():
    """PROTO_E_BAD_PORT on a connected conn closes the old connection."""
    P = lib.proto()
    ident = make_identity()
    with servers.Server(ident.hex, "ok") as srv:
        rc, conn = connect_to(P, ident, srv.port)
        eq(rc, 0, "the first connection")
        eq(P.connect(conn, "127.0.0.1", 0), -107, "proto_connect with port 0")
        eq(conn.fd, -1, "conn.fd after PROTO_E_BAD_PORT (docs.md: left at -1 and the socket closed)")


@case("T-263")
def t263():
    """A name that does not resolve is PROTO_E_RESOLVE."""
    P = lib.proto()
    ident = make_identity()
    rc, conn = connect_to(P, ident, 5000, host="nonexistent.invalid")
    eq(rc, -502, "proto_connect to nonexistent.invalid")
    eq(conn.fd, -1, "conn.fd")


@case("T-264", PIN)
def t264():
    """host == NULL connects to the loopback."""
    P = lib.proto()
    ident = make_identity()
    with servers.Server(ident.hex, "ok") as srv:
        conn = new_conn(P, ident)
        eq(P.c_connect(ctypes.byref(conn), None, srv.port), 0, "host NULL")
        P.close(conn)
        conn = new_conn(P, ident)
        rc = P.c_connect(ctypes.byref(conn), b"", srv.port)
        if PLATFORM == "macos":
            eq(rc, 0, "host \"\" on macOS")
            P.close(conn)
        elif PLATFORM == "linux":
            eq(rc, -502, "host \"\" on glibc and musl (reasoned)")
        else:
            harness.note("%s: host \"\" gave %d" % (PLATFORM, rc))


@case("T-265")
def t265():
    """A closed port is PROTO_E_CONNECT, at once."""
    P = lib.proto()
    ident = make_identity()
    t0 = net.now()
    rc, conn = connect_to(P, ident, net.free_port())
    took = net.ms_since(t0)
    eq(rc, -503, "proto_connect to a closed port")
    eq(conn.fd, -1, "conn.fd")
    check(took < 250 + slack_ms(250), "it took %.0f ms" % took)


@case("T-266")
def t266():
    """Every address of a host is tried."""
    P = lib.proto()
    ident = make_identity()
    with servers.Server(ident.hex, "ok", bind="127.0.0.1") as srv:
        rc, conn = connect_to(P, ident, srv.port, host="localhost")
        eq(rc, 0, "proto_connect to localhost, with the server on 127.0.0.1 only")
        P.close(conn)


@case("T-267", tags=("linux",))
def t267():
    """Silence is PROTO_E_CONNECT_TIMEOUT after CONNECT_TIMEOUT_MS."""
    P = lib.proto()
    ident = make_identity()
    ls_ = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ls_.bind(("127.0.0.1", 0))
    ls_.listen(0)                                       # an accept queue of one
    port = ls_.getsockname()[1]
    c1 = socket.create_connection(("127.0.0.1", port), timeout=2)      # fills it
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.settimeout(0.3)
    try:
        probe.connect(("127.0.0.1", port))
        skip("this kernel completed a connection to a full accept queue: no silence to test with")
    except socket.timeout:
        pass
    except OSError as e:
        skip("this kernel answered a connection to a full accept queue with %s" % e)
    t0 = net.now()
    rc, conn = connect_to(P, ident, port)
    took = net.ms_since(t0)
    eq(rc, -510, "proto_connect to an address that answers nothing")
    eq(conn.fd, -1, "conn.fd")
    check(net.in_window(took, P.macros["CONNECT_TIMEOUT_MS"]), "the deadline took %.0f ms" % took)


@case("T-268", tags=("seam",))
def t268():
    """The address walk ranks the outcomes."""
    runprobe.must_pass("seam_auth", ["walk"], seams=runprobe.AUTH_SEAMS, threads=True, timeout=120)


@case("T-269", tags=("seam",))
def t269():
    """An interrupted connect() is waited for."""
    runprobe.must_pass("seam_auth", ["eintr"], seams=runprobe.AUTH_SEAMS, threads=True)


@case("T-270", tags=("seam",))
def t270():
    """The kernel giving up first counts as silence."""
    runprobe.must_pass("seam_auth", ["etimedout"], seams=runprobe.AUTH_SEAMS, threads=True)


@case("T-271")
def t271():
    """No descriptor leaks on failure."""
    P = lib.proto()
    ident, stranger = make_identity(), make_identity()
    refusing = servers.Server(stranger.hex, "ok")
    silent = servers.Server(ident.hex, "silent")
    registering = servers.Server(ident.hex, "register_fail")
    with refusing, silent, registering:
        scenarios = [
            ("PROTO_E_RESOLVE", -502, "nonexistent.invalid", 5000),
            ("PROTO_E_CONNECT", -503, "127.0.0.1", net.free_port()),
            ("PROTO_E_REJECTED", REJECTED, "127.0.0.1", refusing.port),
            ("PROTO_E_TIMEOUT", TIMEOUT, "127.0.0.1", silent.port),
            ("PROTO_E_REGISTER_REJECTED", REGISTER_REJECTED, "127.0.0.1", registering.port),
        ]
        for name, want, host, port in scenarios:
            # One call first: the system's resolver may open a descriptor of its own
            # the first time and keep it. A leak of the library's would grow with
            # every call, so the second one still shows it.
            warm = new_conn(P, ident)
            eq(P.connect(warm, host, port), want, "the first " + name)
            conn = new_conn(P, ident)
            before = net.fd_count()
            rc = P.connect(conn, host, port)
            eq(rc, want, name)
            eq(conn.fd, -1, "conn.fd after " + name)
            eq(net.fd_count(), before, "open descriptors after " + name)


@case("T-272", timeout=120)
def t272():
    """Reconnecting on a live conn closes the old connection."""
    P = lib.proto()
    ident = make_identity()
    with servers.Server(ident.hex, "ok") as srv:
        rc, conn = connect_to(P, ident, srv.port)
        eq(rc, 0, "the first connection")
        old = conn.fd
        eq(P.connect(conn, "127.0.0.1", srv.port), 0, "the second connection, on the same conn")
        srv.wait_log("rx QUIT")                              # the first child saw QUIT ...
        srv.wait_log("eof")                                  # ... and then the end of the stream
        eq(servers.command(P, conn, "PING"), (4, b"PONG"), "a command on the new socket")
        before = net.fd_count()
        for _ in range(100):
            eq(P.connect(conn, "127.0.0.1", srv.port), 0, "a reconnect")
        eq(net.fd_count(), before, "the client's open descriptors after 100 reconnects")
        alive = lambda: len([c for c in srv.children() if not c[1].startswith("Z")])
        check(net.wait_until(lambda: alive() <= 2, 10), "the server still has %d children after 100 reconnects" % alive())
        P.close(conn)


@case("T-273")
def t273():
    """Reconnecting after the old connection died works."""
    P = lib.proto()
    ident = make_identity()
    signal.signal(signal.SIGPIPE, signal.SIG_DFL)
    with servers.Server(ident.hex, "sleep", ms=100) as srv:
        rc, conn = connect_to(P, ident, srv.port)
        eq(rc, 0, "the first connection")
        rc, text = P.recv_line(conn.fd, 64)
        eq(rc, -603, "a read after the server child ended")
        eq(P.connect(conn, "127.0.0.1", srv.port), 0, "reconnecting without proto_close")
        P.close(conn)


@case("T-274")
def t274():
    """A descriptor that is not a socket is left alone."""
    P = lib.proto()
    ident = make_identity()
    with servers.Server(ident.hex, "ok") as srv:
        rc, keys = P.load_keys(ident.auth_key, ident.enc_key)
        # stdin is a file (/dev/null) here
        conn = lib.Conn()
        conn.keys = keys
        before = os.fstat(0)
        eq(P.connect(conn, "127.0.0.1", srv.port), 0, "a {0} conn with an ordinary stdin")
        after = os.fstat(0)
        eq((after.st_dev, after.st_ino), (before.st_dev, before.st_ino), "stdin")
        check(conn.fd != 0, "the connection took the descriptor of stdin")
        P.close(conn)
        # stdin a pipe
        r, w = os.pipe()
        os.dup2(r, 0)
        conn = lib.Conn()
        conn.keys = keys
        eq(P.connect(conn, "127.0.0.1", srv.port), 0, "a {0} conn with a pipe as stdin")
        check(conn.fd != 0, "the connection took the descriptor of stdin")
        os.write(w, b"x")
        eq(os.read(0, 1), b"x", "the pipe on stdin still works")
        P.close(conn)
        # a pipe at fd 5 or above, in conn->fd: the lowest free number from 5, since a dup2 to 5 would
        # close whatever the case holds there (the write end of this very pipe, or the harness's report pipe)
        fd = fcntl.fcntl(r, fcntl.F_DUPFD, 5)
        conn = lib.Conn()
        conn.keys = keys
        conn.fd = fd
        eq(P.connect(conn, "127.0.0.1", srv.port), 0, "a pipe at fd %d in conn->fd" % fd)
        os.fstat(fd)
        check(conn.fd != fd, "the connection took the pipe's descriptor")
        P.close(conn)


def watched_socket_on(fd):
    """Put one end of a socketpair on descriptor 0, or on the lowest free one from fd: a dup2 to a
    number other than stdin's would close whatever is open there. Returns (reader thread, what it
    read, the descriptor)."""
    x, y = net.sockpair()
    if fd == 0:
        os.dup2(x.fileno(), 0)
    else:
        fd = fcntl.fcntl(x.fileno(), fcntl.F_DUPFD, fd)
    x.close()
    peer = net.Peer(y)
    seen = {}

    def read_all():
        seen["data"] = peer.recv_all(10)
        return seen["data"]
    return net.Worker(read_all), seen, fd


@case("T-275", PIN)
def t275():
    """A {0} conn closes stdin when stdin is a socket."""
    P = lib.proto()
    ident = make_identity()
    with servers.Server(ident.hex, "ok") as srv:
        rc, keys = P.load_keys(ident.auth_key, ident.enc_key)
        reader, seen, _ = watched_socket_on(0)
        conn = lib.Conn()
        conn.keys = keys
        eq(P.connect(conn, "127.0.0.1", srv.port), 0, "a {0} conn with a socket as stdin")
        eq(reader.finish(15), b"QUIT\n", "what the old stdin socket received before it was closed")
        eq(conn.fd, 0, "the new connection takes descriptor 0")
        P.close(conn)


@case("T-276", PIN)
def t276():
    """A stale conn->fd that now holds an application's socket is closed."""
    P = lib.proto()
    ident = make_identity()
    with servers.Server(ident.hex, "ok") as srv:
        rc, keys = P.load_keys(ident.auth_key, ident.enc_key)
        reader, seen, fd = watched_socket_on(7)
        conn = lib.Conn()
        conn.keys = keys
        conn.fd = fd
        eq(P.connect(conn, "127.0.0.1", srv.port), 0, "proto_connect with conn->fd on an application's socket")
        eq(reader.finish(15), b"QUIT\n", "what the application's socket received before it was closed")
        P.close(conn)


@case("T-277", FINDING)
def t277():
    """The connection is close-on-exec."""
    P = lib.proto()
    ident = make_identity()
    with servers.Server(ident.hex, "ok") as srv:
        rc, conn = connect_to(P, ident, srv.port)
        eq(rc, 0, "proto_connect")
        check(net.cloexec(conn.fd), "FD_CLOEXEC is clear: a program the client runs inherits the session")
        P.close(conn)


@case("T-278", PIN)
def t278():
    """Keys that were never loaded are not checked."""
    P = lib.proto()
    ident = make_identity()
    with servers.Server(ident.hex, "ok") as srv:
        conn = lib.Conn.new()                              # all-zero keys
        eq(P.connect(conn, "127.0.0.1", srv.port), REJECTED, "proto_connect with keys that were never loaded")


@case("T-279")
def t279():
    """The client's signal dispositions are unchanged."""
    P = lib.proto()
    ident, stranger = make_identity(), make_identity()
    before = (disposition(signal.SIGPIPE), disposition(signal.SIGCHLD))
    with servers.Server(ident.hex, "ok") as good, servers.Server(stranger.hex, "ok") as bad:
        rc, conn = connect_to(P, ident, good.port)
        eq(rc, 0, "a good connection")
        P.close(conn)
        rc, conn = connect_to(P, ident, bad.port)
        eq(rc, REJECTED, "a refused connection")
        rc, conn = connect_to(P, ident, net.free_port())
        eq(rc, -503, "a failed connection")
    eq((disposition(signal.SIGPIPE), disposition(signal.SIGCHLD)), before, "SIGPIPE and SIGCHLD")


@case("T-280", PIN)
def t280():
    """conn == NULL crashes for a valid port."""
    P = lib.proto()
    port = net.free_port()
    how, code = in_child(lambda: P.c_connect(None, b"127.0.0.1", port))
    check(how == "signal" and code in (signal.SIGSEGV, signal.SIGBUS),
          "a NULL conn no longer crashes (%s %s): decide with T-051" % (how, code))
    eq(P.c_connect(None, b"127.0.0.1", 0), -107, "an invalid port comes first")


@case("T-281", tags=("ipv6",))
def t281():
    """The IPv6 path connects."""
    P = lib.proto()
    ident = make_identity()
    try:
        ls_ = net.listener("::1", 0, family=socket.AF_INET6)
    except OSError as e:
        skip("cannot bind ::1: %s" % e)
    port = ls_.getsockname()[1]
    w = net.Worker(peers.accept_and_serve, ls_, ident.auth_pk, b"OK")
    rc, conn = connect_to(P, ident, port, host="::1")
    eq(rc, 0, "proto_connect to ::1")
    P.close(conn)
    w.finish()
