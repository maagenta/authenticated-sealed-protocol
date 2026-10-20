"""XX. Process-wide effects of proto_serve (T-348 to T-354)."""

import ctypes
import os
import signal
import socket
import time

import harness
import lib
import net
import runprobe
import servers
from harness import FINDING, PIN, PLATFORM, case, check, eq, in_child, skip
from keyfiles import make_identity
from s14_connect import connect_to, disposition
from s16_serve import GOOD, serve_call, starts

SIG_DFL, SIG_IGN = 0, 1


def libc_signal():
    c = lib.libc
    c.signal.restype = ctypes.c_void_p
    c.signal.argtypes = [ctypes.c_int, ctypes.c_void_p]
    return c


def privileged_port_restricted():
    """True when ordinary users cannot bind port 1 (ip_unprivileged_port_start > 1)."""
    try:
        with open("/proc/sys/net/ipv4/ip_unprivileged_port_start") as f:
            return int(f.read()) > 1
    except (OSError, ValueError):
        return False


@case("T-348", FINDING)
def t348():
    """The child reaper is removed when proto_serve returns."""
    P = lib.proto()
    eq(starts(P, net.free_port()), 0, "proto_serve")
    c = lib.libc
    c.popen.restype = ctypes.c_void_p
    c.popen.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
    c.pclose.argtypes = [ctypes.c_void_p]
    c.pclose.restype = ctypes.c_int
    pipe = c.popen(b"exit 3", b"r")
    status = c.pclose(pipe)
    check(status != -1 and os.WIFEXITED(status) and os.WEXITSTATUS(status) == 3,
          "pclose(popen(\"exit 3\")) returned %d (errno %d): the SIGCHLD reaper outlived proto_serve"
          % (status, ctypes.get_errno()))
    pid = os.fork()
    if pid == 0:
        os._exit(7)
    time.sleep(0.2)
    try:
        _, st = os.waitpid(pid, 0)
    except ChildProcessError:
        raise harness.Fail("waitpid on the application's own child fails with ECHILD: the reaper took it")
    eq(os.WEXITSTATUS(st), 7, "the application's own child")


@case("T-349", PIN)
def t349():
    """SIGPIPE stays ignored after proto_serve returns."""
    P = lib.proto()
    c = libc_signal()
    c.signal(signal.SIGPIPE, SIG_DFL)
    eq(starts(P, net.free_port()), 0, "proto_serve")
    eq(disposition(signal.SIGPIPE), SIG_IGN, "SIGPIPE after proto_serve returned")


@case("T-350", PIN)
def t350():
    """An application's SIGCHLD handler is replaced without a word."""
    P = lib.proto()
    signal.signal(signal.SIGCHLD, lambda *a: None)
    mine = disposition(signal.SIGCHLD)
    check(mine not in (SIG_DFL, SIG_IGN), "test data is wrong: no handler installed")
    eq(starts(P, net.free_port()), 0, "proto_serve")
    after = disposition(signal.SIGCHLD)
    check(after != mine, "the application's SIGCHLD handler is still installed after proto_serve")
    check(after not in (SIG_DFL, SIG_IGN), "SIGCHLD is %d after proto_serve: the library's reaper was expected" % after)


@case("T-351", PIN)
def t351():
    """Setup failures after the dispositions change leave them changed."""
    P = lib.proto()
    c = libc_signal()

    def outcome(call):
        def run():
            c.signal(signal.SIGPIPE, SIG_DFL)
            c.signal(signal.SIGCHLD, SIG_DFL)
            call()
            pipe_ignored = c.signal(signal.SIGPIPE, SIG_DFL) == SIG_IGN
            handler = c.signal(signal.SIGCHLD, SIG_DFL) or 0
            os._exit((1 if pipe_ignored else 0) | (2 if handler not in (SIG_DFL, SIG_IGN) else 0))
        return in_child(run)

    held = net.listener("0.0.0.0", 0)
    after = {
        "PROTO_E_PORT_IN_USE": lambda: serve_call(P, held.getsockname()[1]),
        "PROTO_E_BIND": lambda: serve_call(P, net.free_port(), bind=b"192.0.2.1"),
    }
    # Port 1 binds (no EACCES) when the kernel lets unprivileged users bind every port,
    # as on the Alpine container job, so the case needs a restricted port range.
    if PLATFORM == "linux" and os.geteuid() != 0 and privileged_port_restricted():
        after["PROTO_E_PERM_DENIED"] = lambda: serve_call(P, 1)
    for name, call in after.items():
        eq(outcome(call), ("exit", 3), "SIGPIPE ignored (1) and a SIGCHLD handler (2) after " + name)
    before = {
        "PROTO_E_NO_ALLOWLIST": lambda: serve_call(P, net.free_port(), allowed=None),
        "PROTO_E_BAD_ALLOWLIST": lambda: serve_call(P, net.free_port(), allowed=b"A" * 64),
        "PROTO_E_NO_HANDLER": lambda: serve_call(P, net.free_port(), handler=None),
        "PROTO_E_BAD_ADDRESS": lambda: serve_call(P, net.free_port(), bind=b"nowhere"),
        "PROTO_E_BAD_PORT": lambda: serve_call(P, 0),
        "PROTO_E_PARAM": lambda: serve_call(P, net.free_port(), drain=-1),
    }
    for name, call in before.items():
        eq(outcome(call), ("exit", 0), "the dispositions after " + name)
    runprobe.must_pass("seam_serve", ["dispositions"], seams=runprobe.SERVE_SEAMS, threads=True)


@case("T-352")
def t352():
    """In the child, SIGCHLD is at its default and SIGPIPE is ignored."""
    P = lib.proto()
    ident = make_identity()
    with servers.Server(ident.hex, "child_signals") as srv:
        rc, conn = connect_to(P, ident, srv.port)
        eq(rc, 0, "proto_connect")
        srv.wait_log("raw write returned")
        eq(srv.grep("sigchld default="), ["sigchld default=1"], "SIGCHLD in the child")
        eq(srv.grep("sigpipe ignored="), ["sigpipe ignored=1"], "SIGPIPE in the child")
        line = srv.grep("pclose status=")[0]
        check("exited=1 code=3" in line, "pclose(popen(\"exit 3\")) in the handler: %s" % line)
        check("errno_epipe=1" in srv.grep("raw write returned")[0], "a raw write to a closed peer: %s" % srv.grep("raw write"))
        P.close(conn)


@case("T-353", tags=("seam",))
def t353():
    """The reaper keeps errno."""
    runprobe.must_pass("seam_serve", ["reaper_errno"], seams=runprobe.SERVE_SEAMS, threads=True)


@case("T-354")
def t354():
    """The application's own signal handlers reach the children unchanged."""
    P = lib.proto()
    ident = make_identity()
    with servers.Server(ident.hex, "ok", flags=["--sigusr1-noop"]) as srv:
        rc, conn = connect_to(P, ident, srv.port)
        eq(rc, 0, "proto_connect")
        kids = srv.live_children()
        check(kids, "no child")
        os.kill(kids[0][0], signal.SIGUSR1)               # fatal without the application's handler
        time.sleep(0.2)
        eq(servers.command(P, conn, "PING"), (4, b"PONG"), "the child after SIGUSR1")
        P.close(conn)
