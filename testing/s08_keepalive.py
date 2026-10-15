"""VIII. proto_keepalive (T-112 to T-122)."""

import ctypes
import os
import shutil
import socket
import subprocess
import time

import harness
import lib
import net
from harness import PIN, PLATFORM, case, check, eq, skip

INT_MAX = 2 ** 31 - 1


def idle_option():
    for name in ("TCP_KEEPIDLE", "TCP_KEEPALIVE"):
        if hasattr(socket, name):
            return getattr(socket, name)
    skip("this Python knows neither TCP_KEEPIDLE nor TCP_KEEPALIVE")


def knobs(sock):
    return (sock.getsockopt(socket.IPPROTO_TCP, idle_option()),
            sock.getsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL),
            sock.getsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT))


def keepalive_on(sock):
    return sock.getsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE)


_peers = []         # the accepted ends stay open for the life of the case


def tcp():
    c, s = net.tcp_pair()
    _peers.append(s)
    return c


@case("T-112")
def t112():
    """On a TCP socket, the three knobs are set and read back."""
    P = lib.proto()
    c = tcp()
    eq(P.keepalive(c.fileno(), 10, 5, 3), 0, "proto_keepalive(10, 5, 3)")
    check(keepalive_on(c), "SO_KEEPALIVE is off")
    eq(knobs(c), (10, 5, 3), "idle, interval and count")
    for opt in (socket.SO_RCVTIMEO, socket.SO_SNDTIMEO):
        check(c.getsockopt(socket.SOL_SOCKET, opt, 16) == b"\0" * 16, "a socket timeout was set: keepalive is not a read timeout")


@case("T-113")
def t113():
    """Zero or negative values mean "system default"."""
    P = lib.proto()
    default = knobs(tcp())
    for args in ((0, 0, 0), (-1, -1, -1)):
        c = tcp()
        eq(P.keepalive(c.fileno(), *args), 0, "proto_keepalive%r" % (args,))
        check(keepalive_on(c), "SO_KEEPALIVE is off after %r" % (args,))
        eq(knobs(c), default, "knobs after %r" % (args,))


@case("T-114")
def t114():
    """One positive value changes one knob."""
    P = lib.proto()
    default = knobs(tcp())
    c = tcp()
    eq(P.keepalive(c.fileno(), 0, 5, 0), 0, "proto_keepalive(0, 5, 0)")
    eq(knobs(c), (default[0], 5, default[2]), "only the interval changes")


@case("T-115")
def t115():
    """Not a socket is PROTO_E_KEEPALIVE."""
    P = lib.proto()
    r, w = os.pipe()
    eq(P.keepalive(r, 10, 5, 3), -508, "a pipe")
    eq(P.keepalive(-1, 10, 5, 3), -508, "fd -1")
    f = os.open(harness.__file__, os.O_RDONLY)
    eq(P.keepalive(f, 10, 5, 3), -508, "a regular file")
    for fd in (r, w, f):
        os.fstat(fd)                                  # still open
    c = tcp()
    P.keepalive(c.fileno(), 10, 5, 3)
    os.fstat(c.fileno())


@case("T-116", PIN)
def t116():
    """An AF_UNIX socket gets PROTO_KEEPALIVE_DEFAULTED on macOS."""
    P = lib.proto()
    a, b = net.sockpair()
    rc = P.keepalive(a.fileno(), 10, 5, 3)
    if PLATFORM in ("macos", "linux"):
        # macOS observed; Linux reasoned: the generic SO_KEEPALIVE is accepted,
        # and the TCP level options have no handler on a Unix socket.
        eq(rc, 2, "proto_keepalive on a Unix-domain socket")
        check(keepalive_on(a), "SO_KEEPALIVE is off")
    else:
        harness.note("%s: proto_keepalive on AF_UNIX gave %d" % (PLATFORM, rc))
        skip("no baseline recorded for %s: it gave %d" % (PLATFORM, rc))


@case("T-117", PIN)
def t117():
    """Out-of-range knobs: one expectation per platform."""
    P = lib.proto()
    socks = []

    def call(idle, intvl, count):
        c = tcp()
        socks.append(c)                               # keep the socket open for the call
        return P.keepalive(c.fileno(), idle, intvl, count)

    if PLATFORM == "macos":
        eq(call(40000, 0, 0), 0, "idle 40000 s")
        eq(call(0, 0, 1000), 0, "count 1000")
        eq(call(INT_MAX, 0, 0), 2, "idle INT_MAX")
    elif PLATFORM == "linux":
        eq(call(32767, 32767, 127), 0, "the largest values the kernel takes")
        eq(call(40000, 0, 0), 2, "idle 40000 s")
        eq(call(0, 40000, 0), 2, "interval 40000 s")
        eq(call(0, 0, 1000), 2, "count 1000")
    else:
        skip("no baseline recorded for %s" % PLATFORM)


@case("T-118")
def t118():
    """PROTO_KEEPALIVE_DEFAULTED leaves probing on."""
    P = lib.proto()
    c = tcp()
    eq(P.keepalive(c.fileno(), INT_MAX, 7, 3), 2, "proto_keepalive with an idle time no system takes")
    check(keepalive_on(c), "SO_KEEPALIVE is off after PROTO_KEEPALIVE_DEFAULTED")
    idle, intvl, cnt = knobs(c)
    eq((intvl, cnt), (7, 3), "the knobs that were accepted hold their values")


@case("T-119")
def t119():
    """A second call replaces the first."""
    P = lib.proto()
    c = tcp()
    eq(P.keepalive(c.fileno(), 10, 5, 3), 0, "first call")
    eq(P.keepalive(c.fileno(), 20, 6, 4), 0, "second call")
    eq(knobs(c), (20, 6, 4), "the new values hold")


def run_ok(cmd):
    return subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT).returncode == 0


@case("T-120", tags=("linux", "root", "slow"))
def t120():
    """A peer that vanishes is detected."""
    P = lib.proto()
    CLONE_NEWNET = 0x40000000
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.unshare(CLONE_NEWNET) != 0:
        skip("cannot create a network namespace: errno %d" % ctypes.get_errno())
    if shutil.which("ip"):
        run_ok(["ip", "link", "set", "lo", "up"])
    nft = shutil.which("nft")
    ipt = shutil.which("iptables")
    if not nft and not ipt:
        skip("neither nft nor iptables is installed")
    ls = net.listener()
    c = socket.create_connection(ls.getsockname())
    s, _ = ls.accept()
    eq(P.keepalive(c.fileno(), 1, 1, 2), 0, "proto_keepalive(1, 1, 2)")
    if nft:
        ok = (run_ok([nft, "add", "table", "inet", "proto"])
              and run_ok([nft, "add", "chain", "inet", "proto", "in",
                          "{ type filter hook input priority 0 ; }"])
              and run_ok([nft, "add", "rule", "inet", "proto", "in", "drop"]))
    else:
        ok = run_ok([ipt, "-A", "INPUT", "-j", "DROP"])
    if not ok:
        skip("cannot install a drop rule")
    t0 = net.now()
    rc, text = P.recv_line(c.fileno(), 16)
    took = net.ms_since(t0)
    eq(rc, -602, "a blocked proto_recv_line once the peer's packets are dropped")
    check(took < 8000, "keepalive took %.0f ms to notice" % took)
