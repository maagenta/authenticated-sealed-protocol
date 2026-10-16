"""IV. proto_send_line, proto_send_prefixed (T-037 to T-051)."""

import os
import signal
import socket

import harness
import lib
import net
import runprobe
from harness import FINDING, PIN, case, check, eq, in_child, skip, slack_ms

SEND_LINE_BAD_FD = -601


def pair():
    a, b = net.sockpair()
    return a, b, net.Peer(b)


@case("T-037")
def t037():
    """proto_send_line writes the line and a newline, nothing else."""
    P = lib.proto()
    a, b, peer = pair()
    eq(P.send_line(a.fileno(), "OK"), 0, "proto_send_line")
    eq(peer.recv_exact(3), b"OK\n", "bytes on the wire")
    check(peer.silent_for(0.1), "more than OK\\n was written")


@case("T-038")
def t038():
    """An empty line writes just a newline."""
    P = lib.proto()
    a, b, peer = pair()
    eq(P.send_line(a.fileno(), ""), 0, "proto_send_line")
    eq(peer.recv_exact(1), b"\n", "bytes on the wire")
    check(peer.silent_for(0.1), "more than a newline was written")


@case("T-039")
def t039():
    """proto_send_prefixed writes the prefix, exactly body_len bytes, and a newline."""
    P = lib.proto()
    a, b, peer = pair()
    eq(P.send_prefixed(a.fileno(), "PUT ", b"abcdef", 3), 0, "short body")
    eq(peer.recv_line(), b"PUT abc", "only n bytes of the body are sent")
    eq(P.send_prefixed(a.fileno(), "PUT ", b"a\0b\0c", 5), 0, "body with NULs")
    eq(peer.recv_line(), b"PUT a\0b\0c", "NUL bytes go out as they are")
    eq(P.send_prefixed(a.fileno(), "PUT", b"abc"), 0, "no space added")
    eq(peer.recv_line(), b"PUTabc", "the prefix goes out as given")
    big = (b"0123456789abcdef" * 65536)[:1024 * 1024]
    w = net.Worker(lambda: P.send_prefixed(a.fileno(), "PUT ", big))
    eq(peer.recv_line(30), b"PUT " + big, "a 1 MiB body arrives whole")
    eq(w.finish(), 0, "send of the large body")


@case("T-040")
def t040():
    """A zero-length body never touches the pointer."""
    P = lib.proto()
    a, b, peer = pair()
    eq(P.send_prefixed(a.fileno(), "PING", None, 0), 0, "NULL body")
    eq(peer.recv_exact(5), b"PING\n", "bytes on the wire")


@case("T-041")
def t041():
    """An empty prefix writes the body and a newline."""
    P = lib.proto()
    a, b, peer = pair()
    eq(P.send_prefixed(a.fileno(), "", b"body"), 0, "empty prefix")
    eq(peer.recv_exact(5), b"body\n", "bytes on the wire")


@case("T-042", tags=("seam",))
def t042():
    """Short writes are resumed."""
    runprobe.must_pass("seam_wire", ["short_write"], seams=runprobe.WIRE_SEAMS, threads=True)


@case("T-043", timeout=120)
def t043():
    """A signal during a large write neither fails it nor repeats bytes."""
    P = lib.proto()
    a, b = net.sockpair()
    a.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4096)
    size = 8 * 1024 * 1024
    line = bytes(range(97, 123)) * (size // 26 + 1)
    line = line[:size]
    got = bytearray()

    def drain():
        while len(got) < size + 1:
            data = b.recv(65536)
            if not data:
                break
            got.extend(data)
    # A fast machine moves 8 MiB before the storm has sent a handful of signals (5 on a macOS arm64
    # runner): send again until it has interrupted the write often enough to mean something.
    rounds = 0
    with net.SignalStorm(signal.SIGUSR1, 0.001) as storm:
        while storm.sent <= 20 and rounds < 100:
            del got[:]
            reader = net.Worker(drain)
            rc = P.send_line(a.fileno(), line)
            reader.finish(60)
            rounds += 1
            eq(rc, 0, "proto_send_line under a signal storm (round %d)" % rounds)
            check(bytes(got) == line + b"\n", "the bytes on the wire differ from the line (got %d, want %d)"
                  % (len(got), size + 1))
    check(storm.sent > 20, "the storm sent only %d signals in %d rounds" % (storm.sent, rounds))
    harness.note("%d signals in %d rounds of 8 MiB" % (storm.sent, rounds))


def sigpipe_default():
    signal.signal(signal.SIGPIPE, signal.SIG_DFL)


@case("T-044")
def t044():
    """Writing to a closed peer returns PROTO_E_WRITE, not SIGPIPE."""
    P = lib.proto()
    sigpipe_default()
    a, b = net.sockpair()
    b.close()
    fd = a.fileno()
    eq(P.send_line(fd, "x"), -601, "proto_send_line")
    eq(P.send_prefixed(fd, "PUT ", b"body"), -601, "proto_send_prefixed")
    os.fstat(fd)                                   # still open: the library never closes on error


@case("T-045")
def t045():
    """A peer that closes in the middle of a send is a failure."""
    P = lib.proto()
    sigpipe_default()
    a, b = net.sockpair()
    size = 8 * 1024 * 1024

    def reader():
        got = 0
        while got < 100 * 1024:
            data = b.recv(65536)
            if not data:
                break
            got += len(data)
        b.close()
    t = net.Worker(reader)
    rc = P.send_line(a.fileno(), b"x" * size)
    t.finish()
    eq(rc, -601, "proto_send_line interrupted by a close")


@case("T-046")
def t046():
    """The client's signal dispositions are untouched."""
    P = lib.proto()
    sigpipe_default()
    a, b = net.sockpair()
    b.close()
    eq(P.send_line(a.fileno(), "x"), -601, "proto_send_line")

    def raw_write():                                  # a plain send, with SIGPIPE at its default
        a.send(b"y")
    how, code = in_child(raw_write)
    check(how == "signal" and code == signal.SIGPIPE,
          "after the library wrote, a raw send to a closed peer ended with %s %s, not SIGPIPE" % (how, code))


@case("T-047")
def t047():
    """A bad descriptor returns PROTO_E_WRITE."""
    P = lib.proto()
    sigpipe_default()
    eq(P.send_line(-1, "x"), -601, "fd -1")
    a, b = net.sockpair()
    fd = a.detach()
    os.close(fd)
    eq(P.send_line(fd, "x"), -601, "closed fd")
    eq(P.send_prefixed(-1, "x", b"y"), -601, "proto_send_prefixed on fd -1")


@case("T-048", PIN)
def t048():
    """A non-blocking socket with a full send buffer returns PROTO_E_WRITE."""
    P = lib.proto()
    a, b = net.sockpair()
    net.set_nonblocking(a.fileno())
    try:
        while True:
            a.send(b"x" * 65536)
    except BlockingIOError:
        pass
    t0 = net.now()
    rc = P.send_line(a.fileno(), "y" * 100)
    took = net.ms_since(t0)
    eq(rc, -601, "proto_send_line on a full non-blocking socket")
    check(took < 1000 + slack_ms(1000), "the call took %.0f ms: it spins" % took)


@case("T-049", PIN)
def t049():
    """A line that contains \\n goes out as it is."""
    P = lib.proto()
    a, b, peer = pair()
    eq(P.send_line(a.fileno(), "first\nsecond"), 0, "proto_send_line")
    eq(peer.recv_line(), b"first", "first line")
    eq(peer.recv_line(), b"second", "the embedded newline made a second line")


@case("T-050", FINDING)
def t050():
    """A pipe can be written as well as read."""
    P = lib.proto()
    r, w = os.pipe()
    rc = P.send_line(w, "hello")
    eq(rc, 0, "proto_send_line on a pipe")
    eq(os.read(r, 100), b"hello\n", "bytes in the pipe")


@case("T-051", FINDING)
def t051():
    """A NULL line is refused, not dereferenced."""
    P = lib.proto()
    a, b, peer = pair()
    eq(P.c_send_line(a.fileno(), None), -101, "proto_send_line(fd, NULL)")
    eq(P.c_send_prefixed(a.fileno(), None, b"x", 1), -101, "proto_send_prefixed(fd, NULL, ...)")
