"""V. proto_recv_line (T-052 to T-079)."""

import os
import signal
import socket
import time

import harness
import lib
import net
import runprobe
from harness import PIN, case, check, eq, in_child, slack_ms


def fed(data, close=False):
    return net.Feed(data, close)


def read(P, fd, bufsz, **kw):
    return P.recv_line(fd, bufsz, **kw)


@case("T-052", variant_safe=True)
def t052():
    """A line is returned without its newline."""
    P = lib.proto()
    f = fed(b"hello\n")
    eq(read(P, f.fd, 64), (5, b"hello"), "proto_recv_line")


@case("T-053", variant_safe=True)
def t053():
    """An empty line is a valid message."""
    P = lib.proto()
    f = fed(b"\n\n\n")
    for i in range(3):
        eq(read(P, f.fd, 8), (0, b""), "empty line %d" % (i + 1))


@case("T-054", variant_safe=True)
def t054():
    """A \\r before the newline is dropped."""
    P = lib.proto()
    f = fed(b"abc\r\n")
    eq(read(P, f.fd, 16), (3, b"abc"), "proto_recv_line")


@case("T-055", PIN, variant_safe=True)
def t055():
    """Every \\r is dropped, not only the one before the newline."""
    P = lib.proto()
    f = fed(b"a\rb\r\n")
    eq(read(P, f.fd, 16), (2, b"ab"), "proto_recv_line")


@case("T-056", PIN, variant_safe=True)
def t056():
    """A NUL inside a line is kept."""
    P = lib.proto()
    f = fed(b"ab\0cd\n")
    rc, raw = P.recv_line_raw(f.fd, 16)
    eq(rc, 5, "length")
    eq(raw[:5], b"ab\0cd", "the NUL and what follows are kept")
    eq(lib.cstr(raw), b"ab", "strlen sees the line end at the NUL")


@case("T-057", variant_safe=True)
def t057():
    """A line that exactly fills the buffer fits."""
    P = lib.proto()
    f = fed(b"abcd\nxy\n")
    eq(read(P, f.fd, 5), (4, b"abcd"), "exact fit")
    eq(read(P, f.fd, 5), (2, b"xy"), "the next line reads intact")


@case("T-058", variant_safe=True)
def t058():
    """A \\r at the limit is not a character."""
    P = lib.proto()
    f = fed(b"abcd\r\n")
    eq(read(P, f.fd, 5), (4, b"abcd"), "proto_recv_line")


@case("T-059", variant_safe=True)
def t059():
    """One character over is PROTO_E_LINE_TOO_LONG, and the rest stays unread."""
    P = lib.proto()
    f = fed(b"abcde\nnext\n")
    eq(read(P, f.fd, 5), (-604, b"abcd"), "one character over")
    eq(read(P, f.fd, 5), (0, b""), "exactly one more character was consumed: the rest is empty")
    eq(read(P, f.fd, 8), (4, b"next"), "the stream goes on")


@case("T-060", variant_safe=True)
def t060():
    """An exact fit followed by end of stream is PROTO_E_PEER_CLOSED."""
    P = lib.proto()
    f = fed(b"abcd", close=True)
    eq(read(P, f.fd, 5), (-603, b"abcd"), "proto_recv_line")


@case("T-061", variant_safe=True)
def t061():
    """A one-byte buffer holds only empty lines."""
    P = lib.proto()
    eq(read(P, fed(b"\n").fd, 1), (0, b""), "newline")
    eq(read(P, fed(b"a\n").fd, 1), (-604, b""), "one character")
    eq(read(P, fed(b"\r\r\r\n").fd, 1), (0, b""), "carriage returns only")


@case("T-062", variant_safe=True)
def t062():
    """bufsz == 0 returns PROTO_E_PARAM and writes nothing."""
    P = lib.proto()
    f = fed(b"abc\n")
    eq(P.c_recv_line(f.fd, None, 0), -101, "NULL buffer, bufsz 0")
    rc, raw = P.recv_line_raw(f.fd, 4)
    eq(rc, 3, "the line is still there")
    import ctypes
    buf = ctypes.create_string_buffer(b"ZZZZ")
    eq(P.c_recv_line(f.fd, buf, 0), -101, "bufsz 0")
    eq(buf.raw, b"ZZZZ\0", "the buffer was touched")


@case("T-063", PIN)
def t063():
    """buf == NULL with bufsz > 0 crashes."""
    P = lib.proto()
    f = fed(b"abc\n")
    how, code = in_child(lambda: P.c_recv_line(f.fd, None, 16))
    check(how == "signal" and code in (signal.SIGSEGV, signal.SIGBUS),
          "a NULL buffer no longer crashes (%s %s): decide with T-051" % (how, code))


@case("T-064", variant_safe=True)
def t064():
    """End of stream before any byte is PROTO_E_PEER_CLOSED."""
    P = lib.proto()
    f = fed(b"", close=True)
    eq(read(P, f.fd, 16), (-603, b""), "proto_recv_line")


@case("T-065", variant_safe=True)
def t065():
    """End of stream in the middle of a line is PROTO_E_PEER_CLOSED, with the partial line."""
    P = lib.proto()
    f = fed(b"abc", close=True)
    eq(read(P, f.fd, 16), (-603, b"abc"), "proto_recv_line")


@case("T-066", variant_safe=True)
def t066():
    """A reset is PROTO_E_READ."""
    P = lib.proto()
    c, s = net.tcp_pair()
    net.reset_close(s)
    time.sleep(0.05)
    rc, text = read(P, c.fileno(), 16)
    eq(rc, -602, "proto_recv_line after a reset")


@case("T-067", variant_safe=True)
def t067():
    """A bad descriptor is PROTO_E_READ."""
    P = lib.proto()
    rc, raw = P.recv_line_raw(-1, 16)
    eq(rc, -602, "fd -1")
    eq(raw[0], 0, "buf is NUL-terminated")
    a, b = net.sockpair()
    fd = b.detach()
    os.close(fd)
    rc, raw = P.recv_line_raw(fd, 16)
    eq(rc, -602, "closed fd")
    eq(raw[0], 0, "buf is NUL-terminated")


@case("T-068", variant_safe=True)
def t068():
    """Nothing of the next line is taken, on a socket."""
    P = lib.proto()
    f = fed(b"one\ntwo\nthree")
    time.sleep(0.05)
    eq(read(P, f.fd, 16), (3, b"one"), "first line")
    eq(f.b.recv(100, socket.MSG_DONTWAIT), b"two\nthree", "what a raw recv still finds")


@case("T-069", variant_safe=True)
def t069():
    """Nothing of the next line is taken, on a pipe."""
    P = lib.proto()
    p = net.PipeFeed(b"one\ntwo\n")
    eq(read(P, p.fd, 16), (3, b"one"), "first line")
    eq(os.read(p.fd, 100), b"two\n", "what a raw read still finds")


@case("T-070", variant_safe=True)
def t070():
    """A line that trickles in is assembled."""
    P = lib.proto()
    f = net.Feed(b"trickle\n", pace=(1, 0.005))
    t0 = net.now()
    rc, text = read(P, f.fd, 32)
    took = net.ms_since(t0)
    eq((rc, text), (7, b"trickle"), "proto_recv_line")
    check(took >= 25, "returned after %.0f ms, before the newline could have arrived" % took)
    f.finish()


@case("T-071", variant_safe=True)
def t071():
    """Three lines in one segment are read separately."""
    P = lib.proto()
    f = fed(b"a\nb\nc\n")
    eq([read(P, f.fd, 8) for _ in range(3)], [(1, b"a"), (1, b"b"), (1, b"c")], "three lines")


@case("T-072", tags=("seam",))
def t072():
    """On a pipe, the peek is tried once per line."""
    runprobe.must_pass("seam_wire", ["pipe_peek"], seams=runprobe.WIRE_SEAMS, threads=True)


@case("T-073", tags=("seam",))
def t073():
    """On a socket, a large line costs a few calls, not one per byte."""
    runprobe.must_pass("seam_wire", ["big_line"], seams=runprobe.WIRE_SEAMS, threads=True)


@case("T-074", variant_safe=True)
def t074():
    """A signal does not fail a blocked read."""
    P = lib.proto()
    a, b = net.sockpair()
    sender = net.Worker(lambda: (time.sleep(0.3), a.sendall(b"late line\n")))
    with net.SignalStorm(signal.SIGUSR1, 0.005) as storm:
        rc, text = read(P, b.fileno(), 32)
    sender.finish()
    eq((rc, text), (9, b"late line"), "proto_recv_line under signals")
    check(storm.sent > 5, "only %d signals were sent" % storm.sent)


@case("T-075", PIN, variant_safe=True)
def t075():
    """A non-blocking socket with nothing to read is PROTO_E_READ."""
    P = lib.proto()
    a, b = net.sockpair()
    net.set_nonblocking(b.fileno())
    t0 = net.now()
    rc, text = read(P, b.fileno(), 16)
    eq(rc, -602, "proto_recv_line")
    check(net.ms_since(t0) < 500 + slack_ms(500), "it blocked on a non-blocking socket")


@case("T-076", PIN, variant_safe=True)
def t076():
    """An application's SO_RCVTIMEO becomes PROTO_E_READ."""
    P = lib.proto()
    a, b = net.sockpair()
    b.setsockopt(socket.SOL_SOCKET, socket.SO_RCVTIMEO, net.timeval(100))
    t0 = net.now()
    rc, text = read(P, b.fileno(), 16)
    took = net.ms_since(t0)
    eq(rc, -602, "proto_recv_line on a socket with SO_RCVTIMEO (not PROTO_E_TIMEOUT)")
    check(80 <= took <= 100 + slack_ms(400), "it returned after %.0f ms" % took)


@case("T-077", variant_safe=True)
def t077():
    """Every byte value except \\n and \\r passes unchanged."""
    P = lib.proto()
    line = bytes(v for v in range(256) if v not in (10, 13))
    f = fed(line + b"\n")
    rc, raw = P.recv_line_raw(f.fd, 300)
    eq(rc, 254, "length")
    check(raw[:254] == line, "bytes changed on the way")
    f2 = fed(b" \n")
    eq(read(P, f2.fd, 8), (1, b" "), "a line of one space")


@case("T-078", variant_safe=True)
def t078():
    """The handshake's own buffer holds 16383 characters."""
    P = lib.proto()
    n = P.macros["MAX_LINE"]
    f = net.Feed(b"a" * (n - 1) + b"\n")
    eq(read(P, f.fd, n), (n - 1, b"a" * (n - 1)), "a line of MAX_LINE - 1")
    f2 = net.Feed(b"a" * n + b"\n")
    rc, text = read(P, f2.fd, n)
    eq(rc, -604, "a line of MAX_LINE characters")


@case("T-079", variant_safe=True)
def t079():
    """buf is NUL-terminated on every way out."""
    P = lib.proto()

    def ends_at(raw, text):
        return raw[:len(text)] == text and raw[len(text)] == 0

    f = fed(b"abcde\n")
    rc, raw = P.recv_line_raw(f.fd, 5)
    eq(rc, -604, "too long")
    check(ends_at(raw, b"abcd"), "not terminated after PROTO_E_LINE_TOO_LONG: %r" % raw)

    f = fed(b"ab", close=True)
    rc, raw = P.recv_line_raw(f.fd, 16)
    eq(rc, -603, "closed")
    check(ends_at(raw, b"ab") and raw[3:] == b"Z" * 13, "not terminated after PROTO_E_PEER_CLOSED: %r" % raw)

    rc, raw = P.recv_line_raw(-1, 16)
    eq(rc, -602, "bad fd")
    check(ends_at(raw, b"") and raw[1:] == b"Z" * 15, "not terminated after PROTO_E_READ: %r" % raw)

    a, b = net.sockpair()
    rc, raw = P.recv_line_timeout_raw(b.fileno(), 50, 16)
    eq(rc, -605, "silence")
    check(ends_at(raw, b"") and raw[1:] == b"Z" * 15, "not terminated after PROTO_E_TIMEOUT: %r" % raw)
