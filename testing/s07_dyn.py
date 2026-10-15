"""VII. proto_recv_line_dyn, proto_recv_line_dyn_status (T-094 to T-111)."""

import ctypes
import os
import random
import socket
import time

import lib
import net
import runprobe
from harness import PIN, case, check, eq, skip


def dyn(P, data, close=False, pace=None):
    f = net.Feed(data, close, pace)
    got, status = P.recv_dyn(f.fd)
    return got, status, f


def too_slow_for_big_cap(P):
    """A 16 MiB line read a byte at a time takes minutes: not for the tiny-chunk builds."""
    if P.macros["MAX_PAYLOAD"] > 1 << 20 and P.macros["READ_CHUNK"] < 4096:
        skip("a %d byte line at READ_CHUNK=%d is too slow" % (P.macros["MAX_PAYLOAD"], P.macros["READ_CHUNK"]))


@case("T-094", variant_safe=True)
def t094():
    """A short line comes back as a heap string, with PROTO_OK."""
    P = lib.proto()
    got, status, _ = dyn(P, b"short line\n")
    eq((got, status), (b"short line", 0), "proto_recv_line_dyn_status (status started at 999)")


@case("T-095", variant_safe=True)
def t095():
    """An empty line is an empty string, not NULL."""
    P = lib.proto()
    got, status, _ = dyn(P, b"\n")
    eq((got, status), (b"", 0), "proto_recv_line_dyn_status")


@case("T-096", variant_safe=True)
def t096():
    """End of stream first is NULL with PROTO_E_PEER_CLOSED."""
    P = lib.proto()
    got, status, _ = dyn(P, b"", close=True)
    eq((got, status), (None, -603), "proto_recv_line_dyn_status")


@case("T-097", variant_safe=True)
def t097():
    """End of stream in the middle of a line discards the partial line."""
    P = lib.proto()
    got, status, _ = dyn(P, b"partial", close=True)
    eq((got, status), (None, -603), "proto_recv_line_dyn_status")


@case("T-098", variant_safe=True)
def t098():
    """Exactly MAX_PAYLOAD characters are accepted."""
    P = lib.proto()
    too_slow_for_big_cap(P)
    M = P.macros["MAX_PAYLOAD"]
    for n in (M - 1, M):
        got, status, f = dyn(P, b"a" * n + b"\n")
        eq(status, 0, "status for a line of %d characters" % n)
        check(got is not None and len(got) == n and got == b"a" * n, "the line of %d characters came back wrong" % n)
        f.finish()


@case("T-099", variant_safe=True)
def t099():
    """MAX_PAYLOAD + 1 characters are refused, and only those are consumed."""
    P = lib.proto()
    too_slow_for_big_cap(P)
    M = P.macros["MAX_PAYLOAD"]
    f = net.Feed(b"a" * (M + 3) + b"\nnext\n")
    got, status = P.recv_dyn(f.fd)
    eq((got, status), (None, -604), "a line of MAX_PAYLOAD + 3 characters")
    got, status = P.recv_dyn(f.fd)
    eq((got, status), (b"aa", 0), "the two characters left after MAX_PAYLOAD + 1 were consumed")
    got, status = P.recv_dyn(f.fd)
    eq((got, status), (b"next", 0), "the stream goes on")
    f.finish()


@case("T-100", variant_safe=True)
def t100():
    """\\r characters do not count toward the cap."""
    P = lib.proto()
    too_slow_for_big_cap(P)
    M = P.macros["MAX_PAYLOAD"]
    step = M // 16
    chunks = [b"a" * step] * 15 + [b"a" * (M - 15 * step)]
    body = b"\r".join(chunks) + b"\r"                    # 16 carriage returns among M characters
    check(body.count(b"a") == M and body.count(b"\r") == 16, "test data is wrong")
    got, status, f = dyn(P, body + b"\n")
    eq(status, 0, "status for %d characters and 16 carriage returns" % M)
    check(got == b"a" * M, "the carriage returns were not dropped")
    f.finish()


@case("T-101")
def t101():
    """The cap is exact however the bytes arrive."""
    for variant in ("pay64", "pay64c1", "pay64c3"):
        P = lib.proto(variant)
        for piece in (1, 3, 1000):
            got, status, f = dyn(P, b"b" * 64 + b"\n", pace=(piece, 0.001))
            eq((got, status), (b"b" * 64, 0), "64 characters, %s, pieces of %d" % (variant, piece))
            f.finish()
            got, status, f = dyn(P, b"b" * 65 + b"\n", pace=(piece, 0.001))
            eq((got, status), (None, -604), "65 characters, %s, pieces of %d" % (variant, piece))
            f.finish()


@case("T-102")
def t102():
    """Pipes work through the fallback, limits included."""
    P = lib.proto("pay64")

    def on_pipe(data, close=True):
        p = net.PipeFeed(data, close)
        return P.recv_dyn(p.fd)

    eq(on_pipe(b"short\n"), (b"short", 0), "a short line")
    eq(on_pipe(b"\n"), (b"", 0), "an empty line")
    eq(on_pipe(b""), (None, -603), "end of stream first")
    eq(on_pipe(b"partial"), (None, -603), "end of stream in a line")
    eq(on_pipe(b"c" * 64 + b"\n"), (b"c" * 64, 0), "exactly the cap")
    eq(on_pipe(b"c" * 65 + b"\n"), (None, -604), "one over the cap")
    eq(on_pipe(b"c" * 70 + b"\nz\n"), (None, -604), "far over the cap")


@case("T-103")
def t103():
    """proto_recv_line_dyn is proto_recv_line_dyn_status without a status."""
    P = lib.proto("pay64")
    inputs = [(b"hello\n", False), (b"\n", False), (b"", True), (b"part", True),
              (b"d" * 64 + b"\n", False), (b"d" * 70 + b"\n", False)]
    for data, close in inputs:
        f1, f2, f3 = (net.Feed(data, close) for _ in range(3))
        a = P.recv_dyn_plain(f1.fd)
        p = P.c_recv_line_dyn_status(f2.fd, None)         # a NULL status never crashes
        b = P._take(p)
        c, _status = P.recv_dyn(f3.fd)
        eq((a, b), (c, c), "results for %r" % data[:12])


@case("T-104", tags=("seam",))
def t104():
    """The buffer starts at 4096 bytes and doubles."""
    runprobe.must_pass("seam_wire", ["dyn_alloc"], seams=runprobe.WIRE_SEAMS, threads=True)


@case("T-105", tags=("seam",))
def t105():
    """Memory is bounded by the cap."""
    runprobe.must_pass("seam_wire", ["dyn_bound"], seams=runprobe.WIRE_SEAMS, threads=True,
                       timeout=120)


@case("T-106", tags=("seam",))
def t106():
    """A failed first malloc is PROTO_E_NOMEM, and nothing is read."""
    runprobe.must_pass("seam_wire", ["malloc_fail"], seams=runprobe.WIRE_SEAMS, threads=True)


@case("T-107", tags=("seam",))
def t107():
    """A failed realloc is PROTO_E_NOMEM, and the buffer is freed."""
    runprobe.must_pass("seam_wire", ["realloc_fail"], seams=runprobe.WIRE_SEAMS, threads=True)


@case("T-108", variant_safe=True)
def t108():
    """A reset is NULL with PROTO_E_READ."""
    P = lib.proto()
    c, s = net.tcp_pair()
    s.sendall(b"partial")
    time.sleep(0.05)
    net.reset_close(s)
    time.sleep(0.05)
    got, status = P.recv_dyn(c.fileno())
    eq((got, status), (None, -602), "proto_recv_line_dyn_status after a reset")


@case("T-109", PIN, variant_safe=True)
def t109():
    """A NUL inside a line ends it, for the caller."""
    P = lib.proto()
    f = net.Feed(b"ab\0cd\n")
    p = P.c_recv_line_dyn(f.fd)
    check(p, "no line")
    try:
        eq(ctypes.string_at(p, 5), b"ab\0cd", "the buffer holds the NUL and what follows")
        eq(ctypes.string_at(p), b"ab", "the caller sees the line end at the NUL")
    finally:
        lib.libc.free(p)


@case("T-110")
def t110():
    """Many lines of random lengths on one stream come back exact."""
    P = lib.proto()
    rnd = random.Random(1010)
    alphabet = b"abcdefghijklmnopqrstuvwxyz"
    lines = []
    for i in range(1000):
        n = rnd.randint(0, 10000)
        rotated = alphabet[i % 26:] + alphabet[:i % 26]
        lines.append((rotated * (n // 26 + 1))[:n])
    f = net.Feed(b"".join(l + b"\n" for l in lines))
    for i, want in enumerate(lines):
        got, status = P.recv_dyn(f.fd)
        if got != want:
            check(False, "line %d came back as %d bytes, want %d" % (i, -1 if got is None else len(got), len(want)))
    f.finish()


@case("T-111", variant_safe=True)
def t111():
    """The fixed and the heap readers mix on one stream."""
    P = lib.proto()
    cap = P.macros["MAX_PAYLOAD"]                     # rows must fit the cap of every build
    rows = [b"1", b"r" * min(5000, cap), b"s" * min(20000, cap)]
    f = net.Feed(b"ENTRIES 3\n" + b"".join(r + b"\n" for r in rows) + b"END\n")
    eq(P.recv_line(f.fd, 64), (9, b"ENTRIES 3"), "the header")
    for i, want in enumerate(rows):
        got, status = P.recv_dyn(f.fd)
        eq((got, status), (want, 0), "row %d" % (i + 1))
    eq(P.recv_line(f.fd, 64), (3, b"END"), "the line after the rows")
