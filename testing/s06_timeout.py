"""VI. proto_recv_line_timeout (T-080 to T-093)."""

import os
import signal
import socket
import time

import harness
import lib
import net
from harness import PIN, case, check, eq, slack_ms

INT_MAX = 2 ** 31 - 1
INT_MIN = -2 ** 31


def timed(P, fd, ms, bufsz=64):
    t0 = net.now()
    rc, text = P.recv_line_timeout(fd, ms, bufsz)
    return rc, text, net.ms_since(t0)


def window(took, lo, what):
    check(net.in_window(took, lo), "%s took %.0f ms, outside [%d, %d]" % (what, took, lo, lo + slack_ms(250)))


@case("T-080", variant_safe=True)
def t080():
    """A line already waiting is returned at once."""
    P = lib.proto()
    f = net.Feed(b"waiting\n")
    f.finish()                                    # the whole line is in the socket
    rc, text, took = timed(P, f.fd, 1000)
    eq((rc, text), (7, b"waiting"), "proto_recv_line_timeout")
    check(took < 250 + slack_ms(250), "it waited %.0f ms for a line that was there" % took)


@case("T-081", variant_safe=True)
def t081():
    """A silent peer is PROTO_E_TIMEOUT at the deadline."""
    P = lib.proto()
    a, b = net.sockpair()
    rc, text, took = timed(P, b.fileno(), 300)
    eq((rc, text), (-605, b""), "proto_recv_line_timeout")
    window(took, 300, "the deadline")


@case("T-082", variant_safe=True)
def t082():
    """The deadline covers the line, not each byte."""
    P = lib.proto()
    data = b"abcdefghijklmnopqrstuvwxyz\n"
    f = net.Feed(data, pace=(1, 0.05))
    rc, text, took = timed(P, f.fd, 300)
    eq(rc, -605, "proto_recv_line_timeout with a byte every 50 ms")
    window(took, 300, "the deadline")
    check(0 < len(text) < len(data) - 5, "buf holds %r" % text)
    f.finish()
    time.sleep(0.05)
    rest = f.b.recv(1000, socket.MSG_DONTWAIT)
    check(text + rest == data, "the bytes consumed plus the bytes left are not the line: %r + %r" % (text, rest))


@case("T-083", variant_safe=True)
def t083():
    """Signals do not stretch the deadline."""
    P = lib.proto()
    a, b = net.sockpair()
    with net.SignalStorm(signal.SIGUSR1, 0.01) as storm:
        rc, text, took = timed(P, b.fileno(), 300)
    eq(rc, -605, "proto_recv_line_timeout under signals")
    window(took, 300, "the deadline under signals")
    # The storm is a thread that a loaded runner may starve for a while: a few
    # signals landing inside the wait is what the test needs, not a rate.
    check(storm.sent >= 2, "only %d signals were sent" % storm.sent)


@case("T-084", variant_safe=True)
def t084():
    """Nor do signals cut the deadline short."""
    P = lib.proto()
    a, b = net.sockpair()
    # The clock starts before the sender does: its 150 ms sleep then lies inside
    # what is measured, however slowly a loaded or emulated host starts the thread.
    t0 = net.now()
    sender = net.Worker(lambda: (time.sleep(0.15), a.sendall(b"on time\n")))
    with net.SignalStorm(signal.SIGUSR1, 0.01):
        rc, text = P.recv_line_timeout(b.fileno(), 1000)
    took = net.ms_since(t0)
    sender.finish()
    eq((rc, text), (7, b"on time"), "proto_recv_line_timeout under signals")
    check(took >= 140, "returned after %.0f ms, before the line was sent" % took)


@case("T-085", variant_safe=True)
def t085():
    """ms < 0 means no deadline."""
    P = lib.proto()
    pairs = [net.sockpair() for _ in range(2)]
    senders = [net.Worker(lambda a=a: (time.sleep(1.5), a.sendall(b"patience\n"))) for a, b in pairs]
    readers = [net.Worker(lambda b=b, ms=ms: timed(P, b.fileno(), ms)) for (a, b), ms in zip(pairs, (-1, INT_MIN))]
    for ms, r in zip((-1, INT_MIN), readers):
        rc, text, took = r.finish(20)
        eq((rc, text), (8, b"patience"), "proto_recv_line_timeout(ms=%d)" % ms)
        check(took >= 1400, "ms=%d returned after %.0f ms" % (ms, took))
    [s.finish() for s in senders]


@case("T-086", PIN, variant_safe=True)
def t086():
    """ms == 0 is PROTO_E_TIMEOUT even when a whole line is waiting."""
    P = lib.proto()
    f = net.Feed(b"line\n")
    f.finish()                                    # the whole line is waiting
    eq(P.recv_line_timeout(f.fd, 0)[0], -605, "ms == 0 with a line waiting")
    # ms == 1 reads it; a millisecond tick between two clock reads may still
    # time it out. Where READ_CHUNK is shorter than the line, the timeout can
    # fall after the first chunk: the bytes consumed come back in text and are
    # not returned again, so they are put together.
    got = b""
    for attempt in range(5):
        rc, text = P.recv_line_timeout(f.fd, 1)
        got += text
        if rc != -605:
            break
    check(rc >= 0 and got == b"line",
          "ms == 1 reads the line that ms == 0 left: got (%d, %r), want the line" % (rc, got))


@case("T-087", variant_safe=True)
def t087():
    """ms = INT_MAX does not overflow the deadline."""
    P = lib.proto()
    f = net.Feed(b"max\n")
    f.finish()
    rc, text, took = timed(P, f.fd, INT_MAX)
    eq((rc, text), (3, b"max"), "proto_recv_line_timeout")


@case("T-088", variant_safe=True)
def t088():
    """The deadline wins over a full buffer."""
    P = lib.proto()
    f = net.Feed(b"abcd")
    t0 = net.now()
    rc, text = P.recv_line_timeout(f.fd, 200, 5)
    eq((rc, text), (-605, b"abcd"), "a full buffer with a quiet peer")
    window(net.ms_since(t0), 200, "the deadline")


@case("T-089", variant_safe=True)
def t089():
    """A close during the wait is reported at once."""
    P = lib.proto()
    a, b = net.sockpair()
    closer = net.Worker(lambda: (time.sleep(0.1), a.close()))
    rc, text, took = timed(P, b.fileno(), 5000)
    closer.finish()
    eq(rc, -603, "proto_recv_line_timeout when the peer closes")
    check(took < 1000 + slack_ms(1000), "it waited %.0f ms of a 5000 ms deadline" % took)


@case("T-090", variant_safe=True)
def t090():
    """An oversized line under a deadline is refused at once."""
    P = lib.proto()
    f = net.Feed(b"abcdefgh")
    t0 = net.now()
    rc, text = P.recv_line_timeout(f.fd, 5000, 5)
    eq(rc, -604, "an oversized line")
    check(net.ms_since(t0) < 1000 + slack_ms(1000), "it waited for the deadline")


@case("T-091", variant_safe=True)
def t091():
    """Pipes honour the deadline."""
    P = lib.proto()
    r, w = os.pipe()
    rc, text, took = timed(P, r, 200)
    eq(rc, -605, "a silent pipe")
    window(took, 200, "the deadline on a pipe")
    p = net.PipeFeed(b"from a pipe\n")
    rc, text, took = timed(P, p.fd, 1000)
    eq((rc, text), (11, b"from a pipe"), "a pipe holding a line")


@case("T-092", PIN, variant_safe=True)
def t092():
    """Under a deadline a closed descriptor fails at once, but fd -1 waits."""
    P = lib.proto()
    a, b = net.sockpair()
    fd = b.detach()
    os.close(fd)
    rc, text, took = timed(P, fd, 300)
    eq(rc, -602, "a closed descriptor under a deadline")
    check(took < 150 + slack_ms(250), "it waited %.0f ms" % took)
    rc, text, took = timed(P, -1, 300)
    eq(rc, -605, "fd -1 under a deadline")
    window(took, 300, "the deadline on fd -1")
    eq(P.recv_line(-1, 16)[0], -602, "fd -1 without a deadline")


@case("T-093", tags=("root",))
def t093():
    """The deadline runs on the monotonic clock."""
    P = lib.proto()
    a, b = net.sockpair()
    state = {"jumped": False}

    def jump():
        time.sleep(0.1)
        time.clock_settime(time.CLOCK_REALTIME, time.time() - 3600)
        state["jumped"] = True
    t = net.Worker(jump)
    try:
        rc, text, took = timed(P, b.fileno(), 500)
        t.finish()
    finally:
        if state["jumped"]:                       # put the wall clock back
            time.clock_settime(time.CLOCK_REALTIME, time.time() + 3600)
    eq(rc, -605, "proto_recv_line_timeout across a clock change")
    window(took, 500, "the deadline across a clock change")
