"""Sockets, threads and descriptors for the tests, peer side."""

import errno
import fcntl
import os
import resource
import select
import signal
import socket
import struct
import sys
import threading
import time

from harness import Fail, slack_ms


def now():
    return time.monotonic()


def ms_since(t0):
    return (time.monotonic() - t0) * 1000.0


def free_port(addr="127.0.0.1"):
    """A port nobody listens on: bind to 0, read it back, close."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.bind((addr, 0))
        return s.getsockname()[1]
    finally:
        s.close()


def listener(addr="127.0.0.1", port=0, backlog=16, family=socket.AF_INET):
    s = socket.socket(family, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((addr, port))
    s.listen(backlog)
    return s


def tcp_pair():
    """Two connected TCP sockets on the loopback: (client, accepted)."""
    ls = listener()
    try:
        c = socket.create_connection(ls.getsockname())
        s, _ = ls.accept()
    finally:
        ls.close()
    return c, s


def sockpair():
    return socket.socketpair()


def reset_close(sock):
    """Close so that the peer sees a reset, not an orderly end of stream."""
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
    sock.close()


def open_fds():
    """The descriptors this process holds."""
    limit = min(resource.getrlimit(resource.RLIMIT_NOFILE)[0], 1024)
    held = []
    for fd in range(limit):
        try:
            fcntl.fcntl(fd, fcntl.F_GETFD)
            held.append(fd)
        except OSError:
            pass
    return held


def fd_count():
    return len(open_fds())


def child_pids(pid=None):
    """Live children of a process, by asking ps. Empty if ps is unavailable."""
    import subprocess
    pid = os.getpid() if pid is None else pid
    # One -o per column: with "-o pid=,ppid=,stat=" a BSD ps may take everything after the first
    # equals sign for the header of the first column, and print the pids alone.
    try:
        out = subprocess.run(["ps", "-A", "-o", "pid=", "-o", "ppid=", "-o", "stat="], stdout=subprocess.PIPE,
                             stderr=subprocess.DEVNULL, timeout=10).stdout.decode()
    except (OSError, subprocess.SubprocessError):
        return []
    res, understood = [], False
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[0].isdigit() and parts[1].isdigit():
            understood = True
            if parts[1] == str(pid):
                res.append((int(parts[0]), parts[2]))
    if out.strip() and not understood:
        raise Fail("cannot read the output of ps: %r" % out[:200])
    return res


class Worker(threading.Thread):
    """Run fn(*args) in a thread; finish() returns its result or raises its error."""

    def __init__(self, fn, *args):
        threading.Thread.__init__(self)
        self.daemon = True
        self._fn = fn
        self._args = args
        self.result = None
        self.exc = None
        self.start()

    def run(self):
        try:
            self.result = self._fn(*self._args)
        except BaseException as e:      # reported by finish()
            self.exc = e

    def finish(self, timeout=15.0):
        self.join(timeout)
        if self.is_alive():
            raise Fail("a helper thread did not finish in %.0f s" % timeout)
        if self.exc is not None:
            raise self.exc
        return self.result


class Feed(object):
    """A socketpair whose far end is written by a background thread.

    The library reads from .fd; .a is the writing end, kept open unless close
    is asked for, so that no end of stream shows up by accident."""

    def __init__(self, data, close=False, pace=None):
        self.a, self.b = sockpair()
        self.fd = self.b.fileno()
        self._w = Worker(self._send, data, close, pace)

    def _send(self, data, close, pace):
        if pace is None:
            self.a.sendall(data)
        else:
            for i in range(0, len(data), pace[0]):
                self.a.sendall(data[i:i + pace[0]])
                time.sleep(pace[1])
        if close:
            self.a.close()

    def finish(self, timeout=30.0):
        return self._w.finish(timeout)


class PipeFeed(object):
    """A pipe holding data already; the library reads from .fd."""

    def __init__(self, data, close=False):
        self.fd, self.w = os.pipe()
        os.write(self.w, data)
        if close:
            os.close(self.w)


class Peer(object):
    """The other end of a connection, read and written from Python."""

    def __init__(self, sock):
        self.s = sock
        self.buf = b""
        self.eof = False
        self.rx = bytearray()           # every byte that ever arrived, for audits

    def fileno(self):
        return self.s.fileno()

    def send(self, data):
        self.s.sendall(data)

    def send_line(self, text):
        if isinstance(text, str):
            text = text.encode("latin-1")
        self.s.sendall(text + b"\n")

    def _fill(self, deadline):
        left = deadline - time.monotonic()
        if left <= 0:
            return False
        r, _, _ = select.select([self.s], [], [], left)
        if not r:
            return False
        try:
            data = self.s.recv(65536)
        except ConnectionResetError:
            self.eof = True
            self.reset = True
            return True
        if not data:
            self.eof = True
        else:
            self.buf += data
            self.rx += data
        return True

    reset = False

    def recv_line(self, timeout=5.0):
        """The next line without its newline; None at end of stream. A '\\r'
        before the newline is kept: the peer sees the bytes as they are."""
        deadline = time.monotonic() + timeout * max(1.0, 1.0)
        while b"\n" not in self.buf:
            if self.eof:
                if self.buf:
                    line, self.buf = self.buf, b""
                    return line
                return None
            if not self._fill(deadline):
                raise Fail("no line from the peer within %.1f s (held %r)" % (timeout, self.buf[:60]))
        line, _, self.buf = self.buf.partition(b"\n")
        return line

    def recv_exact(self, n, timeout=5.0):
        deadline = time.monotonic() + timeout
        while len(self.buf) < n:
            if self.eof:
                break
            if not self._fill(deadline):
                raise Fail("wanted %d bytes from the peer, got %d" % (n, len(self.buf)))
        data, self.buf = self.buf[:n], self.buf[n:]
        return data

    def recv_all(self, timeout=5.0):
        """Everything until end of stream."""
        deadline = time.monotonic() + timeout
        while not self.eof:
            if not self._fill(deadline):
                raise Fail("the peer did not reach end of stream within %.1f s" % timeout)
        data, self.buf = self.buf, b""
        return data

    def recv_some(self, timeout=0.2):
        """Whatever arrives within timeout (maybe nothing)."""
        deadline = time.monotonic() + timeout
        while not self.eof and time.monotonic() < deadline:
            if not self._fill(deadline):
                break
            if self.buf:
                break
        data, self.buf = self.buf, b""
        return data

    def silent_for(self, timeout=0.2):
        """True if nothing arrives within timeout."""
        data = self.recv_some(timeout)
        if data:
            self.buf = data + self.buf
            return False
        return not self.eof

    def wait_eof(self, timeout=5.0):
        """True if the stream ends (or resets) within timeout."""
        deadline = time.monotonic() + timeout
        while not self.eof:
            if not self._fill(deadline):
                return False
            self.buf = b""
        return True

    def close(self):
        try:
            self.s.close()
        except OSError:
            pass


class SignalStorm(object):
    """Send a signal to the calling thread every `interval` seconds.

    The handler is installed with signal.signal, which does not set SA_RESTART:
    a blocked system call in the calling thread fails with EINTR each time."""

    def __init__(self, signum=None, interval=0.001):
        self.signum = signum or signal.SIGUSR1
        self.interval = interval
        self.sent = 0
        self._stop = threading.Event()

    def __enter__(self):
        self._old = signal.signal(self.signum, lambda *a: None)
        self._tid = threading.get_ident()

        def run():
            while not self._stop.is_set():
                try:
                    signal.pthread_kill(self._tid, self.signum)
                    self.sent += 1
                except OSError:
                    return
                time.sleep(self.interval)
        self._thread = threading.Thread(target=run, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *exc):
        self._stop.set()
        self._thread.join(5)
        signal.signal(self.signum, self._old)


def timeval(ms):
    """struct timeval of this platform holding ms milliseconds, as bytes."""
    import ctypes
    usec_type = ctypes.c_int if sys.platform == "darwin" else ctypes.c_long

    class TV(ctypes.Structure):
        _fields_ = [("tv_sec", ctypes.c_long), ("tv_usec", usec_type)]
    tv = TV(ms // 1000, (ms % 1000) * 1000)
    return ctypes.string_at(ctypes.addressof(tv), ctypes.sizeof(tv))


def wait_until(pred, timeout=5.0, step=0.01):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if pred():
            return True
        time.sleep(step)
    return pred()


def in_window(elapsed_ms, lo_ms, extra_ms=250):
    """Whether elapsed_ms lies in [lo, lo + extra] (extra scaled by PROTO_TEST_SLACK).

    The library counts whole milliseconds on a clock it reads once, so a deadline of lo may fire
    up to a millisecond early (a Linux run measured 299 ms for 300): the window opens 2 ms below."""
    return lo_ms - 2 <= elapsed_ms <= lo_ms + slack_ms(extra_ms)


def set_nonblocking(fd, on=True):
    fl = fcntl.fcntl(fd, fcntl.F_GETFL)
    fcntl.fcntl(fd, fcntl.F_SETFL, (fl | os.O_NONBLOCK) if on else (fl & ~os.O_NONBLOCK))


def cloexec(fd):
    return bool(fcntl.fcntl(fd, fcntl.F_GETFD) & fcntl.FD_CLOEXEC)


def is_nonblocking(fd):
    return bool(fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_NONBLOCK)


def errno_name(e):
    return errno.errorcode.get(e, str(e))
