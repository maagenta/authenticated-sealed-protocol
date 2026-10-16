"""XXV. Load and soak (T-417 to T-423). Every test here is slow."""

import collections
import os
import random
import resource
import signal
import socket
import subprocess
import threading
import time
import traceback

import harness
import lib
import libsodium as ls
import net
import peers
import servers
from harness import Fail, case, check, eq, skip
from keyfiles import make_identity
from s14_connect import connect_to

# T-422 runs this long; the nightly job asks for more (testing/run.py --soak-seconds).
SOAK_SECONDS = float(os.environ.get("PROTO_SOAK_SECONDS", "60"))
SOAK_SEED = os.environ.get("PROTO_SOAK_SEED", "1")


def proc_status_kb(pid, field):
    """A figure of /proc/<pid>/status in KiB (Linux), or None."""
    try:
        with open("/proc/%d/status" % pid) as f:
            for line in f:
                if line.startswith(field + ":"):
                    return int(line.split()[1])
    except (OSError, ValueError):
        pass
    return None


_libproc = []


def footprint_kb(pid):
    """The physical footprint of a process on macOS, in KiB, or None.

    The resident size is the wrong figure there: the allocator keeps blocks it has been given back
    mapped and resident, so that a process that holds 13 MB can show 50 and growing. The footprint
    leaves out the pages the allocator marked reusable, which is the memory the process really uses."""
    import ctypes
    if not _libproc:
        class RusageV0(ctypes.Structure):
            _fields_ = [("uuid", ctypes.c_uint8 * 16)] + [(n, ctypes.c_uint64) for n in (
                "user_time", "system_time", "pkg_idle_wkups", "interrupt_wkups", "pageins", "wired_size",
                "resident_size", "phys_footprint", "proc_start_abstime", "proc_exit_abstime")]
        try:
            dll = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
            dll.proc_pid_rusage.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_void_p]
            _libproc.append((dll, RusageV0))
        except (OSError, AttributeError):
            _libproc.append(None)
    if not _libproc[0]:
        return None
    dll, struct = _libproc[0]
    info = struct()
    if dll.proc_pid_rusage(pid, 0, ctypes.byref(info)) != 0:
        return None
    return info.phys_footprint // 1024


def rss_kb(pid):
    """Resident memory of a process in KiB, or None when it cannot be read."""
    kb = proc_status_kb(pid, "VmRSS")
    if kb is not None:
        return kb
    try:
        out = subprocess.run(["ps", "-o", "rss=", "-p", str(pid)], stdout=subprocess.PIPE,
                             stderr=subprocess.DEVNULL, timeout=10).stdout.decode().strip()
        return int(out) if out else None
    except (OSError, subprocess.SubprocessError, ValueError):
        return None


def memory_kb(pid):
    """What a process holds in memory, in KiB: the physical footprint on macOS, the resident size elsewhere."""
    if harness.PLATFORM == "macos":
        kb = footprint_kb(pid)
        if kb is not None:
            return kb
    return rss_kb(pid)


class MemorySampler(object):
    """Reads the memory of a process in the background; keeps the largest value seen."""

    def __init__(self, pid, every=None):
        self.pid = pid
        self.every = every or (0.005 if harness.PLATFORM in ("linux", "macos") else 0.05)
        self.peak = 0
        self.stopped = threading.Event()
        self.thread = threading.Thread(target=self._run)
        self.thread.daemon = True
        self.thread.start()

    def _run(self):
        while not self.stopped.is_set():
            kb = memory_kb(self.pid)
            if kb:
                self.peak = max(self.peak, kb)
            self.stopped.wait(self.every)

    def stop(self):
        self.stopped.set()
        self.thread.join(10)
        return max(self.peak, proc_status_kb(self.pid, "VmHWM") or 0)


def strict():
    """Whether the allocator of this platform gives memory back soon enough to hold it to the bounds."""
    return harness.PLATFORM in ("linux", "macos")


def raise_nofile(want):
    """Ask for room for `want` descriptors; returns the soft limit there now is."""
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    target = want if hard == resource.RLIM_INFINITY else min(want, hard)
    if soft < target:
        try:
            resource.setrlimit(resource.RLIMIT_NOFILE, (target, hard))
        except (ValueError, OSError):
            pass
    return resource.getrlimit(resource.RLIMIT_NOFILE)[0]


def child_pid(srv, timeout=5.0):
    """Process id of the newest connection handler, from the server's log."""
    return int(srv.wait_log("handler ", timeout)[-1].split("pid=")[1])


def run_sessions(n, workers, fn):
    """Call fn() n times, spread over worker threads; returns what the calls returned."""
    results, lock, taken = [], threading.Lock(), [0]

    def work():
        while True:
            with lock:
                if taken[0] >= n:
                    return
                taken[0] += 1
            r = fn()
            with lock:
                results.append(r)
    for t in [net.Worker(work) for _ in range(workers)]:
        t.finish(900)
    return results


# ------------------------------------------------------------------ T-417

@case("T-417", tags=("slow",), timeout=900)
def t417():
    """10000 sessions in a row leave the server flat."""
    P = lib.proto("default")
    ident = make_identity()
    rc, keys = P.load_keys(ident.auth_key, ident.enc_key)
    eq(rc, 0, "proto_load_keys")
    with servers.Server(ident.hex, "ok", variant="default", flags=["--sigusr2-dump"]) as srv:
        def session():
            conn = lib.Conn.new(keys)
            rc = P.connect(conn, "127.0.0.1", srv.port)
            if rc == 0:
                P.close(conn)
            return rc

        def settled():
            return net.wait_until(lambda: not srv.children(), 15)

        failed = [rc for rc in run_sessions(300, 4, session) if rc != 0]          # warm-up
        check(settled(), "children left after the warm-up: %s" % srv.children())
        base_fds, base_mem = len(srv.dump_fds()), memory_kb(srv.pid)
        check(base_mem, "cannot read the memory of the server")
        steps = []
        for step in range(10):
            failed += [rc for rc in run_sessions(1000, 4, session) if rc != 0]
            check(settled(), "step %d: children left: %s" % (step, srv.children()))
            steps.append((len(srv.dump_fds()), memory_kb(srv.pid)))
        harness.note("descriptors %d, memory %d KiB at the start; after each 1000 sessions: %s"
                     % (base_fds, base_mem, steps))
        check(not failed, "%d of 10300 sessions failed, e.g. with %s" % (len(failed), sorted(set(failed))[:3]))
        eq(sorted({fds for fds, _ in steps}), [base_fds], "the descriptors of the server after every 1000 sessions")
        growth = max(mem for _, mem in steps) - base_mem
        check(growth <= 2048, "the memory of the server grew by %d KiB over 10000 sessions" % growth)
        eq(srv.proc.poll(), None, "the server is still running")


# ------------------------------------------------------------------ T-418

@case("T-418", tags=("slow",), timeout=300)
def t418():
    """A flood of silent connections drains."""
    if raise_nofile(2048) < 1200:
        skip("cannot hold 500 descriptors here")
    P = lib.proto("default")
    drain_s = P.macros["HANDSHAKE_TIMEOUT_MS"] / 1000.0
    ident = make_identity()
    flood, peak, watching = [], [0], threading.Event()
    shed, lock = collections.Counter(), threading.Lock()
    opened_at = []
    with servers.Server(ident.hex, "ok", variant="default") as srv:
        def watch():
            # One ps per second: each poll forks ps, and that competes with the flood on 2-core runners.
            while not watching.is_set():
                peak[0] = max(peak[0], len(srv.live_children()))
                watching.wait(1.0)
        watcher = threading.Thread(target=watch)
        watcher.daemon = True
        watcher.start()

        def open_some(n):
            """n silent connections, one after the other: the server forks for each as fast as they come.

            Opened all at once, the surplus of a queue of 16 is lost: the kernel resets some, and others
            it lets the client believe are connected while the server never sees them. T-320 is about
            bursts. A reset is asked for again, as a client would."""
            give_up = time.monotonic() + 90
            while n:
                try:
                    s = socket.create_connection(("127.0.0.1", srv.port), timeout=60)
                except OSError as e:
                    with lock:
                        shed[type(e).__name__] += 1
                    check(time.monotonic() < give_up, "cannot open the connections of the flood: %s" % e)
                    time.sleep(0.05)
                    continue
                with lock:
                    flood.append(s)
                    opened_at.append(time.monotonic())
                n -= 1
        t0 = time.monotonic()
        # Several openers, so the flood is open well inside HANDSHAKE_TIMEOUT_MS on slow runners: the
        # first children must still be alive when the last connection arrives.
        openers = [threading.Thread(target=open_some, args=(n,)) for n in (125, 125, 125, 125)]
        for t in openers:
            t.start()
        for t in openers:
            t.join()
        eq(len(flood), 500, "silent connections opened")
        opened_in = time.monotonic() - t0
        # A child lives HANDSHAKE_TIMEOUT_MS. Connections older than that have already drained, so on a slow
        # runner (a 2-core box took 18 s to open the flood) the server can only hold the ones still inside
        # the window. Require most of those, not a fixed 450, and sample the peak while the flood is open.
        end = time.monotonic()
        window = sum(1 for t in opened_at if end - t < drain_s - 1.0)
        needed = min(450, int(0.6 * window))
        net.wait_until(lambda: len(srv.live_children()) >= needed, 5)
        peak[0] = max(peak[0], len(srv.live_children()))
        check(peak[0] >= needed,
              "only %d children at most for 500 silent connections (%d still inside the %.0f s window, %.1f s to open "
              "them, the kernel shed %s; the server's log: %s)" % (peak[0], window, drain_s, opened_in, dict(shed),
                                                                 srv.log()[-3:]))
        # Served during the flood, later perhaps; refused by the server, never. A connection the kernel sheds
        # is asked for again, as a client would.
        attempts, rc = 0, None
        while time.monotonic() - t0 < 60:
            attempts += 1
            rc, conn = connect_to(P, ident, srv.port)
            if rc == 0 or rc in (-703, -704):
                break
            time.sleep(0.2)
        served_after = time.monotonic() - t0
        eq(rc, 0, "a legitimate client during the flood, after %d attempts" % attempts)
        P.close(conn)
        check(net.wait_until(lambda: not srv.live_children(), drain_s + 15),
              "%d children left %.0f s after the flood" % (len(srv.live_children()), time.monotonic() - t0))
        gone = time.monotonic() - t0
        watching.set()
        watcher.join(5)
        harness.note("peak %d children; the legitimate client was served %.1f s into the flood, in %d attempts; "
                     "the kernel shed %s; all gone after %.1f s" % (peak[0], served_after, attempts, dict(shed), gone))
        check(peak[0] <= 501, "%d children at the peak, for 500 silent connections and one client" % peak[0])
        check(gone >= drain_s - 1, "the children were gone after %.1f s, before the handshake deadline of %.0f s: "
              "someone closed them" % (gone, drain_s))
        rc, conn = connect_to(P, ident, srv.port)
        eq(rc, 0, "a client after the flood")
        P.close(conn)
        [s.close() for s in flood]
        eq(srv.proc.poll(), None, "the server is still running")


# ------------------------------------------------------------------ T-419

@case("T-419", tags=("slow",), timeout=300)
def t419():
    """A slow 16 MiB line costs bounded memory."""
    P = lib.proto("default")
    cap = P.macros["MAX_PAYLOAD"]
    seconds, chunk = 60.0, 65536
    ident = make_identity()
    with servers.Server(ident.hex, "ok", variant="default") as srv:
        rc, conn = connect_to(P, ident, srv.port)
        eq(rc, 0, "proto_connect")
        pid = child_pid(srv)
        base = memory_kb(pid)
        check(base, "cannot read the memory of the connection's child")
        sampler = MemorySampler(pid, every=0.05)
        s = socket.socket(fileno=os.dup(conn.fd))
        chunks, line_end = cap // chunk, cap % chunk
        start = time.monotonic()
        for i in range(chunks):
            s.sendall(b"X" * chunk)
            left = start + (i + 1) * seconds / chunks - time.monotonic()
            if left > 0:
                time.sleep(left)
        s.sendall(b"X" * line_end + b"\n")
        sent_in = time.monotonic() - start
        rc, reply = P.recv_line(conn.fd, 64)
        peak = sampler.stop()
        harness.note("%d bytes in %.0f s; the child's memory %d KiB before, %d KiB at the peak"
                     % (cap, sent_in, base, peak))
        eq((rc, reply), (3, b"ERR"), "the answer to a line of exactly MAX_PAYLOAD characters, sent over a minute")
        check(sent_in >= seconds - 2, "the line took only %.0f s to send" % sent_in)
        grew = peak - base
        # The line itself, and a few MiB for the allocator when the buffer doubles for the last time.
        allowed = (cap + 2) // 1024 + (4096 if strict() else 16384)
        check(grew <= allowed, "the child's memory grew by %d KiB for a line of %d KiB" % (grew, cap // 1024))
        s.close()
        P.close(conn)


# ------------------------------------------------------------------ T-420

@case("T-420", tags=("slow",), timeout=120)
def t420():
    """Throughput is reported."""
    P = lib.proto("default")
    size = 1024 * 1024
    line = b"x" * (size - 1) + b"\n"
    times = []
    for _ in range(30):
        a, b = net.tcp_pair()
        feeder = net.Worker(a.sendall, line)
        t0 = time.monotonic()
        got, status = P.recv_dyn(b.fileno())
        times.append((time.monotonic() - t0) * 1000.0)
        feeder.finish(10)
        eq((len(got), status), (size - 1, 0), "the line read")
        a.close()
        b.close()
    times.sort()
    median = times[len(times) // 2]
    harness.note("reading a 1 MiB line takes %.1f ms (median of 30; best %.1f, worst %.1f); "
                 "RELEASE_NOTES.md says 3 ms on the machine it was measured on"
                 % (median, times[0], times[-1]))
    # Report only: wall time is noisy, and T-073 is the gate. A return to one call per byte takes seconds.
    check(median < 500, "reading a 1 MiB line took %.0f ms" % median)


# ------------------------------------------------------------------ T-421

def tasks_of_user():
    """Processes and threads that belong to this user: what RLIMIT_NPROC counts on Linux."""
    uid, n = os.getuid(), 0
    for name in os.listdir("/proc"):
        if not name.isdigit():
            continue
        try:
            if os.stat("/proc/" + name).st_uid == uid:
                n += len(os.listdir("/proc/%s/task" % name))
        except OSError:
            pass
    return n


@case("T-421", tags=("linux", "notroot", "slow"), timeout=300)
def t421():
    """A burst past the process limit is refused, then served."""
    if os.path.exists("/.dockerenv"):
        skip("the limit counts the user's tasks on the whole host, and a container shows only its own")
    if raise_nofile(1024) < 600:
        skip("cannot hold 200 descriptors here")
    P = lib.proto("default")
    ident = make_identity()
    limit = tasks_of_user() + 40

    def cap():
        resource.setrlimit(resource.RLIMIT_NPROC, (limit, limit))
    answers, held, lock = [], [], threading.Lock()
    with servers.Server(ident.hex, "ok", variant="default", preexec=cap) as srv:
        def one():
            s = socket.create_connection(("127.0.0.1", srv.port), timeout=30)
            peer = net.Peer(s)
            peer.send_line(b"HELLO")
            try:
                first = peer.recv_line(30)
            except Fail as e:
                first = b"(%s)" % str(e).encode()
            with lock:
                answers.append(first)
                held.append(s)
        for w in [net.Worker(lambda: [one() for _ in range(10)]) for _ in range(20)]:
            w.finish(120)
        busy = sum(1 for a in answers if a == b"FAIL server busy")
        served = sum(1 for a in answers if (a or b"").startswith(b"CHALLENGE "))
        harness.note("200 connections past a limit of %d tasks: %d served, %d told the server is busy"
                     % (limit, served, busy))
        others = collections.Counter(a for a in answers if a != b"FAIL server busy" and not (a or b"").startswith(b"CHALLENGE "))
        eq(busy + served, 200, "connections answered with a challenge or with FAIL server busy (others: %s)" % dict(others))
        check(busy >= 50, "only %d of 200 connections were told the server is busy" % busy)
        eq(srv.proc.poll(), None, "the server is still running")
        [s.close() for s in held]
        check(net.wait_until(lambda: not srv.live_children(), 20), "children left: %s" % srv.children())
        rc, conn = connect_to(P, ident, srv.port)
        eq(rc, 0, "a client once the children are gone")
        P.close(conn)


# ------------------------------------------------------------------ T-422

class Soak(object):
    """Random sessions against one server: well-formed ones, abandoned ones and plain garbage."""

    KINDS = [("clean", 30), ("abrupt", 8), ("reset", 8), ("halfclose", 5), ("midline", 6), ("garbage", 8),
             ("hello_only", 5), ("bad_auth", 6), ("stranger", 5), ("silent", 5), ("big", 3), ("stopping", 4),
             ("toolong", 0.4)]

    def __init__(self, P, ident, keys, port):
        self.P, self.ident, self.keys, self.port = P, ident, keys, port
        self.other = make_identity(write=False)
        self.counts = collections.Counter()
        self.anomalies = []
        self.lock = threading.Lock()
        self.deadline = time.monotonic() + SOAK_SECONDS

    # ---------------------------------------------------------- bookkeeping

    def count(self, what):
        with self.lock:
            self.counts[what] += 1

    def anomaly(self, what):
        with self.lock:
            self.anomalies.append(what)

    # --------------------------------------------------------------- pieces

    def connect(self):
        conn = lib.Conn.new(self.keys)
        rc = self.P.connect(conn, "127.0.0.1", self.port)
        if rc != 0:
            self.count("proto_connect failed")       # the instant of a restart, or a busy machine
            return None
        self.count("proto_connect ok")
        return conn

    def raw(self):
        try:
            return socket.create_connection(("127.0.0.1", self.port), timeout=10)
        except OSError:
            self.count("raw connect failed")
            return None

    @staticmethod
    def text(rnd, n):
        return "".join(rnd.choice("abcdefghijklmnopqrstuvwxyz0123456789+/=") for _ in range(n))

    def expect(self, fd, line, want):
        if self.P.send_line(fd, line) != 0:
            self.anomaly("sending %r failed on a live connection" % line[:30])
            return False
        got, status = self.P.recv_dyn(fd)
        if got != want:
            self.anomaly("%r was answered with %r (status %d)" % (line[:30], (got or b"")[:30], status))
            return False
        return True

    def chat(self, rnd, fd, n):
        """n well-formed commands, each checked against its answer."""
        for _ in range(n):
            r = rnd.random()
            if r < 0.30:
                ok = self.expect(fd, "PING", b"PONG")
            elif r < 0.55:
                body = self.text(rnd, rnd.randint(0, 5000))
                ok = self.expect(fd, "ECHO " + body, ("ECHO " + body).encode())
            elif r < 0.65:
                ok = self.expect(fd, "SLEEP %d" % rnd.randint(0, 30), b"SLEPT")
            elif r < 0.75:
                ok = self.expect(fd, "FDS", b"FDS")
            elif r < 0.85:
                ok = self.expect(fd, "".join(rnd.choice("ABCDEFGH") for _ in range(rnd.randint(1, 12))), b"ERR")
            elif r < 0.90:
                ok = self.expect(fd, "", b"ERR")
            else:
                body = self.text(rnd, rnd.randint(50000, 400000))
                ok = self.expect(fd, "ECHO " + body, ("ECHO " + body).encode())
            if not ok:
                return False
        return True

    @staticmethod
    def reset(sock):
        """Close so that the peer sees a reset. A socket the peer has reset already refuses the option: close it."""
        try:
            net.reset_close(sock)
        except OSError:
            sock.close()

    def drop(self, sock, rnd):
        if rnd.random() < 0.5:
            self.reset(sock)
        else:
            sock.close()

    # ---------------------------------------------------------------- kinds

    def kind_clean(self, rnd):
        conn = self.connect()
        if conn:
            self.chat(rnd, conn.fd, rnd.randint(0, 6))
            self.P.close(conn)

    def kind_abrupt(self, rnd):
        conn = self.connect()
        if conn:
            self.chat(rnd, conn.fd, rnd.randint(0, 4))
            os.close(conn.fd)

    def kind_reset(self, rnd):
        conn = self.connect()
        if conn:
            self.chat(rnd, conn.fd, rnd.randint(0, 4))
            s = socket.socket(fileno=os.dup(conn.fd))
            os.close(conn.fd)
            self.reset(s)

    def kind_halfclose(self, rnd):
        conn = self.connect()
        if conn:
            self.chat(rnd, conn.fd, rnd.randint(0, 3))
            s = socket.socket(fileno=os.dup(conn.fd))
            s.shutdown(socket.SHUT_WR)
            time.sleep(rnd.random() * 0.05)
            s.close()
            os.close(conn.fd)

    def kind_midline(self, rnd):
        conn = self.connect()
        if conn:
            os.write(conn.fd, b"ECHO " + self.text(rnd, rnd.randint(1, 3000)).encode())      # no newline
            if rnd.random() < 0.5:
                time.sleep(rnd.random() * 0.1)
            os.close(conn.fd)

    def kind_garbage(self, rnd):
        s = self.raw()
        if s:
            try:
                s.sendall(os.urandom(rnd.randint(0, 2000)) + (b"\n" if rnd.random() < 0.5 else b""))
            except OSError:
                pass
            self.drop(s, rnd)

    def kind_hello_only(self, rnd):
        s = self.raw()
        if s:
            peer = net.Peer(s)
            try:
                peer.send_line(b"HELLO")
                first = peer.recv_line(10)
                if first is None or not first.startswith(b"CHALLENGE "):
                    self.anomaly("HELLO was answered with %r" % (first,))
            except (Fail, OSError) as e:
                self.anomaly("HELLO: %s" % e)
            self.drop(s, rnd)

    def verdict_after(self, rnd, ident, bad_signature):
        s = self.raw()
        if not s:
            return None
        peer = net.Peer(s)
        try:
            if bad_signature:
                peer.send_line(b"HELLO")
                ch = peer.recv_line(10)
                if ch is None or not ch.startswith(b"CHALLENGE "):
                    return b"(no challenge: %r)" % (ch,)
                peer.send_line(b"AUTH " + ls.b64(ident.auth_pk).encode() + b" " + ls.b64(os.urandom(64)).encode())
                return peer.recv_line(10)
            return peers.client_handshake(peer, ident)
        except (Fail, OSError) as e:
            return b"(%s)" % str(e).encode()
        finally:
            peer.close()

    def kind_bad_auth(self, rnd):
        v = self.verdict_after(rnd, self.ident, True)
        if v is not None and not (v or b"").startswith(b"FAIL"):
            self.anomaly("a forged signature was answered with %r" % (v,))

    def kind_stranger(self, rnd):
        v = self.verdict_after(rnd, self.other, False)
        if v is not None and v != b"FAIL access denied":
            self.anomaly("an identity that is not allowed was answered with %r" % (v,))

    def kind_silent(self, rnd):
        s = self.raw()
        if s:
            time.sleep(0.05 + rnd.random() * 0.25)
            self.drop(s, rnd)

    def kind_big(self, rnd):
        conn = self.connect()
        if conn:
            body = self.text(rnd, rnd.randint(1000000, 3000000))
            self.expect(conn.fd, "ECHO " + body, ("ECHO " + body).encode())
            self.P.close(conn)

    def kind_stopping(self, rnd):
        """STOP in a child ends that child alone; the server goes on."""
        conn = self.connect()
        if conn:
            if self.chat(rnd, conn.fd, rnd.randint(0, 2)) and self.expect(conn.fd, "STOP", b"STOPPING"):
                got, status = self.P.recv_dyn(conn.fd)
                if got is not None or status != -603:
                    self.anomaly("after STOP the connection gave %r (status %d)" % (got, status))
            os.close(conn.fd)

    def kind_toolong(self, rnd):
        """A line past MAX_PAYLOAD: the child gives up on it, the server does not notice."""
        conn = self.connect()
        if conn:
            s = socket.socket(fileno=os.dup(conn.fd))
            s.settimeout(30)
            try:
                s.sendall(b"X" * (self.P.macros["MAX_PAYLOAD"] + 2))
            except OSError:
                pass                                        # the child may close first
            self.drop(s, rnd)
            os.close(conn.fd)

    # ------------------------------------------------------------------ run

    def worker(self, index):
        rnd = random.Random("%s/%d" % (SOAK_SEED, index))
        names = [k for k, _ in self.KINDS]
        weights = [w for _, w in self.KINDS]
        while time.monotonic() < self.deadline:
            kind = rnd.choices(names, weights)[0]
            self.count("session " + kind)
            try:
                getattr(self, "kind_" + kind)(rnd)
            except BaseException:                           # a bug of the test, or something unforeseen
                self.anomaly("%s: %s" % (kind, " | ".join(traceback.format_exc().strip().splitlines()[-3:])))


@case("T-422", tags=("slow",), timeout=int(max(600, SOAK_SECONDS * 3 + 300)))
def t422():
    """An hour of random sessions breaks nothing."""
    if raise_nofile(1024) < 512:
        skip("too few descriptors")
    P = lib.proto("default")
    ident = make_identity()
    rc, keys = P.load_keys(ident.auth_key, ident.enc_key)
    eq(rc, 0, "proto_load_keys")
    stops = 0
    with servers.Server(ident.hex, "ok", variant="default", flags=["--sigusr2-dump"],
                        extra=["--cycles", "1000000"]) as srv:
        soak = Soak(P, ident, keys, srv.port)
        base_fds, base_mem = len(srv.dump_fds()), memory_kb(srv.pid)
        check(base_mem, "cannot read the memory of the server")
        threads = [net.Worker(soak.worker, i) for i in range(4)]
        next_stop = time.monotonic() + 7
        while any(t.is_alive() for t in threads):
            time.sleep(0.2)
            if time.monotonic() >= next_stop and time.monotonic() < soak.deadline - 2:
                os.kill(srv.pid, signal.SIGTERM)             # the server stops and, in this probe, starts again
                stops += 1
                next_stop += 7
        for t in threads:
            t.finish(60)
        eq(srv.proc.poll(), None, "the server is still running (its exit status; the log's tail: %s)" % srv.log()[-6:])
        check(net.wait_until(lambda: not srv.children(), 30), "children left after the soak: %s" % srv.children())
        fds, mem = len(srv.dump_fds()), memory_kb(srv.pid)
        cycles = [int(l.split("open_fds=")[1]) for l in srv.grep("cycle ")]
        harness.note("%d s, %d stops; %s" % (SOAK_SECONDS, stops, dict(sorted(soak.counts.items()))))
        harness.note("server descriptors %d -> %d, memory %d -> %d KiB, open descriptors after each stop: %s"
                     % (base_fds, fds, base_mem, mem, sorted(set(cycles))))
        check(not soak.anomalies, "%d anomalies, e.g. %s" % (len(soak.anomalies), soak.anomalies[:3]))
        attempts = soak.counts["proto_connect ok"] + soak.counts["proto_connect failed"]
        check(attempts >= 50, "only %d connection attempts in %.0f s" % (attempts, SOAK_SECONDS))
        check(soak.counts["proto_connect ok"] >= 0.8 * attempts,
              "only %d of %d connections succeeded" % (soak.counts["proto_connect ok"], attempts))
        eq(fds, base_fds, "descriptors of the server after the soak")
        check(len(set(cycles)) <= 1, "descriptors left open after each stop differ: %s" % sorted(set(cycles)))
        check(len(cycles) >= stops, "%d stops asked, %d returns of proto_serve" % (stops, len(cycles)))
        check(mem - base_mem <= 10240, "the memory of the server grew by %d KiB" % (mem - base_mem))
        rc, conn = connect_to(P, ident, srv.port)
        eq(rc, 0, "a client after the soak")
        P.close(conn)


# ------------------------------------------------------------------ T-423

@case("T-423", tags=("slow",), timeout=600)
def t423():
    """The chunking recipe keeps memory flat."""
    P = lib.proto("default")
    ident = make_identity()
    size, count = 4 * 1024 * 1024, 50
    with servers.Server(ident.hex, "ok", variant="default") as srv:
        rc, conn = connect_to(P, ident, srv.port)
        eq(rc, 0, "proto_connect")
        pid = child_pid(srv)
        base = memory_kb(pid)
        check(base, "cannot read the memory of the connection's child")
        sampler = MemorySampler(pid)
        after, line_kb = [], 0
        for i in range(count):
            chunk = os.urandom(size)
            sealed = P.seal_new(chunk, ident.enc_pk)
            line_kb = max(line_kb, (len(sealed) + 5) // 1024)
            eq(P.send_prefixed(conn.fd, "ECHO ", sealed), 0, "sending message %d" % i)
            reply, status = P.recv_dyn(conn.fd)
            check(reply is not None and reply.startswith(b"ECHO "), "message %d: no echo (status %d)" % (i, status))
            plain, n = P.unseal_new(reply[5:], ident.enc_pk, ident.enc_sk)
            check(plain == chunk, "message %d came back different" % i)
            after.append(memory_kb(pid))
        peak = sampler.stop()
        P.close(conn)
        early, late = max(after[:10]), max(after[10:])
        harness.note("%d MB in %d messages; the child's memory: %d KiB at the start, %d KiB at the peak, "
                     "%d KiB after the first ten messages, %d KiB after the last ten, for lines of %d KiB"
                     % (size * count // 1000000, count, base, peak, early, late, line_kb))
        # 2.75 x MAX_PAYLOAD per connection is the client unsealing; the server child holds the line, and the
        # buffer that grows into it, once. Platforms whose allocator keeps freed blocks get twice the room.
        room = 1 if strict() else 2
        check(peak <= base + room * (3 * line_kb + 4096),
              "the child's memory reached %d KiB for lines of %d KiB (%d KiB at the start)" % (peak, line_kb, base))
        check(late <= early + room * 2048,
              "the child's memory kept growing: %d KiB after the first ten messages, %d KiB after the last" % (early, late))
