"""XVIII. proto_serve (T-292 to T-327)."""

import ctypes
import os
import resource
import signal
import socket
import subprocess
import threading
import time

import harness
import lib
import net
import runprobe
import servers
from harness import FINDING, PIN, PLATFORM, case, check, eq, skip, slack_ms
from keyfiles import make_identity
from net import Peer
from s14_connect import connect_to, new_conn

GOOD = b"a" * 64


def serve_call(P, port, allowed=GOOD, handler="noop", bind=None, drain=0):
    """proto_serve with the arguments given as they are, NULL where None."""
    opts = lib.ServeOpts(bind, drain)
    h = P.noop_handler if handler == "noop" else lib.HANDLER()      # a NULL function pointer
    return P.c_serve(port, allowed, h, None, ctypes.byref(opts))


def starts(P, port, bind=None, drain=0, allowed=GOOD):
    """What proto_serve returns when it is set up and a stop was asked for first."""
    P.serve_stop()
    return serve_call(P, port, allowed, bind=bind, drain=drain)


def bindable(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind(("0.0.0.0", port))
        return True
    except OSError:
        return False
    finally:
        s.close()


@case("T-292")
def t292():
    """Arguments are checked in order, before any socket exists."""
    P = lib.proto()
    port = net.free_port()
    P.serve_stop()                                       # a call that wrongly got going would return
    scenarios = [
        ("a NULL allowlist, a NULL handler and port 0", dict(port=0, allowed=None, handler=None), -103),
        ("a bad allowlist and a NULL handler", dict(port=port, allowed=b"A" * 64, handler=None), -104),
        ("a NULL handler and port 0", dict(port=0, handler=None), -105),
        ("port 0 and a bad address", dict(port=0, bind=b"nowhere"), -107),
        ("a bad address and a negative drain_ms", dict(port=port, bind=b"nowhere", drain=-1), -106),
        ("a negative drain_ms alone", dict(port=port, drain=-1), -101),
    ]
    for what, kw, want in scenarios:
        before = net.fd_count()
        eq(serve_call(P, **kw), want, what)
        eq(net.fd_count(), before, "open descriptors after " + what)
        check(bindable(port), "the port is held after " + what)


@case("T-293")
def t293():
    """An allowlist that is not 64 lowercase hex characters is refused."""
    P = lib.proto()
    P.serve_stop()
    port = net.free_port()
    for what, allowed in (("uppercase", b"A" * 64), ("63 characters", b"a" * 63), ("65 characters", b"a" * 65),
                          ("a g", b"g" + b"a" * 63), ("a NUL at position 32", b"a" * 32 + b"\0" + b"a" * 31)):
        eq(serve_call(P, port, allowed), -104, what)


@case("T-294")
def t294():
    """An out-of-range port is refused."""
    P = lib.proto()
    P.serve_stop()
    for port in (0, -1, 65536, 70000):
        eq(serve_call(P, port), -107, "port %d" % port)


@case("T-295")
def t295():
    """bind_addr must be an IPv4 literal."""
    P = lib.proto()
    for addr in (b"127.0.0.1", b"0.0.0.0"):
        eq(starts(P, net.free_port(), addr), 0, "bind_addr %r" % addr)
    P.serve_stop()
    for addr in (b"127.1", b" 127.0.0.1", b"127.0.0.1 ", b"::1", b"", b"localhost"):
        eq(serve_call(P, net.free_port(), bind=addr), -106, "bind_addr %r" % addr)


@case("T-296", PIN)
def t296():
    """Leading zeros in bind_addr get one verdict per platform."""
    P = lib.proto()
    rc = starts(P, net.free_port(), b"127.000.000.001")
    if PLATFORM == "macos":
        eq(rc, 0, "127.000.000.001 on macOS, whose inet_pton accepts leading zeros")
    elif PLATFORM == "linux":
        eq(rc, -106, "127.000.000.001 on glibc and musl, whose inet_pton refuses them (reasoned)")
    else:
        harness.note("%s: 127.000.000.001 gave %d" % (PLATFORM, rc))
        skip("no baseline recorded for %s: it gave %d" % (PLATFORM, rc))


@case("T-297")
def t297():
    """An address this host does not have is PROTO_E_BIND."""
    P = lib.proto()
    eq(starts(P, net.free_port(), b"192.0.2.1"), -504, "192.0.2.1")
    rc = starts(P, net.free_port(), b"255.255.255.255")
    if PLATFORM == "macos":
        eq(rc, -504, "255.255.255.255 on macOS")
    elif PLATFORM == "linux":
        eq(rc, 0, "255.255.255.255 on Linux, which binds a broadcast address (reasoned)")
    else:
        harness.note("%s: 255.255.255.255 gave %d" % (PLATFORM, rc))


@case("T-298")
def t298():
    """A port held by another listener is PROTO_E_PORT_IN_USE."""
    P = lib.proto()
    other = net.listener("0.0.0.0", 0)
    eq(starts(P, other.getsockname()[1]), -505, "a port another listener holds")


@case("T-299", FINDING, tags=("macos",), finding_on=("macos",))
def t299():
    """A second server on the same port is refused, whatever the two bind addresses."""
    P = lib.proto()
    first = net.listener("0.0.0.0", 0)
    port = first.getsockname()[1]
    eq(starts(P, port, b"127.0.0.1"), -505, "127.0.0.1 after a server on every interface")
    first.close()
    second = net.listener("127.0.0.1", port)
    eq(starts(P, port, None), -505, "every interface after a server on 127.0.0.1")


@case("T-300", tags=("linux", "notroot"))
def t300():
    """A privileged port without privilege is PROTO_E_PERM_DENIED."""
    P = lib.proto()
    try:
        with open("/proc/sys/net/ipv4/ip_unprivileged_port_start") as f:
            first = int(f.read())
    except (OSError, ValueError):
        skip("cannot read ip_unprivileged_port_start")
    if first == 0:
        skip("this host lets ordinary users bind every port")
    eq(starts(P, 1), -506, "port 1 without privilege")


@case("T-301", tags=("seam",))
def t301():
    """A failed socketpair() is PROTO_E_SOCKET, and the port is free."""
    runprobe.must_pass("seam_serve", ["socketpair_fail"], seams=runprobe.SERVE_SEAMS, threads=True)


@case("T-302", tags=("seam",))
def t302():
    """A failed socket() is PROTO_E_SOCKET."""
    runprobe.must_pass("seam_serve", ["socket_fail"], seams=runprobe.SERVE_SEAMS, threads=True)


@case("T-303", tags=("seam",))
def t303():
    """A failed listen() is PROTO_E_LISTEN, and the port is released."""
    runprobe.must_pass("seam_serve", ["listen_fail"], seams=runprobe.SERVE_SEAMS, threads=True)


@case("T-304", tags=("seam",))
def t304():
    """A broken listening socket is PROTO_E_ACCEPT."""
    runprobe.must_pass("seam_serve", ["accept_broken"], seams=runprobe.SERVE_SEAMS, threads=True)


@case("T-305", tags=("seam",))
def t305():
    """Running out of descriptors pauses accept, without a busy loop."""
    runprobe.must_pass("seam_serve", ["accept_emfile"], seams=runprobe.SERVE_SEAMS, threads=True, timeout=60)


@case("T-306", tags=("seam",))
def t306():
    """EINTR and ECONNABORTED from accept are retried at once."""
    runprobe.must_pass("seam_serve", ["accept_retry"], seams=runprobe.SERVE_SEAMS, threads=True)


@case("T-307", tags=("seam",))
def t307():
    """A failed fork() is answered with FAIL server busy."""
    runprobe.must_pass("seam_serve", ["fork_fail"], seams=runprobe.SERVE_SEAMS, threads=True)


def processes_of_user():
    out = subprocess.run(["ps", "-U", str(os.getuid()), "-o", "pid="], stdout=subprocess.PIPE,
                         stderr=subprocess.DEVNULL, timeout=10).stdout.decode()
    return len([l for l in out.splitlines() if l.strip()])


@case("T-308", tags=("linux", "notroot"))
def t308():
    """A real process shortage gets the same answer."""
    P = lib.proto()
    ident = make_identity()
    limit = processes_of_user() + 1

    def cap():
        resource.setrlimit(resource.RLIMIT_NPROC, (limit, limit))
    with servers.Server(ident.hex, "ok", preexec=cap) as srv:
        rc, conn = connect_to(P, ident, srv.port)
        eq(rc, -703, "proto_connect to a server that cannot fork (limit %d)" % limit)


@case("T-309", tags=("seam",))
def t309():
    """A failing poll() is retried after a pause."""
    runprobe.must_pass("seam_serve", ["poll_fail"], seams=runprobe.SERVE_SEAMS, threads=True)


@case("T-310")
def t310():
    """The handler gets the connection, the identity and ctx, in a child."""
    P = lib.proto()
    ident = make_identity()
    with servers.Server(ident.hex, "info", ctx="the-context") as srv:
        rc, conn = connect_to(P, ident, srv.port)
        eq(rc, 0, "proto_connect")
        line = srv.wait_log("info ")[0]
        f = dict(p.split("=", 1) for p in line.split()[1:])
        check(int(f["pid"]) != srv.pid, "the handler runs in the server's own process")
        eq(int(f["ppid"]), srv.pid, "the handler's parent")
        eq(f["identity"], ident.hex, "identity_hex")
        eq(f["ctx"], "the-context", "ctx")
        eq((f["nonblock"], f["peer"]), ("0", "1"), "a blocking, connected socket")
        P.close(conn)


@case("T-311")
def t311():
    """Nothing runs for a stranger."""
    P = lib.proto()
    ident, stranger = make_identity(), make_identity()
    marker = os.path.join(harness.tmpdir("marker"), "ran")
    with servers.Server(ident.hex, "marker", ctx=marker) as srv:
        rc, conn = connect_to(P, stranger, srv.port)
        eq(rc, -703, "a stranger")
        silent = socket.create_connection(("127.0.0.1", srv.port))
        time.sleep(P.macros["HANDSHAKE_TIMEOUT_MS"] / 1000.0 + 0.4)
        silent.close()
        check(not os.path.exists(marker), "the handler ran for a refused or a silent client")
        rc, conn = connect_to(P, ident, srv.port)
        eq(rc, 0, "the legitimate client")
        check(net.wait_until(lambda: os.path.exists(marker), 3), "the handler did not run for the legitimate client")
        P.close(conn)


@case("T-312")
def t312():
    """ctx points to the child's copy."""
    P = lib.proto()
    ident = make_identity()
    with servers.Server(ident.hex, "ctxmod") as srv:
        for _ in range(2):
            rc, conn = connect_to(P, ident, srv.port)
            eq(rc, 0, "proto_connect")
            P.close(conn)
        srv.wait_log("ctxmod counter=", count=2)
        eq(srv.grep("ctxmod counter="), ["ctxmod counter=0"] * 2, "the counter each connection saw")
        eq(srv.stop(), 0, "exit status")
        check("serve rc=0 counter=0" in srv.log(), "the parent's copy changed: %s" % srv.grep("serve rc"))


@case("T-313", timeout=120)
def t313():
    """When the handler returns, the child closes, exits 0 and is reaped."""
    P = lib.proto()
    ident = make_identity()
    with servers.Server(ident.hex, "sleep", ms=10) as srv:
        for _ in range(50):
            rc, conn = connect_to(P, ident, srv.port)
            eq(rc, 0, "proto_connect")
            eq(P.recv_line(conn.fd, 64)[0], -603, "the client sees end of stream when the handler returns")
            os.close(conn.fd)
        check(net.wait_until(lambda: not srv.children(), 5), "children left after 50 sessions: %s" % srv.children())


@case("T-314")
def t314():
    """A handler that crashes costs its own connection only."""
    P = lib.proto()
    ident = make_identity()
    with servers.Server(ident.hex, "crash") as srv:
        for i in range(3):
            rc, conn = connect_to(P, ident, srv.port)
            eq(rc, 0, "client %d" % (i + 1))
            rc, text = P.recv_line(conn.fd, 64)
            check(rc < 0, "the crashed child's connection stayed open")
            os.close(conn.fd)
        check(srv.proc.poll() is None, "the server died with its child")


@case("T-315", timeout=90)
def t315():
    """Clients are served in parallel."""
    P = lib.proto()
    ident = make_identity()
    with servers.Server(ident.hex, "sleep", ms=200) as srv:
        def client():
            rc, conn = connect_to(P, ident, srv.port)
            eq(rc, 0, "proto_connect")
            P.recv_line(conn.fd, 64)
            os.close(conn.fd)
        t0 = net.now()
        workers = [net.Worker(client) for _ in range(20)]
        [w.finish(30) for w in workers]
        took = net.ms_since(t0)
        check(took < 2000 + slack_ms(2000), "20 clients of 200 ms took %.0f ms: they were served one by one" % took)


@case("T-316", timeout=180)
def t316():
    """The parent keeps nothing per connection."""
    P = lib.proto()
    ident = make_identity()
    with servers.Server(ident.hex, "ok", flags=["--sigusr2-dump"]) as srv:
        def session():
            # A session may still time out when the runner is loaded; that says
            # nothing about descriptors, so it is tried again (a few times at most).
            for _ in range(3):
                rc, conn = connect_to(P, ident, srv.port)
                if rc != -605:
                    break
                P.close(conn)
            eq(rc, 0, "proto_connect")
            P.close(conn)
        for _ in range(5):
            session()
        before = sorted(r["fd"] for r in srv.dump_fds())
        for _ in range(200):
            session()
        net.wait_until(lambda: not srv.live_children(), 5)
        after = sorted(r["fd"] for r in srv.dump_fds())
        eq(after, before, "the server's open descriptors after 200 sessions")


@case("T-317")
def t317():
    """A silent stranger costs a child for HANDSHAKE_TIMEOUT_MS only."""
    P = lib.proto()
    ident = make_identity()
    with servers.Server(ident.hex, "ok") as srv:
        strangers = [socket.create_connection(("127.0.0.1", srv.port)) for _ in range(10)]
        check(net.wait_until(lambda: len(srv.live_children()) >= 8, 2), "no children for the strangers")
        time.sleep(P.macros["HANDSHAKE_TIMEOUT_MS"] / 1000.0)
        check(net.wait_until(lambda: not srv.live_children(), 3 + harness.SLACK),
              "children still alive after the handshake deadline: %s" % srv.children())
        [s.close() for s in strangers]


@case("T-318", FINDING)
def t318():
    """What a handler prints reaches its destination."""
    import suite
    if "musl" in suite.libc_name():
        skip("musl: the handler's printf is flushed before _exit, so there is no finding")
    P = lib.proto()
    ident = make_identity()
    with servers.Server(ident.hex, "printf") as srv:
        rc, conn = connect_to(P, ident, srv.port)
        eq(rc, 0, "proto_connect")
        P.recv_line(conn.fd, 64)
        os.close(conn.fd)
        net.wait_until(lambda: "handler says hi" in srv.stdout_text(), 2)
        check("handler says hi" in srv.stdout_text(), "a printf in the handler never reached stdout: lost at the child's _exit")


@case("T-319")
def t319():
    """A stopped server can start again on the same port at once."""
    P = lib.proto()
    ident = make_identity()
    port = net.free_port()
    with servers.Server(ident.hex, "sleep", ms=10, port=port) as first:
        for _ in range(10):
            rc, conn = connect_to(P, ident, port)
            eq(rc, 0, "proto_connect")
            P.recv_line(conn.fd, 64)
            os.close(conn.fd)                          # the server side closed first: TIME_WAIT there
        eq(first.stop(), 0, "the first server's exit status")
    with servers.Server(ident.hex, "ok", port=port) as second:
        rc, conn = connect_to(P, ident, port)
        eq(rc, 0, "a connection to the second server, started at once on the same port")
        P.close(conn)


@case("T-320", tags=("slow",), timeout=300)
def t320():
    """A burst beyond the backlog is served."""
    P = lib.proto("default")
    ident = make_identity()
    with servers.Server(ident.hex, "sleep", ms=50, variant="default") as srv:
        results, tries = [], []

        def client():
            # A kernel may reset a connection its queue cannot hold (macOS does, one in fifty under load);
            # a client asks again.
            for attempt in range(1, 6):
                rc, conn = connect_to(P, ident, srv.port)
                if rc == 0:
                    os.close(conn.fd)
                    break
            results.append(rc)
            tries.append(attempt)
        workers = [net.Worker(client) for _ in range(50)]
        [w.finish(120) for w in workers]
        harness.note("%d of 50 clients asked again, %d times in all" % (sum(1 for t in tries if t > 1), sum(tries) - 50))
        eq(sorted(set(results)), [0], "the codes of 50 simultaneous clients")


@case("T-321", tags=("seam",))
def t321():
    """A client that resets before accept does not wedge the loop."""
    runprobe.must_pass("seam_serve", ["accept_reset"], seams=runprobe.SERVE_SEAMS, threads=True, timeout=60)


@case("T-322", timeout=90)
def t322():
    """proto_serve keeps two descriptors, once."""
    ident = make_identity()
    with servers.Server(ident.hex, "ok", wait=False, extra=["--cycles", "4", "--cycle-ms", "150"]) as srv:
        eq(srv.wait_exit(30), 0, "the probe's exit status")
        base = srv.grep("baseline_fds")[0].split()[1].split(",")
        cycles = srv.grep("cycle ")
        eq(len(cycles), 4, "cycles")
        open_fds = [int(c.split("open_fds=")[1]) for c in cycles]
        eq(open_fds[0], len(base) + 2, "descriptors after the first proto_serve: the baseline and the stop channel")
        eq(open_fds[1:], [open_fds[0]] * 3, "descriptors after later calls")


@case("T-323", FINDING)
def t323():
    """The listening socket and the stop channel are close-on-exec."""
    ident = make_identity()
    with servers.Server(ident.hex, "ok", flags=["--sigusr2-dump"]) as srv:
        socks = [r for r in srv.dump_fds() if r["sock"] == 1]
        check(len(socks) >= 3, "found only %d sockets in the serving process" % len(socks))
        loose = [r["fd"] for r in socks if not r["cloexec"]]
        check(not loose, "sockets %s are not close-on-exec: a program the parent runs inherits them" % loose)


@case("T-324")
def t324():
    """The server is IPv4 only."""
    ident = make_identity()
    with servers.Server(ident.hex, "ok") as srv:
        s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        s.settimeout(2)
        try:
            s.connect(("::1", srv.port))
        except ConnectionRefusedError:
            return
        except OSError as e:
            skip("no IPv6 on the loopback here: %s" % e)
        raise harness.Fail("a client reached the server over ::1")


@case("T-325", timeout=60)
def t325():
    """The child holds nothing of the parent's."""
    P = lib.proto()
    ident = make_identity()
    port = net.free_port()
    with servers.Server(ident.hex, "fds", port=port) as srv:
        rc, conn = connect_to(P, ident, port)
        eq(rc, 0, "proto_connect")
        line = srv.wait_log("child_fds ")[0]
        base = set(int(x) for x in srv.grep("baseline_fds")[0].split()[1].split(","))
        fds = set(int(x) for x in line.split()[1].split(","))
        sock = int(line.split("conn=")[1])
        eq(fds, base | {sock}, "the handler's descriptors: the baseline and the connection")
        P.close(conn)
    # After a stop with drain 0 while a child still serves, the port is free at once.
    with servers.Server(ident.hex, "sleep", ms=4000, port=port, drain=0) as first:
        rc, conn = connect_to(P, ident, port)
        eq(rc, 0, "a client the child will keep for a while")
        eq(first.stop(), 0, "the first server's exit status")
        with servers.Server(ident.hex, "ok", port=port) as second:
            rc2, conn2 = connect_to(P, ident, port)
            eq(rc2, 0, "a connection to a new server on the same port, while the old child serves")
            P.close(conn2)
        os.close(conn.fd)


def non_loopback_ipv4():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("192.0.2.1", 9))
        ip = s.getsockname()[0]
    except OSError:
        return None
    finally:
        s.close()
    return None if ip.startswith("127.") or ip == "0.0.0.0" else ip


@case("T-326")
def t326():
    """bind_addr restricts who can connect."""
    ip = non_loopback_ipv4()
    if not ip:
        skip("this host has no non-loopback IPv4 address")
    ident = make_identity()
    with servers.Server(ident.hex, "ok", bind="127.0.0.1", flags=["--sigusr2-dump"]) as srv:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        try:
            s.connect((ip, srv.port))
            raise harness.Fail("a connection to %s:%d was accepted" % (ip, srv.port))
        except (ConnectionRefusedError, socket.timeout):
            pass
        locals_ = [r.get("local") for r in srv.dump_fds() if r["sock"] == 1]
        check("127.0.0.1:%d" % srv.port in locals_, "no listening socket reports 127.0.0.1:%d: %s" % (srv.port, locals_))


@case("T-327", timeout=120)
def t327():
    """Signals do not disturb the accept loop."""
    P = lib.proto()
    ident = make_identity()
    with servers.Server(ident.hex, "ok", flags=["--sigusr1-noop"]) as srv:
        stop = threading.Event()

        def storm():
            while not stop.is_set():
                try:
                    os.kill(srv.pid, signal.SIGUSR1)
                except OSError:
                    return
                time.sleep(0.001)
        t = threading.Thread(target=storm, daemon=True)
        t.start()
        try:
            for i in range(50):
                rc, conn = connect_to(P, ident, srv.port)
                eq(rc, 0, "client %d under a storm of SIGUSR1" % (i + 1))
                P.close(conn)
        finally:
            stop.set()
            t.join(5)
        eq(srv.stop(), 0, "the server's exit status (0 is PROTO_OK, not PROTO_E_ACCEPT)")
