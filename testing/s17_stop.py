"""XIX. proto_serve_stop and draining (T-328 to T-347)."""

import ctypes
import os
import signal
import socket
import threading
import time

import harness
import lib
import net
import runprobe
import servers
from harness import FINDING, PIN, case, check, eq, skip, slack_ms
from keyfiles import make_identity
from s14_connect import connect_to
from s16_serve import GOOD, bindable, serve_call, starts

INT_MAX = 2 ** 31 - 1


def refused(port):
    try:
        socket.create_connection(("127.0.0.1", port), timeout=2).close()
        return False
    except ConnectionRefusedError:
        return True


@case("T-328")
def t328():
    """A stop from a signal handler ends proto_serve with PROTO_OK."""
    ident = make_identity()
    with servers.Server(ident.hex, "ok") as srv:
        t0 = net.now()
        eq(srv.stop(signal.SIGTERM), 0, "the server's exit status")
        check("serve rc=0 counter=0" in srv.log(), "proto_serve did not return PROTO_OK: %s" % srv.grep("serve rc"))
        check(net.ms_since(t0) < 1500 + slack_ms(1500), "the stop took %.0f ms" % net.ms_since(t0))
        check(refused(srv.port), "a new connection is accepted after the stop")


@case("T-329")
def t329():
    """A stop from another thread ends proto_serve."""
    rc, err, used = runprobe.threads("stop", net.free_port(), tsan=False)
    check(rc == 0, "threads stop: " + err[-500:])


@case("T-330", FINDING)
def t330():
    """A stop from another thread is free of data races."""
    import lib as _lib
    if not _lib.sanitizer_works("tsan"):
        skip("ThreadSanitizer does not work here")
    rc, err, used = runprobe.threads("stop", net.free_port())
    check(used, "ThreadSanitizer was not used")
    check(not runprobe.tsan_report(err), "ThreadSanitizer reports data races in proto_serve_stop: "
          + ", ".join(sorted(set(l.strip() for l in err.splitlines() if "Location is global" in l or "Write of size" in l or "Previous" in l)))[:300])


@case("T-331")
def t331():
    """A stop before proto_serve is kept, but the setup still runs."""
    P = lib.proto()
    P.serve_stop()
    eq(serve_call(P, 0), -107, "a bad port with a stop asked first")
    t0 = net.now()
    eq(serve_call(P, net.free_port()), 0, "a good setup after the stop")
    check(net.ms_since(t0) < 500 + slack_ms(500), "proto_serve waited %.0f ms instead of returning at once" % net.ms_since(t0))


@case("T-332", PIN)
def t332():
    """A stop outlives a failed call."""
    P = lib.proto()
    P.serve_stop()
    eq(serve_call(P, net.free_port(), allowed=None), -103, "a NULL allowlist")
    t0 = net.now()
    eq(serve_call(P, net.free_port()), 0, "a good call after it")
    check(net.ms_since(t0) < 500 + slack_ms(500), "it did not return at once")


@case("T-333")
def t333():
    """A stop after proto_serve returned is kept for the next call."""
    P = lib.proto()
    eq(starts(P, net.free_port()), 0, "the first call")
    P.serve_stop()                                      # after it returned
    t0 = net.now()
    eq(serve_call(P, net.free_port()), 0, "the next call")
    check(net.ms_since(t0) < 500 + slack_ms(500), "it waited for another stop")


@case("T-334", timeout=120)
def t334():
    """Many stops never block."""
    P = lib.proto()
    port = net.free_port()
    first = net.Worker(serve_call, P, port)
    time.sleep(0.4)                                       # let it bind and listen
    t0 = net.now()
    for _ in range(100000):
        P.serve_stop()
    took = net.ms_since(t0)
    eq(first.finish(15), 0, "the proto_serve the stops were asked of")
    check(took < 5000 + slack_ms(5000), "100000 stops took %.0f ms" % took)
    P.serve_stop()                                       # whatever the storm left is one stop
    eq(serve_call(P, net.free_port()), 0, "the call after the storm")
    timer = net.Worker(lambda: (time.sleep(0.3), P.serve_stop()))
    t0 = net.now()
    eq(serve_call(P, net.free_port()), 0, "the call after that")
    took = net.ms_since(t0)
    timer.finish()
    check(took >= 250, "the call after next returned after %.0f ms: a stray stop was left over" % took)


@case("T-335")
def t335():
    """proto_serve_stop preserves errno."""
    P = lib.proto()
    for when in ("before any proto_serve", "on the first call after one", "on a later call"):
        if when == "on the first call after one":
            starts(P, net.free_port())                    # creates the channel
        ctypes.set_errno(4321)
        P.c_serve_stop()
        eq(ctypes.get_errno(), 4321, "errno " + when)
    ctypes.set_errno(4321)
    P.c_serve_stop()
    eq(ctypes.get_errno(), 4321, "errno on a repeated call")


@case("T-336")
def t336():
    """A stop wins over a waiting client."""
    ident = make_identity()
    marker = os.path.join(harness.tmpdir("marker"), "ran")
    with servers.Server(ident.hex, "marker", ctx=marker) as srv:
        os.kill(srv.pid, signal.SIGSTOP)
        client = socket.create_connection(("127.0.0.1", srv.port), timeout=3)
        os.kill(srv.pid, signal.SIGTERM)
        os.kill(srv.pid, signal.SIGCONT)
        eq(srv.wait_exit(10), 0, "the server's exit status")
        check(not os.path.exists(marker), "the handler ran for the waiting client")
        client.settimeout(3)
        try:
            data = client.recv(10)
        except ConnectionResetError:
            data = b""
        eq(data, b"", "what the waiting client reads: its connection is reset or closed")


@case("T-337")
def t337():
    """drain_ms 0 returns at once and leaves children serving."""
    P = lib.proto()
    ident = make_identity()
    with servers.Server(ident.hex, "ok", drain=0) as srv:
        rc, conn = connect_to(P, ident, srv.port)
        eq(rc, 0, "proto_connect")
        t0 = net.now()
        eq(srv.stop(), 0, "the server's exit status")
        check(net.ms_since(t0) < 1000 + slack_ms(1000), "the stop took %.0f ms with a child serving" % net.ms_since(t0))
        eq(servers.command(P, conn, "PING"), (4, b"PONG"), "the child goes on serving its client")
        P.close(conn)


@case("T-338")
def t338():
    """The drain returns when the last child ends."""
    P = lib.proto()
    ident = make_identity()
    with servers.Server(ident.hex, "sleep", ms=500, drain=2000) as srv:
        rc, conn = connect_to(P, ident, srv.port)
        eq(rc, 0, "proto_connect")
        t0 = net.now()
        eq(srv.stop(), 0, "the server's exit status")
        took = net.ms_since(t0)
        check(300 <= took <= 500 + slack_ms(800), "the drain took %.0f ms for a child that ends at 500" % took)
        os.close(conn.fd)


@case("T-339")
def t339():
    """drain_ms bounds the wait."""
    P = lib.proto()
    ident = make_identity()
    with servers.Server(ident.hex, "sleep", ms=6000, drain=500) as srv:
        rc, conn = connect_to(P, ident, srv.port)
        eq(rc, 0, "proto_connect")
        t0 = net.now()
        eq(srv.stop(), 0, "the server's exit status")
        took = net.ms_since(t0)
        check(net.in_window(took, 500, 400), "the drain took %.0f ms with drain_ms 500" % took)
        check(len(net.child_pids(srv.pid)) >= 0, "")
        a = net.Peer(socket.socket(fileno=os.dup(conn.fd)))
        check(a.silent_for(0.2), "the busy child's connection ended with the server")
        os.close(conn.fd)


@case("T-340", PIN)
def t340():
    """The drain counts the application's own children."""
    ident = make_identity()
    with servers.Server(ident.hex, "ok", drain=3000, extra=["--sleeper-ms", "1000"]) as srv:
        t0 = net.now()
        eq(srv.stop(), 0, "the server's exit status")
        took = net.ms_since(t0)
        check(500 <= took <= 1000 + slack_ms(700), "the drain took %.0f ms for a child of the application's that sleeps 1 s" % took)


@case("T-341")
def t341():
    """drain_ms INT_MAX with no children returns at once."""
    ident = make_identity()
    with servers.Server(ident.hex, "ok", drain=INT_MAX) as srv:
        t0 = net.now()
        eq(srv.stop(), 0, "the server's exit status")
        check(net.ms_since(t0) < 1000 + slack_ms(1000), "the stop took %.0f ms" % net.ms_since(t0))


@case("T-342", timeout=90)
def t342():
    """A stop during the drain belongs to the stop in progress."""
    P = lib.proto()
    ident = make_identity()
    with servers.Server(ident.hex, "sleep", ms=1200, drain=3000, extra=["--cycles", "2"]) as srv:
        rc, conn = connect_to(P, ident, srv.port)
        eq(rc, 0, "proto_connect")
        os.kill(srv.pid, signal.SIGTERM)                 # the stop
        time.sleep(0.3)
        os.kill(srv.pid, signal.SIGTERM)                 # another, during the drain
        srv.wait_log("cycle 1 rc=0", 10)
        time.sleep(0.5)
        check(srv.proc.poll() is None, "the second proto_serve returned at once: the stop during the drain was kept")
        rc2, conn2 = connect_to(P, ident, srv.port)
        eq(rc2, 0, "a connection to the second proto_serve")
        os.close(conn2.fd)
        eq(srv.stop(), 0, "the second proto_serve's exit status")
        os.close(conn.fd)


@case("T-343")
def t343():
    """A child that receives the stop signal itself exits at once."""
    P = lib.proto()
    ident = make_identity()
    with servers.Server(ident.hex, "ok") as srv:
        rc, conn = connect_to(P, ident, srv.port)
        eq(rc, 0, "proto_connect")
        kids = srv.live_children()
        check(kids, "no child to signal")
        child = kids[0][0]
        os.kill(child, signal.SIGTERM)
        eq(P.recv_line(conn.fd, 64)[0], -603, "the child's client sees the connection end at once")
        srv.wait_log("term pid=%d" % child)             # the inherited handler ran
        rc2, conn2 = connect_to(P, ident, srv.port)
        eq(rc2, 0, "the server keeps accepting")
        P.close(conn2)
        os.close(conn.fd)


@case("T-344", timeout=90)
def t344():
    """SIGTERM to the whole process group ends everything cleanly."""
    P = lib.proto()
    ident = make_identity()
    with servers.Server(ident.hex, "ok", group=True) as srv:
        conns = []
        for _ in range(3):
            rc, conn = connect_to(P, ident, srv.port)
            eq(rc, 0, "proto_connect")
            conns.append(conn)
        kids = [c[0] for c in srv.live_children()]
        eq(len(kids), 3, "children")
        srv.signal_group(signal.SIGTERM)
        eq(srv.wait_exit(15), 0, "the server's exit status")
        check(net.wait_until(lambda: not any(net_pid_alive(k) for k in kids), 5), "children are still alive")
        terms = srv.grep("term pid=")
        check(len(terms) >= 4, "the inherited handler ran %d times, for the parent and 3 children: %s" % (len(terms), terms))
        for conn in conns:
            eq(P.recv_line(conn.fd, 64)[0], -603, "a client sees its connection end")
            os.close(conn.fd)


def net_pid_alive(pid):
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    # a zombie is not alive
    return not any(p == pid and s.startswith("Z") for p, s in net.child_pids(os.getppid()) + net.child_pids(1))


@case("T-345")
def t345():
    """A handler that calls proto_serve_stop() ends only its own child."""
    P = lib.proto()
    ident = make_identity()
    with servers.Server(ident.hex, "stopper") as srv:
        rc, conn = connect_to(P, ident, srv.port)
        eq(rc, 0, "proto_connect")
        srv.wait_log("stopper calls proto_serve_stop")
        eq(P.recv_line(conn.fd, 64)[0], -603, "the child's connection ends")
        check(not srv.grep("stopper survived"), "the handler went on after proto_serve_stop()")
        time.sleep(0.2)
        check(srv.proc.poll() is None, "the server stopped with its child")
        rc2, conn2 = connect_to(P, ident, srv.port)
        eq(rc2, 0, "the parent goes on serving")
        os.close(conn2.fd)
        os.close(conn.fd)


@case("T-346", timeout=120)
def t346():
    """Serving and stopping on one port, 50 times over, always works."""
    ident = make_identity()
    with servers.Server(ident.hex, "ok", wait=False, extra=["--cycles", "50", "--cycle-ms", "60"]) as srv:
        eq(srv.wait_exit(60), 0, "the probe's exit status")
        cycles = srv.grep("cycle ")
        eq(len(cycles), 50, "cycles")
        check(all(" rc=0 " in c + " " for c in cycles), "a cycle did not return PROTO_OK: %s" % [c for c in cycles if " rc=0 " not in c + " "][:2])
        fds = [int(c.split("open_fds=")[1]) for c in cycles]
        eq(set(fds[1:]), {fds[0]}, "open descriptors from the first cycle on")


@case("T-347", tags=("seam",))
def t347():
    """A stop on the busy path is honoured right after it."""
    runprobe.must_pass("seam_serve", ["busy_stop"], seams=runprobe.SERVE_SEAMS, threads=True)
