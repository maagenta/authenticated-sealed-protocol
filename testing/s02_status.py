"""II. proto_strerror and the status codes (T-026 to T-034).
III. proto_init (T-035, T-036).
"""

import os
import socket
import threading

import harness
import keyfiles
import lib
import net
import runprobe
import statuses as st
from harness import GUARD, PIN, case, check, eq, skip

UNKNOWN = "unknown status code"


@case("T-026")
def t026():
    """Every status code has a message of its own."""
    P = lib.proto()
    check(len(st.STATUS) == 44, "the table holds %d codes, not 44" % len(st.STATUS))
    for name, value, _, _ in st.STATUS:
        msg = P.strerror(value)
        check(msg, "%s has no message" % name)
        check(msg != UNKNOWN, "%s (%d) falls through to %r" % (name, value, UNKNOWN))


@case("T-027", PIN)
def t027():
    """The 44 messages match a golden table."""
    P = lib.proto()
    families = {}
    for name, value, fam, msg in st.STATUS:
        families[fam] = families.get(fam, 0) + 1
        eq(P.strerror(value), msg, "message of %s" % name)
    eq(families, {"success": 3, "caller": 7, "resources": 2, "key files": 11, "cryptography": 2,
                  "sockets": 10, "lines": 5, "handshake": 4}, "codes per family")


@case("T-028")
def t028():
    """No two codes share a message."""
    P = lib.proto()
    seen = {}
    for name, value, _, _ in st.STATUS:
        msg = P.strerror(value)
        check(msg not in seen, "%s and %s share the message %r" % (name, seen.get(msg), msg))
        seen[msg] = name


@case("T-029")
def t029():
    """An unknown value yields "unknown status code"."""
    P = lib.proto()
    for v in (3, -1, -100, -108, -199, -312, -800, -2 ** 31, 2 ** 31 - 1):
        eq(P.strerror(v), UNKNOWN, "proto_strerror(%d)" % v)


@case("T-030")
def t030():
    """proto_strerror never returns NULL."""
    P = lib.proto()
    f = P.c_strerror
    for v in range(-100000, 100001):
        if f(v) is None:
            harness.fail("proto_strerror(%d) returned NULL" % v)
    for v in (-2 ** 31, 2 ** 31 - 1):
        check(f(v) is not None, "proto_strerror(%d) returned NULL" % v)


def header_values():
    """{name: value} of the members of the table, as status.h defines them: a program prints them."""
    body = "".join('    printf("%s %%d\\n", (int)%s);\n' % (n, n) for n, _, _, _ in st.STATUS)
    src = '#include <stdio.h>\n#include "status.h"\nint main(void) {\n' + body + "    return 0;\n}\n"
    d = harness.tmpdir("vals")
    path = os.path.join(d, "v.c")
    with open(path, "w") as f:
        f.write(src)
    rc, out = lib.run([lib.cc(), "-o", os.path.join(d, "v"), "-I", harness.ROOT, path])
    check(rc == 0, "cannot build the value dump: " + out[-300:])
    rc, out, err = lib.run_exe(os.path.join(d, "v"))
    check(rc == 0, "the value dump exited %d" % rc)
    return dict((l.split()[0], int(l.split()[1])) for l in out.decode().splitlines())


@case("T-031")
def t031():
    """rc < 0 partitions the values."""
    # The values status.h gives, not those of this suite's table: a sign flipped in the header must show here.
    values = header_values()
    eq(values.get("PROTO_OK"), 0, "PROTO_OK")
    eq(values.get("PROTO_REGISTER_REQUESTED"), 1, "PROTO_REGISTER_REQUESTED")
    eq(values.get("PROTO_KEEPALIVE_DEFAULTED"), 2, "PROTO_KEEPALIVE_DEFAULTED")
    families = {"caller": 1, "resources": 2, "key files": 3, "cryptography": 4, "sockets": 5,
                "lines": 6, "handshake": 7}
    for name, _, fam, _ in st.STATUS:
        if fam == "success":
            continue
        value = values.get(name)
        check(value is not None and value < 0, "%s is not negative: %r" % (name, value))
        eq((-value) // 100, families[fam], "hundreds digit of %s (%s)" % (name, fam))


@case("T-032")
def t032():
    """The values are frozen."""
    got = header_values()
    for name, value, _, _ in st.STATUS:
        eq(got.get(name), value, "value of %s" % name)


@case("T-033")
def t033():
    """Every message is one line of ASCII."""
    P = lib.proto()
    for name, value, _, _ in st.STATUS:
        msg = P.strerror(value)
        check(msg.isascii() and msg.isprintable(), "message of %s is not plain ASCII: %r" % (name, msg))
        check("\n" not in msg and "\r" not in msg, "message of %s holds a line break" % name)
        check(msg == msg.strip(), "message of %s has surrounding whitespace" % name)


@case("T-034")
def t034():
    """proto_strerror is safe from many threads."""
    P = lib.proto()
    f = P.c_strerror
    errors = []

    def worker():
        try:
            for i in range(20000):
                v = st.STATUS[i % len(st.STATUS)]
                if f(v[1]).decode() != v[3]:
                    errors.append(v[0])
                    return
        except BaseException as e:
            errors.append(repr(e))
    ts = [threading.Thread(target=worker) for _ in range(8)]
    [t.start() for t in ts]
    [t.join(60) for t in ts]
    check(not errors, "a thread saw a wrong message: %s" % errors[:3])
    rc, err, used_tsan = runprobe.threads("strerror")
    check(rc == 0 and not runprobe.tsan_report(err), "threads strerror: " + err[-600:])


@case("T-035")
def t035():
    """proto_init returns PROTO_OK, and is idempotent."""
    P = lib.proto()
    for _ in range(3):
        eq(P.init(), 0, "proto_init")
    results = []

    def worker():
        results.append(P.init())
    ts = [threading.Thread(target=worker) for _ in range(8)]
    [t.start() for t in ts]
    [t.join(30) for t in ts]
    eq(results, [0] * 8, "proto_init from 8 threads")
    rc, err, _ = runprobe.threads("init")
    check(rc == 0 and not runprobe.tsan_report(err), "threads init: " + err[-600:])


@case("T-036")
def t036():
    """The turnkey calls need no proto_init from the application."""
    import peers
    P = lib.proto()
    # proto_serve, in a process that never called proto_init: a stop asked
    # first makes it return once it is set up.
    P.serve_stop()
    rc = P.serve(net.free_port(), "a" * 64, opts=None)
    eq(rc, 0, "proto_serve")
    # proto_connect, against a server that completes the handshake.
    ident = keyfiles.make_identity()
    rc_load, keys = P.load_keys(ident.auth_key, ident.enc_key)
    eq(rc_load, 0, "proto_load_keys")
    ls = net.listener()
    port = ls.getsockname()[1]
    srv = net.Worker(peers.accept_and_serve, ls, ident.auth_pk, b"OK")
    conn = lib.Conn.new(keys)
    rc = P.connect(conn, "127.0.0.1", port)
    eq(rc, 0, "proto_connect")
    check(conn.fd >= 0, "no connection")
    os.close(conn.fd)
    srv.finish()
