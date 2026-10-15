"""I. Build, configuration and headers (T-001 to T-025)."""

import os
import re
import shutil

import baselines
import docsx
import harness
import keyfiles
import lib
import net
from harness import (FINDING, GUARD, PIN, PLATFORM, ROOT, case, check, eq, fail, skip,
                     slack_ms, between)

HEADERS = ["protocol.h", "status.h", "wire.h", "crypto.h", "auth.h", "serve.h"]
SOURCES = lib.LIB_SOURCES
STRICT = ["-Wall", "-Wextra", "-Werror"]


def must_fail(source, flags, needle=None, what=""):
    rc, out = lib.try_compile(source, flags)
    check(rc != 0, "%s compiled; it must not" % (what or " ".join(flags)))
    if needle:
        check(needle in out, "%s failed, but not with %r: %s" % (what or " ".join(flags), needle, out[-300:]))


def must_build(source, flags, what=""):
    rc, out = lib.try_compile(source, flags)
    check(rc == 0, "%s does not compile: %s" % (what or " ".join(flags), out[-400:]))


# Every public header, the way a consumer includes the ones an option touches.
OPTION_HEADERS = '#include "protocol.h"\n#include "wire.h"\n'


@case("T-001", variant_safe=False)
def t001():
    """Headers compile in isolation."""
    for h in HEADERS:
        must_build('#include "%s"\n' % h, STRICT, h + " alone")
        must_build('#include "%s"\n#include "%s"\n' % (h, h), STRICT, h + " twice")


@case("T-002")
def t002():
    """The constants and compile-time options have their documented defaults."""
    src = OPTION_HEADERS + '#include "crypto.h"\n#define SA(n, c) typedef char sa_##n[(c) ? 1 : -1]\n' + "\n".join([
        "SA(a, CHALLENGE_LEN == 32);",
        "SA(b, MAX_LINE == 16384);",
        "SA(c, CONNECT_TIMEOUT_MS == 10000);",
        "SA(d, HANDSHAKE_TIMEOUT_MS == 10000);",
        "SA(e, QUIT_TIMEOUT_MS == 2000);",
        "SA(f, READ_CHUNK == 65536);",
        "SA(g, MAX_PAYLOAD == 16 * 1024 * 1024);",
        "SA(h, AUTH_PK_LEN == 32);",
        "SA(i, AUTH_SK_LEN == 64);",
        "SA(j, AUTH_SIG_LEN == 64);",
        "SA(k, ENC_PK_LEN == 32);",
        "SA(l, ENC_SK_LEN == 32);",
    ]) + "\n"
    must_build(src, [], "the constants table")


@case("T-003")
def t003():
    """Overrides reach the code."""
    flags = ["-DCONNECT_TIMEOUT_MS=2000", "-DHANDSHAKE_TIMEOUT_MS=3000", "-DQUIT_TIMEOUT_MS=500",
             "-DREAD_CHUNK=131072", "-DMAX_PAYLOAD=4194304"]
    src = OPTION_HEADERS
    for name, value in (("CONNECT_TIMEOUT_MS", 2000), ("HANDSHAKE_TIMEOUT_MS", 3000),
                        ("QUIT_TIMEOUT_MS", 500), ("READ_CHUNK", 131072),
                        ("MAX_PAYLOAD", 4194304)):
        src += "#if %s != %d\n#error %s lost its override\n#endif\n" % (name, value, name)
    must_build(src, flags + STRICT, "the override check")
    for s in SOURCES:           # no "macro redefined" warning in any source
        rc, out = lib.compile_source(s, flags + STRICT)
        check(rc == 0, "%s with the overrides: %s" % (s, out[-300:]))

    # At the minimum the options still work at run time.
    from lib import Conn, Keys
    P = lib.proto("min")
    a, b = net.sockpair()
    t0 = net.now()
    rc = P.auth_client(a.fileno(), Keys())
    took = net.ms_since(t0)
    eq(rc, -605, "proto_auth_client against a silent peer at HANDSHAKE_TIMEOUT_MS=1")
    check(took < 100 + slack_ms(400), "the 1 ms handshake deadline took %.0f ms" % took)
    conn = Conn.new()
    conn.fd = a.detach()
    t0 = net.now()
    P.close(conn)
    took = net.ms_since(t0)
    eq(conn.fd, -1, "conn.fd after proto_close")
    check(took < 100 + slack_ms(400), "proto_close at QUIT_TIMEOUT_MS=0 waited %.0f ms" % took)


@case("T-004")
def t004():
    """CONNECT_TIMEOUT_MS=0 fails the build."""
    must_fail('#include "protocol.h"\n', ["-DCONNECT_TIMEOUT_MS=0"],
              "CONNECT_TIMEOUT_MS must be at least 1")
    must_build('#include "protocol.h"\n', ["-DCONNECT_TIMEOUT_MS=1"])


@case("T-005")
def t005():
    """HANDSHAKE_TIMEOUT_MS below 1 fails the build."""
    for v in ("0", "-1"):
        must_fail('#include "protocol.h"\n', ["-DHANDSHAKE_TIMEOUT_MS=" + v],
                  "HANDSHAKE_TIMEOUT_MS must be at least 1")
    must_build('#include "protocol.h"\n', ["-DHANDSHAKE_TIMEOUT_MS=1"])


@case("T-006")
def t006():
    """A negative QUIT_TIMEOUT_MS fails the build; 0 is allowed."""
    must_fail('#include "protocol.h"\n', ["-DQUIT_TIMEOUT_MS=-1"], "QUIT_TIMEOUT_MS must not be negative")
    must_build('#include "protocol.h"\n', ["-DQUIT_TIMEOUT_MS=0"])


@case("T-007", FINDING)
def t007():
    """A timeout above INT_MAX fails the build."""
    # The options are passed on as an int number of milliseconds, so a value
    # past INT_MAX wraps negative where it is used, in auth.c.
    for name in ("HANDSHAKE_TIMEOUT_MS", "CONNECT_TIMEOUT_MS", "QUIT_TIMEOUT_MS"):
        rc, out = lib.compile_source("auth.c", ["-D%s=3000000000" % name])
        check(rc != 0, "%s=3000000000 compiled with only a warning: it wraps negative "
                       "where it is passed as an int" % name)


@case("T-008")
def t008():
    """READ_CHUNK below 1 fails the build."""
    for v in ("0", "-5"):
        must_fail('#include "wire.h"\n', ["-DREAD_CHUNK=" + v], "READ_CHUNK must be at least 1")
    must_build('#include "wire.h"\n', ["-DREAD_CHUNK=1"])


@case("T-009")
def t009():
    """MAX_PAYLOAD outside 64 bytes to 1 GiB fails the build."""
    for v in ("63", "1073741825"):
        must_fail('#include "wire.h"\n', ["-DMAX_PAYLOAD=" + v],
                  "MAX_PAYLOAD must be between 64 and 1 GiB")
    for v in ("64", "1073741824"):
        must_build('#include "wire.h"\n', ["-DMAX_PAYLOAD=" + v])


@case("T-010")
def t010():
    """An empty option fails at the #if."""
    for name in ("MAX_PAYLOAD", "READ_CHUNK", "HANDSHAKE_TIMEOUT_MS", "CONNECT_TIMEOUT_MS",
                 "QUIT_TIMEOUT_MS"):
        must_fail(OPTION_HEADERS, ["-D%s=" % name], what="-D%s=" % name)


@case("T-011", timeout=900)
def t011():
    """The framing options change nothing observable."""
    failures = []
    variants = ("chunk1", "chunk3", "pay64")
    for v in variants:
        lib.proto(v)                         # build in this process, once
    safe = sorted((c for c in harness.REGISTRY.values() if c.variant_safe), key=lambda c: c.id)
    check(len(safe) >= 20, "only %d wire tests are marked variant-safe" % len(safe))
    for v in variants:
        for c in safe:
            def one(c=c, v=v):
                with lib.using_variant(v):
                    c.fn()
            out = harness.run_isolated(one, timeout=c.timeout)
            if out.kind not in ("ok", "skip") or (out.kind == "ok" and out.noise):
                failures.append("%s in %s: %s %s" % (c.id, v, out.kind, out.msg))
    check(not failures, "; ".join(failures[:6]) + (" ..." if len(failures) > 6 else ""))

    # Correctness does not depend on the chunk size: 1 MiB, one byte per peek.
    P = lib.proto("chunk1")
    a, b = net.sockpair()
    line = (b"0123456789abcdefghij" * 52429)[:1024 * 1024]
    sender = net.Worker(lambda: (a.sendall(line + b"\n"), a.close()))
    got, status = P.recv_dyn(b.fileno())
    sender.finish(60)
    eq(status, 0, "status")
    check(got == line, "a 1 MiB line did not read back intact in the READ_CHUNK=1 build")


def sources_compile(compiler_path, flags):
    bad = []
    for s in SOURCES:
        rc, out = lib.compile_source(s, flags, compiler=compiler_path)
        if rc != 0:
            bad.append("%s: %s" % (s, out.strip().splitlines()[-1][:160] if out.strip() else "?"))
    return bad


@case("T-012")
def t012():
    """The five library sources build with -Wall -Wextra -Werror."""
    problems = []
    for name, path in lib.compilers():
        bad = sources_compile(path, STRICT)
        problems += ["%s: %s" % (name, b) for b in bad]
        if PLATFORM == "macos":
            bad = sources_compile(path, STRICT + ["-std=c11", "-pedantic"])
            problems += ["%s -std=c11 -pedantic: %s" % (name, b) for b in bad]
    check(not problems, "; ".join(problems[:4]))


EXTENDED = ["-Wconversion", "-Wsign-conversion", "-Wshadow", "-Wstrict-prototypes",
            "-Wmissing-prototypes", "-Wcast-qual", "-Wformat=2", "-Wnull-dereference",
            "-Wpedantic"]


@case("T-013")
def t013():
    """An extended warning set stays quiet."""
    results = {}
    for name, path in lib.compilers():
        family = lib.cc_family(path)
        flags = EXTENDED + (["-O2", "-Wformat-truncation=2", "-Wstringop-overflow=4"]
                            if family == "gcc" else [])
        counts = {}
        for s in SOURCES:
            rc, out = lib.compile_source(s, flags, compiler=path)
            lines = set(l for l in out.splitlines() if "warning:" in l)
            counts[s] = len(lines)
        results[family] = counts
    compared = False
    for family, counts in results.items():
        bname = "warnings-%s-%s.txt" % (family, PLATFORM)        # what a compiler says depends on the headers too
        if baselines.recording():
            baselines.save(bname, counts, "warnings per source with the extended set (T-013), %s on %s"
                           % (family, PLATFORM))
            continue
        base = baselines.load(bname)
        if base is None:
            harness.note("no warning baseline for %s on %s yet (--record-baselines); findings now: %r"
                         % (family, PLATFORM, counts))
            continue
        compared = True
        worse = ["%s: %d (was %d)" % (s, n, base.get(s, 0)) for s, n in counts.items()
                 if n > base.get(s, 0)]
        check(not worse, "new warnings: " + "; ".join(worse))
    if not compared and not baselines.recording():
        skip("no warning baseline recorded for the compilers of this host yet (--record-baselines); "
             "findings now: %s" % results)


@case("T-014", FINDING, finding_on=("linux",))
def t014():
    """The sources build under a strict ISO dialect on glibc and musl."""
    dialects = [["-std=c99"], ["-std=c11"], ["-std=c99", "-pedantic"]]
    if PLATFORM == "linux":
        dialects += [["-D_POSIX_C_SOURCE=200809L"], ["-D_XOPEN_SOURCE=700"]]
    problems = []
    for name, path in lib.compilers():
        for d in dialects:
            bad = sources_compile(path, d)
            if bad:
                problems.append("%s %s: %s" % (name, " ".join(d), bad[0]))
    check(not problems, "%d dialect builds fail, e.g. %s" % (len(problems), problems[0] if problems else ""))


@case("T-015", FINDING, tags=("macos",), finding_on=("macos",))
def t015():
    """wire.c compiles under -D_POSIX_C_SOURCE=200809L on macOS."""
    flag = ["-D_POSIX_C_SOURCE=200809L"]
    for s in ("auth.c", "serve.c"):
        rc, out = lib.compile_source(s, flag)
        check(rc == 0, "%s does not compile under %s: %s" % (s, flag[0], out[-200:]))
    rc, out = lib.compile_source("wire.c", flag)
    check(rc == 0, "wire.c does not compile under %s: TCP_KEEPALIVE is hidden" % flag[0])


def link(main_text, sources, extra=(), with_sodium=True):
    d = harness.tmpdir("link")
    main = os.path.join(d, "main.c")
    with open(main, "w") as f:
        f.write(main_text)
    c_flags, ld_flags = lib.sodium() if with_sodium else ([], [])
    cmd = [lib.cc(), "-o", os.path.join(d, "a.out"), "-I", ROOT] + c_flags + list(extra) + [main] \
        + [os.path.join(ROOT, s) for s in sources] + (ld_flags if with_sodium else [])
    return lib.run(cmd)


@case("T-016")
def t016():
    """A client links without serve.c."""
    main = '''#include "auth.h"
#include "crypto.h"
#include "wire.h"
int main(void) {
    proto_conn_t c; char b[8]; size_t n;
    c.fd = -1;
    (void)proto_init(); (void)proto_connect(&c, "h", 1); proto_close(&c);
    (void)proto_recv_line(0, b, sizeof b); (void)proto_send_line(1, "x");
    (void)proto_seal_new((const unsigned char *)"x", 1, c.keys.enc_pk);
    (void)proto_unseal_new("x", c.keys.enc_pk, c.keys.enc_sk, &n);
    (void)proto_strerror(0);
    return 0;
}
'''
    rc, out = link(main, ["status.c", "wire.c", "crypto.c", "auth.c"])
    check(rc == 0, "the client does not link without serve.c: " + out[-400:])


@case("T-017")
def t017():
    """wire.c and status.c need no libsodium."""
    cmd = [lib.cc(), "-MM", "-I", ROOT, os.path.join(ROOT, "wire.c"), os.path.join(ROOT, "status.c")]
    rc, out = lib.run(cmd)
    check(rc == 0, "cannot list the dependencies: " + out[-200:])
    check("sodium" not in out and "protocol.h" not in out and "crypto.h" not in out,
          "wire.c or status.c include a libsodium-dependent header: " + out)
    main = '''#include "wire.h"
int main(void) {
    char b[8];
    (void)proto_send_line(1, "x"); (void)proto_recv_line(0, b, sizeof b);
    (void)proto_recv_line_timeout(0, b, sizeof b, 1); (void)proto_keepalive(0, 0, 0, 0);
    (void)proto_send_prefixed(1, "p", "b", 1); (void)proto_recv_line_dyn(0);
    return proto_strerror(0) == 0;
}
'''
    rc, out = link(main, ["wire.c", "status.c"], with_sodium=False)
    check(rc == 0, "wire.c and status.c do not link without libsodium: " + out[-400:])


def nm_symbols(obj):
    """(defined, undefined) global symbol names of an object file, without Mach-O underscores."""
    rc, out = lib.run(["nm", "-g", obj])
    if rc != 0:
        skip("nm is not available: " + out[:80])
    defined, undefined = [], []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 2 or line.endswith(":"):
            continue
        kind, name = parts[-2], parts[-1]
        if PLATFORM == "macos" and name.startswith("_"):
            name = name[1:]
        if kind in ("U", "u", "w", "v"):
            undefined.append(name)
        elif len(kind) == 1 and kind.isalpha() and kind.isupper():
            defined.append(name)
    return defined, undefined


HELPERS = ["write_all", "read_line_part", "strip_cr", "now_ms", "wait_readable", "recv_line_equal",
           "recv_line_until", "read_b64_key", "is_b64_char", "connect_timeout", "is_socket",
           "is_identity_hex", "reap_children", "drain", "stop_asked", "stop_fd", "in_child", "wake"]


@case("T-018")
def t018():
    """Only proto_* symbols are exported."""
    d = harness.tmpdir("obj")
    c_flags, _ = lib.sodium()
    offenders = []
    for s in SOURCES:
        obj = os.path.join(d, s + ".o")
        rc, out = lib.run([lib.cc(), "-c", "-o", obj, "-I", ROOT] + c_flags + [os.path.join(ROOT, s)])
        check(rc == 0, "cannot compile %s: %s" % (s, out[-200:]))
        defined, _ = nm_symbols(obj)
        offenders += ["%s exports %s" % (s, n) for n in defined if not n.startswith("proto_")]
        offenders += ["%s exports helper %s" % (s, n) for n in defined if n in HELPERS]
    check(not offenders, "; ".join(offenders[:6]))


@case("T-019", tags=("linux",))
def t019():
    """A 32-bit build passes the suite."""
    import suite
    suite.require_toolchain(["-m32"])
    suite.run_suite("m32", extra=["-m32"])


@case("T-020", tags=("linux",))
def t020():
    """An Alpine (musl) build passes the suite."""
    import suite
    if "musl" not in suite.libc_name():
        skip("not musl: the platforms job runs the suite inside Alpine")
    suite.run_suite("musl")


@case("T-021", PIN)
def t021():
    """The headers have no extern "C"."""
    for h in HEADERS:
        text = docsx.read(h)
        check('extern "C"' not in text, h + ' now has extern "C": a C++ consumer is supported; update this pin')
    cxx = next((shutil.which(n) for n in ("c++", "g++", "clang++") if shutil.which(n)), None)
    if not cxx:
        skip("no C++ compiler")
    d = harness.tmpdir("cxx")
    c_flags, ld_flags = lib.sodium()
    objs = []
    for s in ("status.c", "wire.c", "crypto.c", "auth.c"):
        o = os.path.join(d, s + ".o")
        rc, out = lib.run([lib.cc(), "-c", "-o", o, "-I", ROOT] + c_flags + [os.path.join(ROOT, s)])
        check(rc == 0, out[-200:])
        objs.append(o)
    main = os.path.join(d, "main.cpp")
    with open(main, "w") as f:
        f.write('#include "auth.h"\nint main() { proto_conn_t c; c.fd = -1; return proto_connect(&c, "h", 1); }\n')
    rc, out = lib.run([cxx, "-o", os.path.join(d, "a.out"), "-I", ROOT] + c_flags + [main] + objs + ld_flags)
    check(rc != 0, "a C++ file now links against the C objects: the headers work from C++")
    check("proto_connect" in out, "the C++ link failed, but not on proto_connect: " + out[-300:])


def vault_project():
    """A project directory laid out as docs.md describes, with the library at protocol/."""
    d = harness.tmpdir("vault")
    os.symlink(ROOT, os.path.join(d, "protocol"))
    for fname in ("vault-client.c", "vault-server.c"):
        text = docsx.find_block("docs.md", "c", "/* %s */" % fname)
        with open(os.path.join(d, fname), "w") as f:
            f.write(text)
    make = docsx.find_block("docs.md", "make", "client: vault-client.c")
    with open(os.path.join(d, "Makefile"), "w") as f:
        f.write(make)
    return d


@case("T-022")
def t022():
    """The Makefile in docs.md builds the worked examples."""
    d = vault_project()
    c_flags, ld_flags = lib.sodium()
    cmd = ["make", "-C", d, "client", "server", "CC=" + lib.cc(),
           "CFLAGS=-Wall -Wextra -O2 -I. " + " ".join(c_flags), "LDFLAGS=" + " ".join(ld_flags)]
    rc, out = lib.run(cmd)
    check(rc == 0, "make failed: " + out[-600:])
    for exe in ("vault-client", "vault-server"):
        check(os.access(os.path.join(d, exe), os.X_OK), exe + " was not built")


def keygen_make(d, *targets, **overrides):
    c_flags, ld_flags = lib.sodium()
    cmd = ["make", "-C", os.path.join(ROOT, "keygen"), "BUILD=" + d, "CC=" + lib.cc(),
           "CFLAGS=-Wall -Wextra -O2 -Werror " + " ".join(c_flags),
           "LDFLAGS=" + " ".join(ld_flags)]
    cmd += ["%s=%s" % kv for kv in overrides.items()]
    return lib.run(cmd + list(targets))


@case("T-023")
def t023():
    """keygen builds with -Werror, and its Makefile targets work."""
    d = harness.tmpdir("kg")
    rc, out = keygen_make(d)
    check(rc == 0, "make -C keygen failed: " + out[-500:])
    check(os.access(os.path.join(d, "keygen"), os.X_OK), "BUILD=$TMP did not put the binary in $TMP")
    rc, out = keygen_make(d, "clean")
    check(rc == 0, "make clean failed: " + out[-300:])
    check(not os.path.exists(os.path.join(d, "keygen")), "make clean left the binary")


@case("T-024", PIN)
def t024():
    """keygen/Makefile hard-codes gcc and replaces CFLAGS."""
    text = docsx.read("keygen/Makefile")
    check(re.search(r"^CC\s*=\s*gcc\s*$", text, re.M), "CC is no longer hard-coded to gcc: update this pin")
    check(re.search(r"^CFLAGS\s*=", text, re.M), "CFLAGS is no longer assigned outright: update this pin")
    check(not re.search(r"^CC\s*\?=", text, re.M), "CC is now overridable from the environment")


@case("T-025", tags=("linux",))
def t025():
    """keygen cross-compiles for AArch64."""
    cross = shutil.which("aarch64-linux-gnu-gcc")
    if not cross:
        skip("no aarch64-linux-gnu-gcc")
    d = harness.tmpdir("kg")
    c_flags, ld_flags = lib.sodium()
    rc, out = lib.run(["make", "-C", os.path.join(ROOT, "keygen"), "arm64", "BUILD=" + d,
                       "CC_ARM=" + cross, "CFLAGS=-Wall -Wextra -O2", "LDFLAGS=-lsodium"])
    if rc != 0 and ("sodium" in out):
        skip("no libsodium for aarch64 on this host")
    check(rc == 0, "make arm64 failed: " + out[-400:])
    rc, out = lib.run(["file", os.path.join(d, "keygen-arm64")])
    check("aarch64" in out.lower() or "arm aarch64" in out.lower(), "not an AArch64 executable: " + out)
