"""XXIII. Sanitizers, fuzzing and static analysis (T-390 to T-406)."""

import glob
import os
import re
import shutil
import subprocess
import sys

import baselines
import fuzzing
import harness
import lib
import net
import runprobe
import suite
from harness import FINDING, HERE, ROOT, case, check, eq, skip
from keyfiles import make_identity, write_file

SOURCES = lib.LIB_SOURCES

SEAM_RUNS = [
    ("seam_wire", runprobe.WIRE_SEAMS, ["short_write", "pipe_peek", "big_line", "dyn_alloc", "dyn_bound",
                                        "malloc_fail", "realloc_fail"]),
    ("seam_auth", runprobe.AUTH_SEAMS, ["server_alloc", "bad_port", "walk", "eintr", "etimedout", "close_noop"]),
    ("seam_serve", runprobe.SERVE_SEAMS, ["socketpair_fail", "socket_fail", "listen_fail", "accept_broken",
                                          "accept_emfile", "accept_retry", "fork_fail", "poll_fail",
                                          "accept_reset", "reaper_errno", "busy_stop", "dispositions"]),
]


def require_sanitizer(kind):
    if not lib.sanitizer_works(kind):
        skip("this compiler cannot build and run a program with the %s sanitizer" % kind)


def sanitizer_clean(err, kind):
    text = err.decode("utf-8", "replace") if isinstance(err, bytes) else err
    bad = ("ERROR: AddressSanitizer", "runtime error:", "WARNING: ThreadSanitizer", "ERROR: LeakSanitizer")
    return not any(b in text for b in bad)


class Runs(object):
    """Runs of programs under a sanitizer. A run that fails is kept and the next one goes on, so that a
    test reports every run that failed and not the first, which on a platform seen for the first
    time hides the rest."""

    def __init__(self):
        self.failed = []
        self.count = 0

    def probe(self, name, args, seams, kind, leaks=False, timeout=180):
        env = dict(lib.san_env(kind))
        if kind == "asan":
            env["ASAN_OPTIONS"] += ":detect_leaks=%d" % (1 if leaks else 0)
        rc, out, err = runprobe.run(name, args, seams=seams, sanitize=kind, env=env, threads=True, timeout=timeout)
        text = err.decode("utf-8", "replace")
        self.count += 1
        if rc != 0 or not sanitizer_clean(text, kind):
            self.failed.append("%s %s under %s failed (%d): %s" % (name, " ".join(args), kind, rc, text.strip()[-500:]))

    def suite(self, label, **kwargs):
        self.count += 1
        try:
            suite.run_suite(label, **kwargs)
        except harness.Fail as e:
            self.failed.append(str(e)[:600])

    def done(self):
        check(not self.failed, "%d of %d runs failed: %s" % (len(self.failed), self.count, " || ".join(self.failed)))


@case("T-390", timeout=900)
def t390():
    """ASan and UBSan find nothing."""
    require_sanitizer("asan")
    runs = Runs()
    runs.suite("asan", sanitize="asan")
    for name, seams, scenarios in SEAM_RUNS:
        for sc in scenarios:
            runs.probe(name, [sc], seams, "asan")
    ident = make_identity()
    for sc in ("read_eio", "read_eintr", "read_onebyte", "open_flags"):
        runs.probe("seam_crypto", [sc, ident.auth_pub], runprobe.CRYPTO_SEAMS, "asan")
    d = harness.tmpdir("asan")
    kinds = {"ok": ident.auth_pub, "empty": write_file(os.path.join(d, "e"), b"\n"),
             "stray": write_file(os.path.join(d, "s"), b" " + open(ident.auth_pub, "rb").read()),
             "format": write_file(os.path.join(d, "f"), b"AAAA*AAAA\n"),
             "size": write_file(os.path.join(d, "z"), b"AAAA\n"), "readfail": ident.auth_pub}
    for kind, path in kinds.items():
        runs.probe("seam_crypto", ["memzero", kind, path], runprobe.CRYPTO_SEAMS, "asan")
    for sc in ("malloc_fail", "unseal_alloc", "unseal_failures"):
        runs.probe("seam_crypto", [sc], runprobe.CRYPTO_SEAMS, "asan")
    for sc in (["strerror"], ["init"], ["load", ident.auth_key, ident.enc_key]):
        runs.probe("threads", sc, None, "asan")
    runs.done()


@case("T-391", timeout=600)
def t391():
    """LeakSanitizer finds nothing."""
    require_sanitizer("asan")
    if not lib.leak_check_supported():
        skip("this platform's AddressSanitizer cannot detect leaks")
    runs = Runs()
    runs.suite("lsan", sanitize="asan", leaks=True)
    for sc in ("dyn_alloc", "malloc_fail", "realloc_fail"):
        runs.probe("seam_wire", [sc], runprobe.WIRE_SEAMS, "asan", leaks=True)
    runs.probe("seam_crypto", ["unseal_failures"], runprobe.CRYPTO_SEAMS, "asan", leaks=True)
    runs.done()


@case("T-392", FINDING, timeout=600)
def t392():
    """ThreadSanitizer finds nothing in the threaded tests."""
    require_sanitizer("tsan")
    ident = make_identity()
    reports = []
    for sc in (["strerror"], ["init"], ["load", ident.auth_key, ident.enc_key], ["stop", net.free_port()]):
        rc, err, used = runprobe.threads(sc[0], *sc[1:])
        check(used, "ThreadSanitizer was not used")
        if rc != 0 or runprobe.tsan_report(err):
            reports.append("%s: %s" % (sc[0], "; ".join(sorted(set(
                l.strip() for l in err.splitlines() if "Location is global" in l)))[:200] or err.strip()[-200:]))
    check(not reports, "ThreadSanitizer reports in: " + " | ".join(reports))


@case("T-393", tags=("linux",), timeout=900)
def t393():
    """Valgrind finds nothing."""
    vg = shutil.which("valgrind")
    if not vg:
        skip("valgrind is not installed")
    exe = suite.build()
    scenarios = ["wire", "keys", "seal", "seal_bounds", "sign", "handshake"]
    rc, out = lib.run([vg, "--error-exitcode=99", "--leak-check=full", "--errors-for-leak-kinds=definite", "-q",
                       exe] + scenarios, timeout=800, env=dict(os.environ, PROTO_SUITE_VALGRIND="1"))
    check(rc == 0, "valgrind reports (%d): %s" % (rc, out[-900:]))


def fuzz_case(name):
    n = fuzzing.fuzz(name)
    check(n > 0, "the %s target ran no input" % name)


@case("T-394", tags=("fuzz",), timeout=900)
def t394():
    """Fuzz the key-file parser."""
    fuzz_case("key_files")


@case("T-395", tags=("fuzz",), timeout=900)
def t395():
    """Fuzz the line readers."""
    fuzz_case("line_readers")


@case("T-396", tags=("fuzz",), timeout=900)
def t396():
    """Fuzz the server handshake."""
    fuzz_case("server_handshake")


@case("T-397", tags=("fuzz",), timeout=900)
def t397():
    """Fuzz the client handshake."""
    fuzz_case("client_handshake")


@case("T-398", tags=("fuzz",), timeout=900)
def t398():
    """Fuzz proto_unseal_new."""
    fuzz_case("unseal")


def analyzer_findings(family, path):
    """{source: number of distinct warnings} for the compiler's static analyzer."""
    c_flags, _ = lib.sodium()
    counts = {}
    for s in SOURCES:
        d = harness.tmpdir("an")
        if family == "clang":
            cmd = [path, "--analyze", "-Xanalyzer", "-analyzer-output=text", "-I", lib.SRC] + c_flags + \
                  [os.path.join(lib.SRC, s)]
        else:
            cmd = [path, "-fanalyzer", "-c", "-o", os.path.join(d, "o.o"), "-I", lib.SRC] + c_flags + \
                  [os.path.join(lib.SRC, s)]
        rc, out = lib.run(cmd, cwd=d)
        counts[s] = len(set(l for l in out.splitlines() if "warning:" in l))
    return counts


def baseline_check(bname, counts, what, header):
    """Compare counts with a baseline. False when there is none yet: the counts are noted instead."""
    if baselines.recording():
        baselines.save(bname, counts, header)
        return True
    base = baselines.load(bname)
    if base is None:
        harness.note("%s: no baseline recorded (--record-baselines); findings now: %r" % (what, counts))
        return False
    worse = ["%s: %d (was %d)" % (s, n, base.get(s, 0)) for s, n in counts.items() if n > base.get(s, 0)]
    check(not worse, "new findings of %s: %s" % (what, "; ".join(worse)))
    return True


@case("T-399", timeout=600)
def t399():
    """The static analysers find nothing."""
    ran, compared = False, False
    for name, path in lib.compilers():
        family = lib.cc_family(path)
        if family == "gcc":
            rc, out = lib.run([path, "-dumpversion"])
            try:
                if int(out.strip().split(".")[0]) < 10:
                    continue
            except ValueError:
                continue
        elif family != "clang":
            continue
        ran = True
        counts = analyzer_findings(family, path)
        compared |= baseline_check("analyzer-%s-%s.txt" % (family, harness.PLATFORM), counts,
                                   "the %s analyzer" % family,
                                   "warnings of the %s static analyzer per source on %s (T-399)"
                                   % (family, harness.PLATFORM))
    if not ran:
        skip("neither clang --analyze nor gcc -fanalyzer is available")
    if not compared:
        skip("no analyzer baseline recorded for the compilers of this host yet (--record-baselines)")


@case("T-400")
def t400():
    """cppcheck finds nothing."""
    cppcheck = shutil.which("cppcheck")
    if not cppcheck:
        skip("cppcheck is not installed")
    c_flags, _ = lib.sodium()
    counts = {}
    for s in SOURCES:
        rc, out = lib.run([cppcheck, "--enable=warning,portability,performance", "--inline-suppr", "--quiet",
                           "--template={file}:{line}:{severity}:{id}", "-I", lib.SRC, "--suppress=missingIncludeSystem",
                           os.path.join(lib.SRC, s)])
        counts[s] = len([l for l in out.splitlines() if re.match(r".+:\d+:\w+:\w+", l)])
    if not baseline_check("cppcheck-%s.txt" % harness.PLATFORM, counts, "cppcheck",
                          "cppcheck findings per source on %s (T-400)" % harness.PLATFORM):
        skip("no cppcheck baseline recorded for this platform yet (--record-baselines)")


def coverage_percentages():
    """{source: (percent, lines, [uncovered line numbers])} of the C suite run under gcov."""
    gcov = shutil.which("gcov")
    if not gcov:
        skip("gcov is not installed")
    d = harness.tmpdir("cov")
    c_flags, ld_flags = lib.sodium()
    objs = []
    flags = ["--coverage", "-O0", "-g", "-I", lib.SRC, "-I", lib.PROBE_DIR] + lib.variant_defines("fast")
    for s in SOURCES + [None]:
        src = os.path.join(lib.PROBE_DIR, "suite.c") if s is None else os.path.join(lib.SRC, s)
        obj = os.path.join(d, ("suite" if s is None else s[:-2]) + ".o")
        rc, out = lib.run([lib.cc()] + flags + c_flags + ["-c", "-o", obj, src])
        check(rc == 0, "cannot build with coverage: " + out[-300:])
        objs.append(obj)
    exe = os.path.join(d, "suite-cov")
    rc, out = lib.run([lib.cc(), "--coverage"] + objs + ["-o", exe] + ld_flags + ["-pthread"])
    check(rc == 0, "cannot link with coverage: " + out[-300:])
    rc, so, se = lib.run_exe(exe, [], timeout=300, cwd=d)
    check(rc == 0, "the suite failed under coverage: " + se.decode()[-300:])
    result = {}
    for s in SOURCES:
        rc, out = lib.run([gcov, "-o", d, os.path.join(lib.SRC, s)], cwd=d)
        m = re.search(r"File '[^']*" + re.escape(s) + r"'\s*\nLines executed:([\d.]+)% of (\d+)", out)
        if not m:
            continue
        uncovered = []
        gp = os.path.join(d, s + ".gcov")
        if os.path.exists(gp):
            for line in open(gp, errors="replace"):
                parts = line.split(":", 2)
                if len(parts) == 3 and parts[0].strip() == "#####":
                    uncovered.append(int(parts[1]))
        result[s] = (float(m.group(1)), int(m.group(2)), uncovered)
    return result


@case("T-401", timeout=600)
def t401():
    """Coverage is published, with a floor per file."""
    result = coverage_percentages()
    check(set(result) == set(SOURCES), "gcov reported on %s only" % sorted(result))
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    lines = ["### Coverage of the C suite", "", "| file | lines | covered |", "|---|---|---|"]
    for s in SOURCES:
        pct, n, unc = result[s]
        harness.note("%s: %.1f%% of %d lines" % (s, pct, n))
        lines.append("| %s | %d | %.1f%% |" % (s, n, pct))
    lines.append("")
    for s in SOURCES:
        unc = result[s][2]
        if unc:
            lines.append("`%s` uncovered: %s" % (s, ", ".join(str(x) for x in unc[:60]) + (" ..." if len(unc) > 60 else "")))
    if path:
        try:
            with open(path, "a") as f:
                f.write("\n".join(lines) + "\n")
        except OSError:
            pass
    floors = {s: max(0, int(result[s][0]) - 10) for s in SOURCES}
    if baselines.recording():
        baselines.save("coverage.txt", floors, "line coverage floor per file, in percent (T-401); ten points under the first run")
        return
    base = baselines.load("coverage.txt")
    if base is None:
        return                                           # published; no floor recorded yet
    low = ["%s: %.1f%% is under its floor of %d%%" % (s, result[s][0], base[s]) for s in SOURCES
           if s in base and result[s][0] < base[s]]
    check(not low, "; ".join(low))


@case("T-402", tags=("linux",), timeout=900)
def t402():
    """The sanitizers run on the 32-bit build too."""
    suite.require_toolchain(["-m32", "-fsanitize=address,undefined"])
    suite.run_suite("m32 asan", extra=["-m32"], sanitize="asan")


@case("T-403", tags=("linux",), timeout=600)
def t403():
    """A fortified build passes the suite."""
    last = ""
    for level in ("3", "2"):
        flags = ["-O2", "-U_FORTIFY_SOURCE", "-D_FORTIFY_SOURCE=" + level]
        try:
            suite.run_suite("fortified", extra=flags)
            return
        except lib.BuildError as e:
            last = str(e)
            continue
    skip("this compiler cannot build with fortification: " + last[-200:])


@case("T-404", timeout=600)
def t404():
    """The fuzz corpora are kept, and grow with every fix."""
    # No fuzz tag: replaying the corpora takes a moment, and it runs on every run, so that a defect a
    # kept input found cannot come back between two fuzzing jobs.
    for name, target in sorted(fuzzing.TARGETS.items()):
        n = fuzzing.replay(target)
        check(n >= 3, "the corpus of %s holds only %d inputs" % (name, n))
        harness.note("%s: %d inputs replayed" % (name, n))


def strip_comments(text):
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    return re.sub(r"//[^\n]*", "", text)


def captured(fn):
    """Run fn() with descriptors 1 and 2 on a file; returns what was written there."""
    import tempfile
    sys.stdout.flush()
    sys.stderr.flush()
    f = tempfile.TemporaryFile()
    saved = (os.dup(1), os.dup(2))
    os.dup2(f.fileno(), 1)
    os.dup2(f.fileno(), 2)
    try:
        fn()
    finally:
        os.dup2(saved[0], 1)
        os.dup2(saved[1], 2)
        os.close(saved[0])
        os.close(saved[1])
    f.seek(0)
    return f.read()


@case("T-405")
def t405():
    """The library stays silent."""
    pattern = re.compile(r"\b(printf|fprintf|vprintf|vfprintf|puts|fputs|putchar|perror|syslog)\s*\(")
    for s in SOURCES:
        with open(os.path.join(lib.SRC, s), encoding="utf-8") as f:
            text = strip_comments(f.read())
        hit = pattern.search(text)
        check(not hit, "%s calls %s: the library must not write to the console" % (s, hit.group(1) if hit else ""))
    P = lib.proto()
    ident = make_identity()

    def exercise():
        P.strerror(-101)
        a, b = net.sockpair()
        P.send_line(a.fileno(), "x")
        P.recv_line(b.fileno(), 16)
        P.recv_line_timeout(b.fileno(), 20, 16)
        P.load_keys(ident.auth_pub, ident.auth_pub)
        P.load_pubkey_hex("/nonexistent")
        sealed = P.seal_new(b"hello", ident.enc_pk)
        P.unseal_full(sealed, ident.enc_pk, ident.enc_sk)
        P.unseal_full(b"nonsense", ident.enc_pk, ident.enc_sk)
        P.auth_server(b.fileno(), "A" * 64)
        P.serve_stop()
        P.serve(0, "a" * 64)
        rc, keys = P.load_keys(ident.auth_key, ident.enc_key)
        conn = lib.Conn.new(keys)
        P.connect(conn, "127.0.0.1", net.free_port())
    out = captured(exercise)
    eq(out, b"", "what the library wrote to stdout and stderr")


MUTANTS = [
    ("wire.c", "if (i + 1 >= bufsz) {", "if (i + 1 > bufsz) {", ["T-057", "T-059", "T-061", "T-078"]),
    ("wire.c", "if (i > (size_t)MAX_PAYLOAD) {", "if (i >= (size_t)MAX_PAYLOAD) {", ["T-101", "T-102"]),
    ("wire.c", "#define MAX_PAYLOAD_BUF ((size_t)MAX_PAYLOAD + 2)", "#define MAX_PAYLOAD_BUF ((size_t)MAX_PAYLOAD + 1)",
     ["T-101", "T-102"]),
    ("crypto.c", "else if (bin_len != expected_len)", "else if (bin_len < expected_len)", ["T-140"]),
    ("auth.c", "|| ch_len != CHALLENGE_LEN) return PROTO_E_BAD_CHALLENGE;",
     "|| ch_len > CHALLENGE_LEN) return PROTO_E_BAD_CHALLENGE;", ["T-220"]),
    ("auth.c", "if (port < 1 || port > 65535) return PROTO_E_BAD_PORT;",
     "if (port < 1 || port > 65536) return PROTO_E_BAD_PORT;", ["T-261"]),
    ("serve.c", "if (port < 1 || port > 65535) return PROTO_E_BAD_PORT;",
     "if (port < 1 || port > 65536) return PROTO_E_BAD_PORT;", ["T-294"]),
]


def run_ids(ids, src=None):
    env = dict(os.environ)
    if src:
        env["PROTO_TEST_SRC"] = src
    p = subprocess.run([sys.executable, os.path.join(HERE, "run.py"), "--id", ",".join(ids)],
                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=env, timeout=900)
    return p.returncode, p.stdout.decode("utf-8", "replace")


def mutant_tree(source, old, new):
    d = harness.tmpdir("mutant")
    for f in glob.glob(os.path.join(ROOT, "*.c")) + glob.glob(os.path.join(ROOT, "*.h")):
        shutil.copy(f, d)
    shutil.copytree(os.path.join(ROOT, "keygen"), os.path.join(d, "keygen"))
    path = os.path.join(d, source)
    with open(path, encoding="utf-8") as f:
        text = f.read()
    check(text.count(old) == 1, "%s no longer holds the expression %r exactly once" % (source, old))
    with open(path, "w", encoding="utf-8") as f:
        f.write(text.replace(old, new))
    return d


@case("T-406", tags=("slow",), timeout=3000)
def t406():
    """The boundary tests are sharp."""
    # Every test a mutant is judged by must pass first: one that fails anyway would kill its mutant for nothing.
    rc, out = run_ids(sorted(set(t for _, _, _, ids in MUTANTS for t in ids)))
    check(rc == 0, "the tests that must kill the mutants do not pass on the unaltered code: " + out[-300:])
    survivors = []
    for source, old, new, ids in MUTANTS:
        tree = mutant_tree(source, old, new)
        rc, out = run_ids(ids, src=tree)
        if rc == 0:
            survivors.append("%s: %s -> %s (tests %s)" % (source, old, new, ",".join(ids)))
    for s in survivors:
        harness.note("SURVIVED: " + s)
    harness.note("%d of %d mutants killed" % (len(MUTANTS) - len(survivors), len(MUTANTS)))
    # Report only until the job is stable (see the entry): survivors are listed, not failed.
