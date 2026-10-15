"""Test harness for the proto library.

Every case runs in a forked child with its own process group, a private
temporary directory, captured stdout and stderr, and a hard deadline. A case
that crashes, hangs or leaves processes behind therefore fails that case and
nothing else. The parent judges the child by its wait status and by the short
report the child writes on a pipe.

Verdicts, as in README.md:

    guard    must pass.
    pin      must pass; it records behaviour nobody documented.
    finding  fails today by design (XFAIL). If it passes (XPASS) the run
             fails, so the day a fix lands the test is turned into a guard.
"""

import json
import os
import platform as _platform
import select
import shutil
import signal
import stat
import sys
import tempfile
import time
import traceback

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

GUARD, PIN, FINDING = "guard", "pin", "finding"

# Seconds a case may run before the parent kills it. Slow cases ask for more.
DEFAULT_TIMEOUT = int(os.environ.get("PROTO_TEST_TIMEOUT", "60"))

# Multiplies the slack of every timing window, for slow hosts and emulators.
SLACK = float(os.environ.get("PROTO_TEST_SLACK", "1"))


def _detect_platform():
    p = sys.platform
    if p.startswith("linux"):
        return "linux"
    if p == "darwin":
        return "macos"
    for name in ("freebsd", "openbsd", "netbsd", "dragonfly"):
        if p.startswith(name):
            return name
    return p


PLATFORM = _detect_platform()
OPTS = None         # the parsed command line, set by run.py
ARCH = _platform.machine().lower()
if ARCH in ("amd64", "x86_64"):
    ARCH = "x86_64"
elif ARCH in ("aarch64", "arm64"):
    ARCH = "arm64"

SECTIONS = [
    ("I", 1, 25, "Build, configuration and headers"),
    ("II", 26, 34, "proto_strerror and the status codes"),
    ("III", 35, 36, "proto_init"),
    ("IV", 37, 51, "proto_send_line, proto_send_prefixed"),
    ("V", 52, 79, "proto_recv_line"),
    ("VI", 80, 93, "proto_recv_line_timeout"),
    ("VII", 94, 111, "proto_recv_line_dyn, proto_recv_line_dyn_status"),
    ("VIII", 112, 122, "proto_keepalive"),
    ("IX", 123, 158, "Key files"),
    ("X", 159, 170, "proto_load_keys"),
    ("XI", 171, 178, "proto_load_pubkey_hex"),
    ("XII", 179, 202, "proto_seal, proto_seal_new, proto_unseal_new"),
    ("XIII", 203, 211, "proto_sign_challenge, proto_verify_challenge"),
    ("XIV", 212, 230, "proto_auth_client"),
    ("XV", 231, 253, "proto_auth_server"),
    ("XVI", 254, 281, "proto_connect"),
    ("XVII", 282, 291, "proto_close"),
    ("XVIII", 292, 327, "proto_serve"),
    ("XIX", 328, 347, "proto_serve_stop and draining"),
    ("XX", 348, 354, "Process-wide effects of proto_serve"),
    ("XXI", 355, 373, "The keygen tool"),
    ("XXII", 374, 389, "End-to-end and integration"),
    ("XXIII", 390, 406, "Sanitizers, fuzzing and static analysis"),
    ("XXIV", 407, 416, "Documentation and source-level invariants"),
    ("XXV", 417, 423, "Load and soak"),
    ("XXVI", 424, 425, "Found by the fuzz targets"),
]


def section_of(tid):
    n = int(tid.split("-")[1])
    for numeral, lo, hi, title in SECTIONS:
        if lo <= n <= hi:
            return numeral
    return "?"


class Fail(AssertionError):
    """An assertion of a case did not hold."""


class Skip(Exception):
    """The case does not apply here."""


class Timeout(Exception):
    """The case ran past its own deadline."""


def fail(msg):
    raise Fail(msg)


def skip(reason):
    raise Skip(reason)


def check(cond, msg="check failed"):
    if not cond:
        raise Fail(msg)


def eq(got, want, what="value"):
    if got != want:
        raise Fail("%s: got %r, want %r" % (what, got, want))


def between(value, lo, hi, what="value"):
    if not (lo <= value <= hi):
        raise Fail("%s: %r is outside [%r, %r]" % (what, value, lo, hi))


def slack_ms(ms):
    """Extra milliseconds a timing window allows above its lower bound."""
    return int(ms * SLACK)


# ---------------------------------------------------------------- registry

class Case(object):
    def __init__(self, tid, verdict, tags, fn, finding_on, variant_safe,
                 timeout):
        self.id = tid
        self.verdict = verdict
        self.tags = frozenset(tags)
        self.fn = fn
        self.finding_on = finding_on
        self.variant_safe = variant_safe
        self.timeout = timeout
        self.title = (fn.__doc__ or "").strip().splitlines()[0] if fn.__doc__ else ""
        self.section = section_of(tid)

    def effective_verdict(self):
        """A finding that only manifests on some platforms is a guard elsewhere."""
        if (self.verdict == FINDING and self.finding_on is not None
                and PLATFORM not in self.finding_on):
            return GUARD
        return self.verdict


REGISTRY = {}


def case(tid, verdict=GUARD, tags=(), finding_on=None, variant_safe=False,
         timeout=None):
    """Register fn as test tid of the catalogue."""
    def deco(fn):
        if tid in REGISTRY:
            raise RuntimeError("duplicate test id " + tid)
        REGISTRY[tid] = Case(tid, verdict, tags, fn, finding_on, variant_safe,
                             timeout or (600 if "slow" in tags else DEFAULT_TIMEOUT))
        fn.case = REGISTRY[tid]
        return fn
    return deco


# ------------------------------------------------------- per-case context

TMP = None          # private directory of the running case
NOTES = []          # lines the case wants to show in verbose mode


def note(msg):
    NOTES.append(str(msg))


def tmpdir(prefix="t"):
    """A fresh directory inside the case's private one."""
    return tempfile.mkdtemp(prefix=prefix, dir=TMP)


# ----------------------------------------------------------- isolated run

class Outcome(object):
    def __init__(self, kind, msg="", elapsed=0.0, notes=None, noise=b""):
        self.kind = kind      # ok fail error skip crash timeout
        self.msg = msg
        self.elapsed = elapsed
        self.notes = notes or []
        self.noise = noise


def _rmtree_force(path):
    def onerror(func, p, exc):
        try:
            os.chmod(os.path.dirname(p), 0o700)
            os.chmod(p, 0o700)
            func(p)
        except OSError:
            pass
    try:
        for dirpath, dirnames, filenames in os.walk(path):
            try:
                os.chmod(dirpath, 0o700)
            except OSError:
                pass
        shutil.rmtree(path, onerror=onerror)
    except OSError:
        pass


def _read_pipe(r):
    chunks = []
    try:
        os.set_blocking(r, False)
        while True:
            try:
                data = os.read(r, 65536)
            except BlockingIOError:
                break
            if not data:
                break
            chunks.append(data)
    except OSError:
        pass
    return b"".join(chunks)


def in_child(fn, timeout=30):
    """Run fn() in a forked child and say how it ended: ('exit', code) or
    ('signal', number). For calls that are expected to crash."""
    sys.stdout.flush()
    sys.stderr.flush()
    pid = os.fork()
    if pid == 0:
        code = 0
        try:
            fn()
        except BaseException:
            code = 1
        os._exit(code)
    deadline = time.monotonic() + timeout
    while True:
        done, ws = os.waitpid(pid, os.WNOHANG)
        if done:
            break
        if time.monotonic() > deadline:
            os.kill(pid, signal.SIGKILL)
            _, ws = os.waitpid(pid, 0)
            return ("timeout", 0)
        time.sleep(0.002)
    if os.WIFSIGNALED(ws):
        return ("signal", os.WTERMSIG(ws))
    return ("exit", os.WEXITSTATUS(ws))


def run_isolated(fn, timeout=DEFAULT_TIMEOUT, capture=True, setup=None):
    """Run fn() in a forked child and report how it ended."""
    global TMP
    sys.stdout.flush()
    sys.stderr.flush()
    base = tempfile.mkdtemp(prefix="proto-test-")
    case_tmp = os.path.join(base, "tmp")
    os.mkdir(case_tmp)
    out_path = os.path.join(base, "output")
    r, w = os.pipe()
    t0 = time.monotonic()
    pid = os.fork()
    if pid == 0:
        status = 0
        try:
            try:
                os.setpgid(0, 0)
            except OSError:
                pass
            os.close(r)
            if capture:
                fd = os.open(out_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
                os.dup2(fd, 1)
                os.dup2(fd, 2)
                os.close(fd)
            nul = os.open(os.devnull, os.O_RDONLY)
            os.dup2(nul, 0)
            os.close(nul)
            TMP = case_tmp
            del NOTES[:]
            os.chdir(case_tmp)

            def on_alarm(signum, frame):
                raise Timeout("case ran past its own deadline")
            signal.signal(signal.SIGALRM, on_alarm)
            signal.alarm(max(1, int(timeout) - 2))
            report = {"kind": "ok", "msg": ""}
            try:
                if setup:
                    setup()
                fn()
            except Skip as e:
                report = {"kind": "skip", "msg": str(e)}
            except Fail as e:
                report = {"kind": "fail", "msg": str(e)}
            except Timeout as e:
                report = {"kind": "timeout", "msg": str(e)}
            except AssertionError as e:
                report = {"kind": "fail", "msg": "assertion: %s" % (e,)}
            except BaseException:
                tb = traceback.format_exc().strip().splitlines()
                report = {"kind": "error", "msg": " | ".join(tb[-4:])}
            signal.alarm(0)
            report["notes"] = NOTES[:50]
            data = json.dumps(report).encode("utf-8")[:60000]
            os.write(w, data)
        except BaseException:
            status = 3
        finally:
            os._exit(status)
    # parent
    os.close(w)
    try:
        os.setpgid(pid, pid)
    except OSError:
        pass
    try:
        grouped = os.getpgid(pid) == pid and pid != os.getpgrp()
    except OSError:
        grouped = False
    deadline = t0 + timeout
    ws = None
    timed_out = False
    while True:
        try:
            done, ws = os.waitpid(pid, os.WNOHANG)
        except ChildProcessError:
            done, ws = pid, 0
        if done:
            break
        if time.monotonic() > deadline:
            timed_out = True
            try:
                if grouped:
                    os.killpg(pid, signal.SIGKILL)
                else:
                    os.kill(pid, signal.SIGKILL)
            except OSError:
                pass
            try:
                _, ws = os.waitpid(pid, 0)
            except ChildProcessError:
                ws = 0
            break
        time.sleep(0.002)
    elapsed = time.monotonic() - t0
    if grouped:
        try:
            os.killpg(pid, signal.SIGKILL)       # stragglers of the case
        except OSError:
            pass
    raw = _read_pipe(r)
    os.close(r)
    noise = b""
    if capture:
        try:
            with open(out_path, "rb") as f:
                noise = f.read(4000)
        except OSError:
            pass
    _rmtree_force(base)

    if timed_out:
        return Outcome("timeout", "killed after %d s" % timeout, elapsed, noise=noise)
    if os.WIFSIGNALED(ws):
        sig = os.WTERMSIG(ws)
        try:
            name = signal.Signals(sig).name
        except ValueError:
            name = str(sig)
        return Outcome("crash", "killed by " + name, elapsed, noise=noise)
    if not raw:
        return Outcome("error", "child exited %d without a report" % os.WEXITSTATUS(ws),
                       elapsed, noise=noise)
    try:
        report = json.loads(raw.decode("utf-8"))
    except ValueError:
        return Outcome("error", "unreadable report", elapsed, noise=noise)
    return Outcome(report["kind"], report.get("msg", ""), elapsed,
                   report.get("notes", []), noise)


# ------------------------------------------------------------- selection

TAG_SKIPS = {
    "linux": lambda: None if PLATFORM == "linux" else "Linux only",
    "macos": lambda: None if PLATFORM == "macos" else "macOS only",
    "root": lambda: None if os.geteuid() == 0 else "needs root",
    "notroot": lambda: "must not run as root" if os.geteuid() == 0 else None,
}


def skip_reason(c, opts):
    for tag, probe in TAG_SKIPS.items():
        if tag in c.tags:
            reason = probe()
            if reason:
                return reason
    if "slow" in c.tags and not opts.slow:
        return "slow test: use --slow"
    if "fuzz" in c.tags and not opts.fuzz:
        return "fuzz target: use --fuzz"
    if opts.only_slow and "slow" not in c.tags:
        return "not slow"
    return None


def _number(text):
    return int(text.strip().upper().replace("T-", ""))


def parse_ids(spec):
    """'T-057', '57', 'T-057..T-062' and comma lists of those."""
    ids = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if ".." in part:
            a, b = part.split("..", 1)
            ids.update("T-%03d" % n for n in range(_number(a), _number(b) + 1))
        else:
            ids.add("T-%03d" % _number(part))
    return ids


def select_cases(opts):
    cases = sorted(REGISTRY.values(), key=lambda c: c.id)
    if opts.id:
        wanted = set()
        for spec in opts.id:
            wanted |= parse_ids(spec)
        cases = [c for c in cases if c.id in wanted]
    if opts.section:
        wanted = set(s.upper() for s in opts.section)
        arabic = {"%d" % (i + 1): s[0] for i, s in enumerate(SECTIONS)}
        wanted = set(arabic.get(s, s) for s in wanted)
        cases = [c for c in cases if c.section in wanted]
    if opts.tag:
        cases = [c for c in cases if set(opts.tag) & c.tags]
    return cases


# --------------------------------------------------------------- reporting

class Tally(object):
    def __init__(self):
        self.counts = {"PASS": 0, "FAIL": 0, "XFAIL": 0, "XPASS": 0, "SKIP": 0}
        self.problems = []
        self.skips = []
        self.xfails = []


def judge(c, out):
    """Turn an Outcome into PASS, FAIL, XFAIL, XPASS or SKIP."""
    verdict = c.effective_verdict()
    if out.kind == "skip":
        return "SKIP", out.msg
    problem = out.kind != "ok"
    msg = out.msg
    if not problem and out.noise:
        problem = True
        msg = "the library wrote to stdout or stderr: %r" % out.noise[:120]
    if verdict == FINDING:
        if out.kind == "error":
            # An exception is the case being wrong, not the finding holding: it must not hide there.
            return "FAIL", "error: %s" % msg
        if problem:
            return "XFAIL", msg
        return "XPASS", "the finding now passes: make it a guard"
    if problem:
        return "FAIL", ("%s: %s" % (out.kind, msg)) if out.kind != "fail" else msg
    return "PASS", ""


def run_selected(opts):
    cases = select_cases(opts)
    tally = Tally()
    t_start = time.monotonic()
    current = None
    for c in cases:
        if opts.verbose and c.section != current:
            current = c.section
            title = [s[3] for s in SECTIONS if s[0] == current][0]
            print("\n== %s. %s" % (current, title))
        reason = skip_reason(c, opts)
        if reason:
            tally.counts["SKIP"] += 1
            tally.skips.append((c.id, reason))
            if opts.verbose:
                print("SKIP   %s  %s" % (c.id, reason))
            continue
        out = run_isolated(c.fn, c.timeout)
        status, msg = judge(c, out)
        tally.counts[status] += 1
        if status == "SKIP":
            tally.skips.append((c.id, msg))
        if status == "FAIL" or status == "XPASS":
            tally.problems.append((c.id, status, msg))
        if status == "XFAIL":
            tally.xfails.append((c.id, msg))
        if status in ("FAIL", "XPASS", "XFAIL", "SKIP") or opts.verbose:
            line = "%-6s %s  %5.2fs  %s" % (status, c.id, out.elapsed, c.title)
            if msg:
                line += "\n         " + msg
            print(line)
        else:
            sys.stdout.write(".")
            if sum(tally.counts.values()) % 60 == 0:
                sys.stdout.write("\n")
        if opts.verbose:
            for n in out.notes:
                print("         note: " + n)
        sys.stdout.flush()
    elapsed = time.monotonic() - t_start
    print()
    print("%s %s: %d passed, %d failed, %d expected to fail (findings), "
          "%d fixed findings (XPASS), %d skipped, in %.1f s"
          % (PLATFORM, ARCH, tally.counts["PASS"], tally.counts["FAIL"],
             tally.counts["XFAIL"], tally.counts["XPASS"], tally.counts["SKIP"],
             elapsed))
    write_summary(tally, elapsed)
    return tally


def write_summary(tally, elapsed):
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not path:
        return
    try:
        with open(path, "a") as f:
            f.write("### proto tests on %s %s\n\n" % (PLATFORM, ARCH))
            f.write("| passed | failed | expected to fail | fixed (XPASS) | skipped | time |\n")
            f.write("|---|---|---|---|---|---|\n")
            c = tally.counts
            f.write("| %d | %d | %d | %d | %d | %.0f s |\n\n"
                    % (c["PASS"], c["FAIL"], c["XFAIL"], c["XPASS"], c["SKIP"], elapsed))
            for tid, status, msg in tally.problems:
                f.write("- **%s** %s: %s\n" % (status, tid, msg))
            if tally.skips:
                f.write("\nSkipped: " + ", ".join("%s (%s)" % s for s in tally.skips[:80]) + "\n")
    except OSError:
        pass
