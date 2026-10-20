"""Building the library under test, and binding it with ctypes.

The five sources are compiled into a shared library per build variant (the
timeouts and framing options are compile-time), cached under testing/.build/.
Programs that need more than a call into the library -- fault-injection seams,
sanitizers, a server -- are built from testing/probes/ against the same sources.
"""

import contextlib
import ctypes
import ctypes.util
import fcntl
import glob
import hashlib
import os
import re
import shutil
import subprocess
import sys

import harness
from harness import HERE, PLATFORM, ROOT

# Where the library's sources are. The mutation test (T-406) points it at a copy
# with one expression altered.
SRC = os.environ.get("PROTO_TEST_SRC") or ROOT
BUILD_DIR = os.path.join(HERE, ".build")
PROBE_DIR = os.path.join(HERE, "probes")
LIB_SOURCES = ["status.c", "wire.c", "crypto.c", "auth.c", "serve.c"]
SOEXT = ".dylib" if PLATFORM == "macos" else ".so"

SIZE_MAX = 2 ** (8 * ctypes.sizeof(ctypes.c_size_t)) - 1

# ------------------------------------------------------------ toolchain


def cc():
    return os.environ.get("CC") or shutil.which("cc") or shutil.which("gcc") or "cc"


def run(cmd, timeout=120, input=None, env=None, cwd=None):
    """Run a command; returns (returncode, combined output as text)."""
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                           timeout=timeout, input=input, env=env, cwd=cwd)
    except FileNotFoundError as e:
        return 127, str(e)
    except subprocess.TimeoutExpired as e:
        return 124, "timed out: " + str(e)
    return p.returncode, p.stdout.decode("utf-8", "replace")


_cc_version = {}


def cc_version(compiler=None):
    compiler = compiler or cc()
    if compiler not in _cc_version:
        rc, out = run([compiler, "--version"])
        _cc_version[compiler] = out.strip() if out.strip() else "?"
    return _cc_version[compiler]


def cc_family(compiler=None):
    """'clang', 'gcc' or 'other', from everything `--version` prints: a gcc called cc says only
    "cc (Ubuntu ...)" on its first line and names the Free Software Foundation on the next."""
    v = cc_version(compiler).lower()
    if "clang" in v:
        return "clang"
    if "gcc" in v or "free software foundation" in v:
        return "gcc"
    return "other"


_sodium_cache = []


def sodium():
    """(cflags, ldflags) that find libsodium on this host."""
    if _sodium_cache:
        return _sodium_cache[0]
    env_c = os.environ.get("SODIUM_CFLAGS")
    env_l = os.environ.get("SODIUM_LIBS")
    if env_c is not None or env_l is not None:
        res = (env_c.split() if env_c else [], env_l.split() if env_l else ["-lsodium"])
    else:
        res = None
        pc = shutil.which("pkg-config") or shutil.which("pkgconf")
        if pc:
            rc1, c = run([pc, "--cflags", "libsodium"])
            rc2, l = run([pc, "--libs", "libsodium"])
            if rc1 == 0 and rc2 == 0:
                res = (c.split(), l.split())
        if res is None:
            res = ([], ["-lsodium"])
            for root in ("/usr/local", "/opt/homebrew", "/opt/local", "/usr/pkg", "/usr"):
                if os.path.exists(os.path.join(root, "include", "sodium.h")):
                    if root != "/usr":
                        res = (["-I" + root + "/include"], ["-L" + root + "/lib", "-lsodium"])
                    break
    cflags, ldflags = res
    # Find the shared library at run time wherever it was found at link time.
    rpaths = ["-Wl,-rpath," + f[2:] for f in ldflags if f.startswith("-L")]
    _sodium_cache.append((cflags, ldflags + rpaths))
    return _sodium_cache[0]


def sodium_library_path():
    """Absolute path of the libsodium shared library, for ctypes."""
    dirs = [f[2:] for f in sodium()[1] if f.startswith("-L")]
    dirs += ["/usr/local/lib", "/opt/homebrew/lib", "/opt/local/lib", "/usr/pkg/lib",
             "/usr/lib", "/usr/lib64", "/usr/lib/x86_64-linux-gnu",
             "/usr/lib/aarch64-linux-gnu", "/lib/x86_64-linux-gnu", "/lib/aarch64-linux-gnu"]
    for d in dirs:
        for pattern in ("libsodium.dylib", "libsodium.so", "libsodium.so.*", "libsodium.*.dylib"):
            hits = sorted(glob.glob(os.path.join(d, pattern)))
            if hits:
                return hits[0]
    return ctypes.util.find_library("sodium") or "libsodium.so"


# ---------------------------------------------------------------- caching

_digests = {}


def sources_digest(with_probes=False):
    """Changes whenever a top-level source or header (and, if asked, a probe) changes."""
    if with_probes not in _digests:
        h = hashlib.sha1()
        paths = glob.glob(os.path.join(SRC, "*.c")) + glob.glob(os.path.join(SRC, "*.h")) \
            + glob.glob(os.path.join(SRC, "keygen", "*.c"))
        if with_probes:
            paths += glob.glob(os.path.join(PROBE_DIR, "*"))
        for p in sorted(paths):
            h.update(os.path.basename(p).encode())
            with open(p, "rb") as f:
                h.update(f.read())
        _digests[with_probes] = h.hexdigest()
    return _digests[with_probes]


def _key(*parts, probes=False):
    h = hashlib.sha1()
    for p in parts:
        h.update(repr(p).encode())
    h.update(sources_digest(probes).encode())
    h.update(cc_version().encode())
    return h.hexdigest()[:12]


@contextlib.contextmanager
def _locked():
    os.makedirs(BUILD_DIR, exist_ok=True)
    with open(os.path.join(BUILD_DIR, ".lock"), "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(lock, fcntl.LOCK_UN)


class BuildError(Exception):
    pass


def _compile_all(out, steps):
    """steps: list of command lists run in order; the last produces out."""
    for cmd in steps:
        rc, text = run(cmd)
        if rc != 0:
            raise BuildError("build failed: %s\n%s" % (" ".join(cmd), text[-3000:]))


# ---------------------------------------------------------- build variants

def _slow_hosts(ms):
    """A timeout of the fast build, stretched by PROTO_TEST_SLACK: on an emulated machine a handshake
    that takes a moment must not be a timeout. The tests read the values from the build."""
    return int(ms * max(1.0, harness.SLACK))


FAST = ["-DHANDSHAKE_TIMEOUT_MS=%d" % _slow_hosts(300), "-DQUIT_TIMEOUT_MS=%d" % _slow_hosts(200),
        "-DCONNECT_TIMEOUT_MS=%d" % _slow_hosts(500)]

VARIANTS = {
    "default": [],
    "fast": FAST,
    "chunk1": FAST + ["-DREAD_CHUNK=1"],
    "chunk3": FAST + ["-DREAD_CHUNK=3"],
    "pay64": FAST + ["-DMAX_PAYLOAD=64"],
    "pay4096": FAST + ["-DMAX_PAYLOAD=4096"],
    "pay64c1": FAST + ["-DMAX_PAYLOAD=64", "-DREAD_CHUNK=1"],
    "pay64c3": FAST + ["-DMAX_PAYLOAD=64", "-DREAD_CHUNK=3"],
    "min": ["-DHANDSHAKE_TIMEOUT_MS=1", "-DQUIT_TIMEOUT_MS=0"],
    "quit0": ["-DHANDSHAKE_TIMEOUT_MS=%d" % _slow_hosts(300), "-DQUIT_TIMEOUT_MS=0",
              "-DCONNECT_TIMEOUT_MS=%d" % _slow_hosts(500)],
}

DEFAULT_MACROS = {
    "CONNECT_TIMEOUT_MS": 10000,
    "HANDSHAKE_TIMEOUT_MS": 10000,
    "QUIT_TIMEOUT_MS": 2000,
    "READ_CHUNK": 65536,
    "MAX_PAYLOAD": 16 * 1024 * 1024,
    "MAX_LINE": 16384,
    "CHALLENGE_LEN": 32,
}


def macros_of(defines):
    """The value of every compile-time option in a build with these -D flags."""
    m = dict(DEFAULT_MACROS)
    for d in defines:
        mt = re.match(r"-D(\w+)=(\d+)$", d)
        if mt and mt.group(1) in m:
            m[mt.group(1)] = int(mt.group(2))
    return m


def variant_defines(variant):
    return list(VARIANTS[variant])


def build_shared(variant):
    """Path of the shared library for a build variant, building it if needed."""
    defines = variant_defines(variant)
    flags = ["-O1", "-g", "-fPIC", "-shared", "-Wall", "-Wextra"] + defines
    key = _key("shared", variant, flags)
    out_dir = os.path.join(BUILD_DIR, "lib-%s-%s" % (variant, key))
    out = os.path.join(out_dir, "libproto" + SOEXT)
    if os.path.exists(out):
        return out
    with _locked():
        if os.path.exists(out):
            return out
        os.makedirs(out_dir, exist_ok=True)
        c_flags, ld_flags = sodium()
        tmp = out + ".tmp%d" % os.getpid()
        cmd = ([cc()] + flags + ["-I", SRC] + c_flags + ["-o", tmp]
               + [os.path.join(SRC, s) for s in LIB_SOURCES] + ld_flags)
        _compile_all(tmp, [cmd])
        os.replace(tmp, out)
    return out


SANITIZE = {
    "asan": ["-fsanitize=address,undefined", "-fno-sanitize-recover=all",
             "-fno-omit-frame-pointer"],
    "tsan": ["-fsanitize=thread", "-fno-omit-frame-pointer"],
}


def sanitizer_works(kind):
    """Whether this compiler can build and run a program with that sanitizer.

    For ThreadSanitizer, also whether it reports a race it cannot miss: NetBSD
    builds and runs -fsanitize=thread programs that never report anything, and
    there a clean run would turn every TSan finding into an XPASS."""
    key = "san-" + kind
    cached = _san_cache.get(key)
    if cached is not None:
        return cached
    d = os.path.join(BUILD_DIR, "san-check")
    os.makedirs(d, exist_ok=True)
    src = os.path.join(d, "t.c")
    with open(src, "w") as f:
        f.write("int main(void){return 0;}\n")
    exe = os.path.join(d, "t-" + kind)
    rc, _ = run([cc()] + SANITIZE[kind] + ["-o", exe, src])
    ok = rc == 0
    if ok:
        rc, _ = run([exe], timeout=30, env=dict(os.environ, **san_env(kind)))
        ok = rc == 0
    if ok and kind == "tsan":
        # The thread's access comes second, after a flag read and written with relaxed atomics, which TSan
        # does not count as synchronization. Left to the scheduler, the two accesses came in either order,
        # and with the main thread's second the TSan of GCC 16 missed the race in one run in seven: TSan was
        # judged absent at random, and the tests that need it skipped, or ran without it.
        racy = os.path.join(d, "race.c")
        with open(racy, "w") as f:
            f.write("#include <pthread.h>\n"
                    "int x, go;\n"
                    "static void *bump(void *a) {\n"
                    "    while (!__atomic_load_n(&go, __ATOMIC_RELAXED))\n"
                    "        ;\n"
                    "    x++;\n"
                    "    return a;\n"
                    "}\n"
                    "int main(void) {\n"
                    "    pthread_t t;\n"
                    "    if (pthread_create(&t, 0, bump, 0) != 0) return 1;\n"
                    "    x++;\n"
                    "    __atomic_store_n(&go, 1, __ATOMIC_RELAXED);\n"
                    "    pthread_join(t, 0);\n"
                    "    return 0;\n"
                    "}\n")
        exe = os.path.join(d, "race-tsan")
        rc, _ = run([cc()] + SANITIZE[kind] + ["-pthread", "-o", exe, racy])
        if rc == 0:
            rc, out = run([exe], timeout=30, env=dict(os.environ, **san_env(kind)))
            ok = "WARNING: ThreadSanitizer: data race" in out
        else:
            ok = False
    _san_cache[key] = ok
    return ok


_san_cache = {}


def san_env(kind):
    # allocator_may_return_null: a huge request (T-187) must fail like malloc does,
    # not abort the sanitizer's allocator.
    if kind == "asan":
        opts = "abort_on_error=0:exitcode=66:detect_stack_use_after_return=0:allocator_may_return_null=1"
        return {"ASAN_OPTIONS": opts, "UBSAN_OPTIONS": "print_stacktrace=1:exitcode=66"}
    return {"TSAN_OPTIONS": "exitcode=66:halt_on_error=0:report_signal_unsafe=0:allocator_may_return_null=1"}


def leak_check_supported():
    """Whether the AddressSanitizer here can also detect leaks."""
    if "leaks" in _san_cache:
        return _san_cache["leaks"]
    ok = False
    if sanitizer_works("asan"):
        exe = os.path.join(BUILD_DIR, "san-check", "t-asan")
        rc, out = run([exe], timeout=30,
                      env=dict(os.environ, ASAN_OPTIONS="detect_leaks=1:exitcode=66"))
        ok = rc == 0
    _san_cache["leaks"] = ok
    return ok


def build_exe(name, probe_src=None, variant="fast", seams=None, sanitize=None,
              sources=None, extra_cflags=(), extra_ld=(), defines=None, pic=False,
              sodium_override=None):
    """Compile a program from probes/ together with library sources.

    seams maps a library source ("wire.c") to -D flags that rename the libc
    calls it makes (-Drecv=count_recv); that source gets -U_FORTIFY_SOURCE as
    well, or glibc's fortified inline versions would be renamed too. The probe
    defines the replacements. Returns the path of the executable.
    """
    sources = LIB_SOURCES if sources is None else sources
    seams = seams or {}
    probe_src = probe_src or (name + ".c")
    defs = variant_defines(variant) if defines is None else list(defines)
    san = SANITIZE[sanitize] if sanitize else []
    flags_common = ["-O1", "-g", "-Wall", "-Wextra", "-I", SRC, "-I", PROBE_DIR] + defs + san \
        + list(extra_cflags)
    key = _key("exe", name, probe_src, variant, defs, sorted(seams.items()), sanitize,
               list(sources), list(extra_cflags), list(extra_ld), sodium_override, probes=True)
    out_dir = os.path.join(BUILD_DIR, "exe-%s-%s" % (name, key))
    out = os.path.join(out_dir, name)
    if os.path.exists(out):
        return out
    c_flags, ld_flags = sodium_override or sodium()
    with _locked():
        if os.path.exists(out):
            return out
        os.makedirs(out_dir, exist_ok=True)
        objs, steps = [], []
        for i, s in enumerate(list(sources) + [None]):
            if s is None:
                src = os.path.join(PROBE_DIR, probe_src)
                extra = []
            else:
                src = os.path.join(SRC, s)
                extra = seams.get(s, [])
                if extra:
                    extra = ["-U_FORTIFY_SOURCE"] + extra
            obj = os.path.join(out_dir, "o%d.o" % i)
            steps.append([cc()] + flags_common + c_flags + extra + ["-c", "-o", obj, src])
            objs.append(obj)
        tmp = out + ".tmp%d" % os.getpid()
        steps.append([cc()] + san + objs + ["-o", tmp] + ld_flags + list(extra_ld))
        _compile_all(tmp, steps)
        os.replace(tmp, out)
    return out


def try_compile(text, flags=(), compiler=None, name="t.c", link=False, with_sodium=True):
    """Compile (and optionally link) a C snippet in the case's directory.

    Returns (returncode, compiler output)."""
    d = harness.tmpdir("cc")
    path = os.path.join(d, name)
    with open(path, "w") as f:
        f.write(text)
    c_flags, ld_flags = sodium() if with_sodium else ([], [])
    out = os.path.join(d, "t.out" if link else "t.o")
    cmd = [compiler or cc()] + ([] if link else ["-c"]) + ["-o", out, "-I", SRC] + c_flags \
        + list(flags) + [path] + (ld_flags if link else [])
    return run(cmd)


def compile_source(source, flags=(), compiler=None):
    """Compile one library source to an object file in the case's directory."""
    d = harness.tmpdir("cc")
    c_flags, _ = sodium()
    cmd = [compiler or cc(), "-c", "-o", os.path.join(d, "t.o"), "-I", SRC] + c_flags \
        + list(flags) + [os.path.join(SRC, source)]
    return run(cmd)


def compilers():
    """The distinct C compilers of this host: [(name, path)]. CC alone if it is set."""
    if os.environ.get("CC"):
        return [(os.environ["CC"], shutil.which(os.environ["CC"]) or os.environ["CC"])]
    # The same compiler goes by several names: cc is gcc on Linux (one file, two version lines), and
    # on macOS gcc, clang and cc are three copies of Apple's clang (three files, one version text).
    seen_files, seen_versions, res = set(), set(), []
    for name in ("gcc", "clang", "cc"):
        path = shutil.which(name)
        if not path:
            continue
        real, version = os.path.realpath(path), cc_version(path)
        if real in seen_files or version in seen_versions:
            continue
        seen_files.add(real)
        seen_versions.add(version)
        res.append((name, path))
    return res


def build_keygen():
    """Path of the keygen tool, built from keygen/keygen.c."""
    key = _key("keygen")
    out_dir = os.path.join(BUILD_DIR, "keygen-" + key)
    out = os.path.join(out_dir, "keygen")
    if os.path.exists(out):
        return out
    with _locked():
        if os.path.exists(out):
            return out
        os.makedirs(out_dir, exist_ok=True)
        c_flags, ld_flags = sodium()
        tmp = out + ".tmp%d" % os.getpid()
        _compile_all(tmp, [[cc(), "-Wall", "-Wextra", "-O2", "-o", tmp,
                            os.path.join(SRC, "keygen", "keygen.c")] + c_flags + ld_flags])
        os.replace(tmp, out)
    return out


def run_exe(exe, args=(), timeout=60, env=None, input=None, cwd=None):
    """Run a built program; returns (returncode, stdout, stderr) as bytes."""
    e = dict(os.environ)
    if env:
        e.update(env)
    try:
        p = subprocess.run([exe] + list(args), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           timeout=timeout, input=input, env=e, cwd=cwd)
    except subprocess.TimeoutExpired as ex:
        return 124, ex.stdout or b"", (ex.stderr or b"") + b"\ntimed out"
    return p.returncode, p.stdout, p.stderr


# ------------------------------------------------------------- C structures

class Keys(ctypes.Structure):
    _fields_ = [("auth_pk", ctypes.c_ubyte * 32), ("auth_sk", ctypes.c_ubyte * 64),
                ("enc_pk", ctypes.c_ubyte * 32), ("enc_sk", ctypes.c_ubyte * 32)]

    def raw(self):
        return ctypes.string_at(ctypes.addressof(self), ctypes.sizeof(self))

    def is_zero(self):
        return self.raw() == b"\0" * ctypes.sizeof(self)

    @classmethod
    def filled(cls, byte):
        k = cls()
        ctypes.memset(ctypes.addressof(k), byte, ctypes.sizeof(k))
        return k


class Conn(ctypes.Structure):
    _fields_ = [("fd", ctypes.c_int), ("keys", Keys), ("identity_hex", ctypes.c_char * 65)]

    @classmethod
    def new(cls, keys=None):
        c = cls()
        c.fd = -1
        if keys is not None:
            c.keys = keys
        return c


class ServeOpts(ctypes.Structure):
    _fields_ = [("bind_addr", ctypes.c_char_p), ("drain_ms", ctypes.c_int)]


HANDLER = ctypes.CFUNCTYPE(None, ctypes.c_int, ctypes.c_char_p, ctypes.c_void_p)

libc = ctypes.CDLL(None, use_errno=True)
libc.free.argtypes = [ctypes.c_void_p]
libc.free.restype = None


def _b(x):
    if isinstance(x, str):
        return x.encode("utf-8", "surrogateescape")
    return x


def base64_buffer_size(n):
    """sodium_base64_ENCODED_LEN(n, ORIGINAL): characters of n bytes, plus the NUL."""
    return (n + 2) // 3 * 4 + 1


def cstr(buf):
    """Bytes of a C buffer up to its first NUL."""
    raw = bytes(buf)
    i = raw.find(b"\0")
    return raw if i < 0 else raw[:i]


class Proto(object):
    """The library of one build variant, called through ctypes."""

    def __init__(self, variant):
        self.variant = variant
        self.path = build_shared(variant)
        self.macros = macros_of(variant_defines(variant))
        d = ctypes.CDLL(self.path, use_errno=True)
        self.dll = d
        c_int, c_char_p, c_void_p, c_size_t = (ctypes.c_int, ctypes.c_char_p,
                                               ctypes.c_void_p, ctypes.c_size_t)
        P = ctypes.POINTER

        def f(name, restype, *argtypes):
            fn = getattr(d, name)
            fn.restype = restype
            fn.argtypes = list(argtypes)
            return fn

        self.c_strerror = f("proto_strerror", c_char_p, c_int)
        self.c_send_line = f("proto_send_line", c_int, c_int, c_char_p)
        self.c_recv_line = f("proto_recv_line", c_int, c_int, c_void_p, c_size_t)
        self.c_recv_line_timeout = f("proto_recv_line_timeout", c_int, c_int, c_void_p,
                                     c_size_t, c_int)
        self.c_recv_line_dyn = f("proto_recv_line_dyn", c_void_p, c_int)
        self.c_recv_line_dyn_status = f("proto_recv_line_dyn_status", c_void_p, c_int,
                                        P(c_int))
        self.c_send_prefixed = f("proto_send_prefixed", c_int, c_int, c_char_p, c_void_p,
                                 c_size_t)
        self.c_keepalive = f("proto_keepalive", c_int, c_int, c_int, c_int, c_int)
        self.c_init = f("proto_init", c_int)
        self.c_load_keys = f("proto_load_keys", c_int, c_char_p, c_char_p, P(Keys))
        self.c_load_pubkey_hex = f("proto_load_pubkey_hex", c_int, c_char_p, c_void_p, c_size_t)
        self.c_seal = f("proto_seal", c_int, c_void_p, c_size_t, c_void_p, c_void_p, c_size_t)
        self.c_seal_new = f("proto_seal_new", c_void_p, c_void_p, c_size_t, c_void_p)
        self.c_unseal_new = f("proto_unseal_new", c_void_p, c_char_p, c_void_p, c_void_p,
                              P(c_size_t))
        self.c_sign_challenge = f("proto_sign_challenge", c_int, c_void_p, c_size_t, c_void_p,
                                  c_void_p)
        self.c_verify_challenge = f("proto_verify_challenge", c_int, c_void_p, c_size_t,
                                    c_void_p, c_void_p)
        self.c_auth_client = f("proto_auth_client", c_int, c_int, P(Keys))
        self.c_auth_server = f("proto_auth_server", c_void_p, c_int, c_char_p)
        self.c_connect = f("proto_connect", c_int, P(Conn), c_char_p, c_int)
        self.c_close = f("proto_close", None, P(Conn))
        self.c_serve = f("proto_serve", c_int, c_int, c_char_p, HANDLER, c_void_p, P(ServeOpts))
        self.c_serve_stop = f("proto_serve_stop", None)

    # --------------------------------------------------------- status

    def strerror(self, code):
        s = self.c_strerror(code)
        return s.decode("utf-8", "replace") if s is not None else None

    # ---------------------------------------------------------- wire

    def send_line(self, fd, line):
        return self.c_send_line(fd, _b(line))

    def recv_line(self, fd, bufsz=16384, fill=0):
        """(rc, text) of proto_recv_line. fill is the byte buf holds beforehand."""
        buf = ctypes.create_string_buffer(bufsz)
        if fill:
            ctypes.memset(buf, fill, bufsz)
        rc = self.c_recv_line(fd, buf, bufsz)
        return rc, cstr(buf.raw)

    def recv_line_raw(self, fd, bufsz, fill=ord("Z")):
        """(rc, whole buffer) -- for tests that look past the NUL."""
        buf = ctypes.create_string_buffer(bufsz)
        ctypes.memset(buf, fill, bufsz)
        rc = self.c_recv_line(fd, buf, bufsz)
        return rc, buf.raw

    def recv_line_timeout(self, fd, ms, bufsz=16384, fill=0):
        buf = ctypes.create_string_buffer(bufsz)
        if fill:
            ctypes.memset(buf, fill, bufsz)
        rc = self.c_recv_line_timeout(fd, buf, bufsz, ms)
        return rc, cstr(buf.raw)

    def recv_line_timeout_raw(self, fd, ms, bufsz, fill=ord("Z")):
        buf = ctypes.create_string_buffer(bufsz)
        ctypes.memset(buf, fill, bufsz)
        rc = self.c_recv_line_timeout(fd, buf, bufsz, ms)
        return rc, buf.raw

    def recv_dyn(self, fd, with_status=True):
        """(bytes or None, status) of proto_recv_line_dyn_status; frees the line."""
        status = ctypes.c_int(999)
        p = self.c_recv_line_dyn_status(fd, ctypes.byref(status))
        return self._take(p), status.value

    def recv_dyn_plain(self, fd):
        return self._take(self.c_recv_line_dyn(fd))

    @staticmethod
    def _take(p):
        if not p:
            return None
        try:
            return ctypes.string_at(p)
        finally:
            libc.free(p)

    def send_prefixed(self, fd, prefix, body, n=None):
        body = _b(body)
        if body is None:
            return self.c_send_prefixed(fd, _b(prefix), None, 0 if n is None else n)
        return self.c_send_prefixed(fd, _b(prefix), body, len(body) if n is None else n)

    def keepalive(self, fd, idle, intvl, count):
        return self.c_keepalive(fd, idle, intvl, count)

    # -------------------------------------------------------- crypto

    def init(self):
        return self.c_init()

    def load_keys(self, auth_path, enc_path, out=None):
        out = Keys() if out is None else out
        rc = self.c_load_keys(_b(auth_path), _b(enc_path), ctypes.byref(out))
        return rc, out

    def load_pubkey_hex(self, path, size=65, fill=0):
        buf = ctypes.create_string_buffer(size)
        if fill:
            ctypes.memset(buf, fill, size)
        rc = self.c_load_pubkey_hex(_b(path), buf, size)
        return rc, buf.raw

    def seal(self, msg, enc_pk, out_size=None):
        """(rc, base64 text) of proto_seal into a buffer of exactly out_size."""
        if out_size is None:
            out_size = base64_buffer_size(len(msg) + 48)
        buf = ctypes.create_string_buffer(max(out_size, 1))
        rc = self.c_seal(msg, len(msg), bytes(enc_pk), buf, out_size)
        return rc, cstr(buf.raw)

    def seal_new(self, msg, enc_pk):
        p = self.c_seal_new(msg, len(msg), bytes(enc_pk))
        return self._take(p)

    def unseal_new(self, b64, enc_pk, enc_sk):
        """(plaintext or None, out_len or None)."""
        out_len = ctypes.c_size_t(0xDEAD)
        p = self.c_unseal_new(_b(b64), bytes(enc_pk), bytes(enc_sk), ctypes.byref(out_len))
        if not p:
            return None, out_len.value
        try:
            n = out_len.value
            return ctypes.string_at(p, n), n
        finally:
            libc.free(p)

    def unseal_full(self, b64, enc_pk, enc_sk):
        """(plaintext, out_len, byte after the plaintext), or (None, out_len, None)."""
        out_len = ctypes.c_size_t(0xDEAD)
        p = self.c_unseal_new(_b(b64), bytes(enc_pk), bytes(enc_sk), ctypes.byref(out_len))
        if not p:
            return None, out_len.value, None
        try:
            n = out_len.value
            data = ctypes.string_at(p, n + 1)
            return data[:n], n, data[n]
        finally:
            libc.free(p)

    def sign(self, challenge, auth_sk):
        sig = ctypes.create_string_buffer(64)
        rc = self.c_sign_challenge(challenge, len(challenge), bytes(auth_sk), sig)
        return rc, sig.raw

    def verify(self, challenge, sig, auth_pk):
        return self.c_verify_challenge(challenge, len(challenge), bytes(sig), bytes(auth_pk))

    # ------------------------------------------------------ handshake

    def auth_client(self, fd, keys):
        return self.c_auth_client(fd, ctypes.byref(keys))

    def auth_server(self, fd, allowed):
        return self._take(self.c_auth_server(fd, _b(allowed)))

    def connect(self, conn, host, port):
        return self.c_connect(ctypes.byref(conn), _b(host), port)

    def close(self, conn):
        self.c_close(ctypes.byref(conn))

    # --------------------------------------------------------- serve

    def serve_stop(self):
        self.c_serve_stop()

    def serve(self, port, allowed, handler=None, ctx=None, opts=None):
        """proto_serve with a handler that is never meant to run."""
        if handler is None:
            handler = self.noop_handler
        return self.c_serve(port, _b(allowed), handler, ctx,
                            None if opts is None else ctypes.byref(opts))

    @property
    def noop_handler(self):
        if not hasattr(self, "_noop"):
            self._noop = HANDLER(lambda fd, ident, ctx: None)
        return self._noop


_protos = {}
_override = []


def proto(variant=None):
    """The library of a build variant ('fast' unless the case says otherwise)."""
    if variant is None:
        variant = _override[-1] if _override else "fast"
    if variant not in _protos:
        _protos[variant] = Proto(variant)
    return _protos[variant]


@contextlib.contextmanager
def using_variant(variant):
    """Make proto() with no argument return this variant: for T-011."""
    _override.append(variant)
    try:
        yield
    finally:
        _override.pop()
