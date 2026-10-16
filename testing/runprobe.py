"""Running the programs in probes/ and reading what they report."""

import os

import harness
import lib

PTHREAD = ["-pthread"]

# The calls wire.c makes that seam_wire.c takes over.
WIRE_SEAMS = {"wire.c": ["-Dsend=seam_send", "-Drecv=count_recv", "-Dread=count_read",
                         "-Dmalloc=seam_malloc", "-Drealloc=seam_realloc", "-Dfree=seam_free"]}


# The calls auth.c makes that seam_auth.c takes over, and the send that counts writes.
AUTH_SEAMS = {
    "auth.c": ["-Dgetaddrinfo=seam_getaddrinfo", "-Dfreeaddrinfo=seam_freeaddrinfo",
               "-Dsocket=seam_socket", "-Dconnect=seam_connect", "-Dgetsockopt=seam_getsockopt",
               "-Dclose=seam_close", "-Dpoll=seam_poll", "-Dstrdup=seam_strdup", "-Dmalloc=seam_malloc",
               "-Dfree=seam_free"],
    "wire.c": ["-Dsend=seam_send"],
}

# The calls serve.c makes that seam_serve.c takes over.
SERVE_SEAMS = {"serve.c": ["-Dsocket=seam_socket", "-Dsocketpair=seam_socketpair", "-Dlisten=seam_listen",
                           "-Daccept=seam_accept", "-Dfork=seam_fork", "-Dpoll=seam_poll"]}

# NetBSD declares socket() with __RENAME(__socket30), an asm label that -Dsocket
# does not touch: the renamed declaration still links to the real socket(). The
# label is macro-expanded, so renaming __socket30 too points it at the seam.
if harness.PLATFORM == "netbsd":
    for _seams in (AUTH_SEAMS, SERVE_SEAMS):
        for _src, _flags in _seams.items():
            if "-Dsocket=seam_socket" in _flags:
                _flags.append("-D__socket30=seam_socket")

# The calls crypto.c makes that seam_crypto.c takes over.
CRYPTO_SEAMS = {"crypto.c": ["-Dread=seam_read", "-Dopen=seam_open", "-Dmalloc=seam_malloc",
                             "-Dfree=seam_free", "-Dsodium_memzero=spy_memzero"]}


def build(name, **kw):
    kw.setdefault("extra_cflags", [])
    kw.setdefault("extra_ld", [])
    if kw.pop("threads", False):
        kw["extra_cflags"] = list(kw["extra_cflags"]) + PTHREAD
        kw["extra_ld"] = list(kw["extra_ld"]) + PTHREAD
    return lib.build_exe(name, **kw)


def run(name, args=(), timeout=120, env=None, input=None, cwd=None, **build_kw):
    """Build and run a probe: (returncode, stdout, stderr) as bytes."""
    exe = build(name, **build_kw)
    return lib.run_exe(exe, args, timeout=timeout, env=env, input=input, cwd=cwd)


def must_pass(name, args=(), what="", **kw):
    rc, out, err = run(name, args, **kw)
    if rc != 0:
        harness.fail("%s %s failed (%d): %s" % (name, " ".join(map(str, args)), rc,
                                                err.decode("utf-8", "replace").strip()[-400:] or out.decode("utf-8", "replace")[-200:]))
    return out


def threads(scenario, *args, tsan=True):
    """Run the threads probe, under ThreadSanitizer when this host has it.

    Returns (returncode, stderr text, whether TSan was used)."""
    san = "tsan" if tsan and lib.sanitizer_works("tsan") else None
    env = lib.san_env("tsan") if san else None
    rc, out, err = run("threads", [scenario] + [str(a) for a in args], env=env,
                       sanitize=san, threads=True)
    return rc, err.decode("utf-8", "replace"), san is not None


def tsan_report(text):
    return "WARNING: ThreadSanitizer" in text
