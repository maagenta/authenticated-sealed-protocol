"""Running the programs in probes/ and reading what they report."""

import os

import harness
import lib

PTHREAD = ["-pthread"]

# The calls wire.c makes that seam_wire.c takes over.
WIRE_SEAMS = {"wire.c": ["-Dsend=seam_send", "-Drecv=count_recv", "-Dread=count_read",
                         "-Dmalloc=seam_malloc", "-Drealloc=seam_realloc", "-Dfree=seam_free"]}


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
