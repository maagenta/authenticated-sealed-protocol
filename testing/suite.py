"""Running probes/suite.c under the builds that Python cannot host.

A 32-bit build, a musl build, a fortified build and a sanitizer's runtime cannot
be loaded into the Python that runs the suite, so each of them runs the same
core scenarios as one C program.
"""

import os
import platform
import shlex

import harness
import lib
import runprobe
from harness import check, fail, skip


def libc_name():
    """'musl', 'glibc' or the platform's name."""
    rc, out = lib.run(["ldd", "--version"])
    if "musl" in out.lower():
        return "musl"
    name, _ = platform.libc_ver()
    return name or harness.PLATFORM


def sodium32():
    """libsodium flags for the 32-bit build: SODIUM32_CFLAGS and SODIUM32_LIBS, else the usual ones."""
    c, l = os.environ.get("SODIUM32_CFLAGS"), os.environ.get("SODIUM32_LIBS")
    if c is not None or l is not None:
        return (shlex.split(c or ""), shlex.split(l or "-lsodium"))
    return lib.sodium()


def require_toolchain(flags):
    """Skip unless a program builds and links with these flags and libsodium."""
    sod = sodium32() if "-m32" in flags else lib.sodium()
    d = harness.tmpdir("tc")
    src = os.path.join(d, "t.c")
    with open(src, "w") as f:
        f.write('#include <sodium.h>\nint main(void){return sodium_init() < 0;}\n')
    rc, out = lib.run([lib.cc()] + list(flags) + sod[0] + [src, "-o", os.path.join(d, "t")] + sod[1] + list(flags))
    if rc != 0:
        skip("no toolchain for %s: %s" % (" ".join(flags), out.strip().splitlines()[-1][:120] if out.strip() else ""))
    rc, out, err = lib.run_exe(os.path.join(d, "t"))
    if rc != 0:
        skip("a program built with %s does not run here" % " ".join(flags))


def build(extra=(), sanitize=None):
    extra = list(extra)
    link = [f for f in extra if f in ("-m32",)]
    sod = sodium32() if "-m32" in extra else None
    return runprobe.build("suite", variant="fast", threads=True, sanitize=sanitize,
                          extra_cflags=extra, extra_ld=link, sodium_override=sod)


def run_suite(label, extra=(), scenario="all", sanitize=None, leaks=False, timeout=300):
    """Build and run the suite probe; fail unless every scenario passes. Returns its stderr."""
    exe = build(extra, sanitize)
    env = dict(lib.san_env(sanitize)) if sanitize else {}
    if sanitize == "asan":
        env["ASAN_OPTIONS"] = env.get("ASAN_OPTIONS", "") + (":detect_leaks=1" if leaks else ":detect_leaks=0")
    elif sanitize == "tsan":
        env["TSAN_OPTIONS"] = env.get("TSAN_OPTIONS", "")
    args = [] if scenario == "all" else scenario.split(",")
    rc, out, err = lib.run_exe(exe, args, timeout=timeout, env=env)
    text = err.decode("utf-8", "replace")
    if rc != 0:
        fail("the %s build of the suite failed (%d): %s" % (label, rc, text.strip()[-700:]
                                                             or out.decode("utf-8", "replace")[-300:]))
    if sanitize and ("ERROR: AddressSanitizer" in text or "runtime error" in text
                     or "WARNING: ThreadSanitizer" in text or "LeakSanitizer" in text):
        fail("a sanitizer reported in the %s build: %s" % (label, text.strip()[-700:]))
    return text
