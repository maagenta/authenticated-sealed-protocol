"""XXI. The keygen tool (T-355 to T-373)."""

import os
import pty
import re
import resource
import select
import shutil
import signal
import stat
import subprocess
import time

import harness
import lib
import libsodium as ls
import net
from harness import FINDING, PIN, PLATFORM, case, check, eq, skip
from keyfiles import write_file

FILES = ("auth.key", "auth.pub", "enc.key")
SIZES = {"auth.key": 89, "auth.pub": 45, "enc.key": 45}


def keygen_path():
    return lib.build_keygen()


def run_keygen(cwd, stdin=None, preexec=None, args=(), timeout=30):
    """Run keygen in cwd: (exit status, stdout, stderr)."""
    p = subprocess.run([keygen_path()] + list(args), cwd=cwd, stdin=stdin if stdin is not None else subprocess.DEVNULL,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, preexec_fn=preexec, timeout=timeout)
    return p.returncode, p.stdout.decode("utf-8", "replace"), p.stderr.decode("utf-8", "replace")


def fresh():
    return harness.tmpdir("kg")


def listing(d):
    return sorted(os.listdir(d))


def read(d, name):
    with open(os.path.join(d, name), "rb") as f:
        return f.read()


@case("T-355")
def t355():
    """keygen in an empty directory makes three key files, mode 0600."""
    d = fresh()
    rc, out, err = run_keygen(d)
    eq(rc, 0, "exit status (stderr: %s)" % err.strip()[:100])
    eq(listing(d), sorted(FILES), "the files")
    for name in FILES:
        st = os.stat(os.path.join(d, name))
        eq(stat.S_IMODE(st.st_mode), 0o600, "mode of " + name)
        eq(st.st_size, SIZES[name], "size of " + name)
        data = read(d, name)
        check(data.endswith(b"\n") and data.count(b"\n") == 1, name + " is not one line")
        check(re.fullmatch(rb"[A-Za-z0-9+/]+={0,2}\n", data), name + " is not standard base64")
    eq(len(ls.b64d(read(d, "enc.key").strip())), 32, "enc.key decodes to")


@case("T-356")
def t356():
    """The files load."""
    P = lib.proto()
    d = fresh()
    eq(run_keygen(d)[0], 0, "exit status")
    rc, keys = P.load_keys(os.path.join(d, "auth.key"), os.path.join(d, "enc.key"))
    eq(rc, 0, "proto_load_keys")
    rc, hexed = P.load_pubkey_hex(os.path.join(d, "auth.pub"))
    eq(rc, 0, "proto_load_pubkey_hex")
    eq(hexed[:64], bytes(keys.auth_pk).hex().encode(), "auth.pub against auth.key")
    eq(ls.b64d(read(d, "auth.key").strip())[32:], ls.b64d(read(d, "auth.pub").strip()),
       "the last 32 bytes of auth.key against auth.pub")


@case("T-357")
def t357():
    """Every run makes a new identity."""
    a, b = fresh(), fresh()
    eq((run_keygen(a)[0], run_keygen(b)[0]), (0, 0), "exit statuses")
    for name in FILES:
        check(read(a, name) != read(b, name), "two runs made the same " + name)


@case("T-358")
def t358():
    """A second run refuses to overwrite."""
    d = fresh()
    eq(run_keygen(d)[0], 0, "the first run")
    before = {n: (read(d, n), os.stat(os.path.join(d, n)).st_mtime_ns) for n in FILES}
    time.sleep(0.05)
    rc, out, err = run_keygen(d)
    eq(rc, 1, "exit status of the second run")
    check("auth.key" in err, "the message does not name auth.key: %r" % err[:120])
    after = {n: (read(d, n), os.stat(os.path.join(d, n)).st_mtime_ns) for n in FILES}
    eq(after, before, "the files after the second run")


@case("T-359")
def t359():
    """Any one of the three files present stops the run before anything is written."""
    for name in FILES:
        d = fresh()
        write_file(os.path.join(d, name), b"existing\n")
        rc, out, err = run_keygen(d)
        eq(rc, 1, "exit status with %s present" % name)
        eq(listing(d), [name], "the directory with only %s present" % name)
        eq(read(d, name), b"existing\n", name + " itself")


@case("T-360", FINDING)
def t360():
    """A dangling symlink at a key's name stops the run before anything is written."""
    for name in ("enc.key", "auth.pub"):
        d = fresh()
        os.symlink(os.path.join(d, "nowhere"), os.path.join(d, name))
        rc, out, err = run_keygen(d)
        eq(rc, 1, "exit status with a dangling %s" % name)
        eq(listing(d), [name], "files left behind next to a dangling %s" % name)


@case("T-361", FINDING)
def t361():
    """A stale probe file does not stop keygen."""
    d = fresh()
    write_file(os.path.join(d, ".keygen-probe"), b"")
    rc, out, err = run_keygen(d)
    eq(rc, 0, "exit status with a stale .keygen-probe (stderr: %s)" % err.strip()[:100])
    check(set(FILES) <= set(listing(d)), "the key files were not made")


@case("T-362", tags=("notroot",))
def t362():
    """A read-only directory is refused, and nothing is created."""
    d = fresh()
    os.chmod(d, 0o500)
    try:
        rc, out, err = run_keygen(d)
        eq(rc, 1, "exit status")
        check("cannot create files here" in err and "Permission denied" in err, "message: %r" % err[:120])
        eq(listing(d), [], "files created in a read-only directory")
    finally:
        os.chmod(d, 0o700)


class Mount(object):
    """A small filesystem for the tests that need one (root, Linux)."""

    def __init__(self, kind):
        if PLATFORM != "linux":
            skip("this test mounts a filesystem with Linux's mount")
        self.kind = kind
        self.dir = harness.tmpdir("mnt")
        self.img = os.path.join(harness.tmpdir("img"), "disk")

    def __enter__(self):
        if self.kind == "vfat":
            for tool in ("mkfs.vfat", "mount", "umount"):
                if not shutil.which(tool):
                    skip("%s is not installed" % tool)
            with open(self.img, "wb") as f:
                f.truncate(8 * 1024 * 1024)
            r = subprocess.run(["mkfs.vfat", self.img], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            if r.returncode != 0:
                skip("mkfs.vfat failed: " + r.stdout.decode()[-100:])
            cmd = ["mount", "-o", "loop,uid=%d" % os.getuid(), self.img, self.dir]
        else:
            if not shutil.which("mount"):
                skip("mount is not installed")
            cmd = ["mount", "-t", "tmpfs", "-o", "size=64k", "tmpfs", self.dir]
        r = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        if r.returncode != 0:
            skip("cannot mount a %s filesystem here: %s" % (self.kind, r.stdout.decode()[-120:]))
        return self.dir

    def __exit__(self, *exc):
        subprocess.run(["umount", self.dir], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


@case("T-363", tags=("root",))
def t363():
    """On a filesystem without permissions, a script gets no keys."""
    with Mount("vfat") as d:
        rc, out, err = run_keygen(d, stdin=subprocess.DEVNULL)
        eq(rc, 1, "exit status")
        check("Aborted; no files were created." in out, "stdout: %r" % out[-200:])
        check("does not support" in out, "no warning: %r" % out[-200:])
        eq(listing(d), [], "files created on a filesystem without permissions")


def with_terminal(d, answers):
    """Run keygen with a pseudo-terminal as stdin, typing each answer; returns (status, stdout)."""
    master, slave = pty.openpty()
    p = subprocess.Popen([keygen_path()], cwd=d, stdin=slave, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    os.close(slave)
    time.sleep(0.4)
    for a in answers:
        os.write(master, a)
    try:
        out, err = p.communicate(timeout=20)
    finally:
        os.close(master)
    return p.returncode, out.decode("utf-8", "replace")


@case("T-364", tags=("root",))
def t364():
    """On a filesystem without permissions, only an explicit yes on a terminal goes ahead."""
    with Mount("vfat") as d:
        rc, out = with_terminal(d, [b"y\n"])
        eq(rc, 0, "exit status after y")
        check("WARNING: files are readable by other users" in out, "the final message: %r" % out[-200:])
        eq(listing(d), sorted(FILES), "files after y")
        for name in FILES:
            os.unlink(os.path.join(d, name))
        for answer in (b"n\n", b"\n"):
            rc, out = with_terminal(d, [answer])
            eq(rc, 1, "exit status after %r" % answer)
            eq(listing(d), [], "files after %r" % answer)
        p = subprocess.run([keygen_path()], cwd=d, input=b"y\n", stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        eq(p.returncode, 1, "a piped y is no answer")
        eq(listing(d), [], "files after a piped y")


@case("T-365")
def t365():
    """The umask can tighten the mode, never loosen it."""
    P = lib.proto()
    tight = fresh()
    eq(run_keygen(tight, preexec=lambda: os.umask(0o277))[0], 0, "exit status under umask 0277")
    for name in FILES:
        eq(stat.S_IMODE(os.stat(os.path.join(tight, name)).st_mode), 0o400, "mode of %s under umask 0277" % name)
    rc, keys = P.load_keys(os.path.join(tight, "auth.key"), os.path.join(tight, "enc.key"))
    eq(rc, 0, "the files with mode 0400 load")
    open_ = fresh()
    eq(run_keygen(open_, preexec=lambda: os.umask(0))[0], 0, "exit status under umask 0")
    for name in FILES:
        eq(stat.S_IMODE(os.stat(os.path.join(open_, name)).st_mode), 0o600, "mode of %s under umask 0" % name)


@case("T-366", tags=("root",))
def t366():
    """A full disk removes the partial file."""
    with Mount("tmpfs") as d:
        # buffering=0: no buffered tail is left for the close in the with-exit to flush, since that
        # close raises ENOSPC on the full tmpfs (seen on the privileged CI job).
        with open(os.path.join(d, "filler"), "wb", buffering=0) as f:
            try:
                while True:
                    f.write(b"x" * 4096)
                    f.flush()
            except OSError:
                pass
        rc, out, err = run_keygen(d)
        eq(rc, 1, "exit status")
        check("auth.key" in err, "the error does not name the file: %r" % err[:150])
        check(not os.path.exists(os.path.join(d, "auth.key")), "the partial auth.key is still there")


@case("T-367", FINDING)
def t367():
    """A file-size limit does not leave an empty auth.key behind."""
    d = fresh()

    def limit():
        resource.setrlimit(resource.RLIMIT_FSIZE, (0, 0))
    p = subprocess.run([keygen_path()], cwd=d, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE, preexec_fn=limit)
    eq(p.returncode, 1, "exit status under a file-size limit of 0 (not killed by SIGXFSZ)")
    eq(listing(d), [], "files left behind under a file-size limit")


@case("T-368", PIN)
def t368():
    """keygen ignores its arguments."""
    d = fresh()
    rc, out, err = run_keygen(d, args=["--help"])
    eq(rc, 0, "keygen --help")
    eq(listing(d), sorted(FILES), "an identity was generated all the same")


@case("T-369")
def t369():
    """Progress goes to stdout and errors to stderr, with exit codes 0 and 1 only."""
    d = fresh()
    rc, out, err = run_keygen(d)
    eq(rc, 0, "a run")
    check("Created: auth.key" in out and err == "", "success: stdout %r, stderr %r" % (out[-80:], err))
    rc, out, err = run_keygen(d)
    eq(rc, 1, "a second run")
    check(err.strip() != "" and "Created" not in out, "refusal: stdout %r, stderr %r" % (out[-80:], err[:80]))
    if os.geteuid() != 0:
        ro = fresh()
        os.chmod(ro, 0o500)
        try:
            rc, out, err = run_keygen(ro)
            eq(rc, 1, "a read-only directory")
            check(err.strip() != "", "no error on stderr")
        finally:
            os.chmod(ro, 0o700)


@case("T-370", timeout=120)
def t370():
    """Two runs at once make one identity."""
    P = lib.proto()
    for round_ in range(25):
        d = fresh()
        procs = [subprocess.Popen(["/bin/sh", "-c", 'read go; exec "$0"', keygen_path()], cwd=d,
                                  stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                 for _ in range(2)]
        time.sleep(0.05)
        for p in procs:
            p.stdin.write(b"go\n")
            p.stdin.flush()
        results = []
        for p in procs:
            out, err = p.communicate(timeout=30)
            results.append(p.returncode)
        eq(sorted(results), [0, 1], "exit statuses of two concurrent runs (round %d)" % round_)
        eq(listing(d), sorted(FILES), "files (round %d)" % round_)
        rc, keys = P.load_keys(os.path.join(d, "auth.key"), os.path.join(d, "enc.key"))
        eq(rc, 0, "the identity that resulted loads (round %d)" % round_)
        rc, hexed = P.load_pubkey_hex(os.path.join(d, "auth.pub"))
        eq(hexed[:64], bytes(keys.auth_pk).hex().encode(), "auth.pub matches auth.key (round %d)" % round_)


@case("T-371")
def t371():
    """Nothing is written outside the current directory."""
    parent = fresh()
    d = os.path.join(parent, "work")
    os.mkdir(d)
    before = listing(parent)
    eq(run_keygen(d)[0], 0, "a run")
    eq(listing(d), sorted(FILES), "the directory after a success (no probe file)")
    eq(run_keygen(d)[0], 1, "an aborted run")
    eq(listing(d), sorted(FILES), "the directory after an abort")
    eq(listing(parent), before, "the parent directory")


@case("T-372")
def t372():
    """The generated enc.key is not low-order."""
    P = lib.proto()
    for _ in range(5):
        d = fresh()
        eq(run_keygen(d)[0], 0, "a run")
        rc, keys = P.load_keys(os.path.join(d, "auth.key"), os.path.join(d, "enc.key"))
        eq(rc, 0, "proto_load_keys")
        sealed = P.seal_new(b"a message", bytes(keys.enc_pk))
        check(sealed is not None, "sealing to the generated enc_pk failed")
        eq(P.unseal_full(sealed, bytes(keys.enc_pk), bytes(keys.enc_sk))[0], b"a message", "opening")


@case("T-373", PIN)
def t373():
    """keygen leaves the secret keys in memory until it exits."""
    with open(os.path.join(harness.ROOT, "keygen", "keygen.c"), encoding="utf-8") as f:
        text = f.read()
    check("sodium_memzero" not in text and "explicit_bzero" not in text,
          "keygen.c now wipes its keys: the decision recorded by this pin changed")
