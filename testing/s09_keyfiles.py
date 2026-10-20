"""IX. Key files (T-123 to T-158).

Every format case goes through the three ways a key file is loaded: a 32-byte
public key (proto_load_pubkey_hex), the 64-byte auth.key and the 32-byte
enc.key (proto_load_keys, the other file being good).
"""

import base64
import hashlib
import os
import resource
import signal
import socket
import stat
import time

import harness
import keyfiles
import lib
import libsodium as ls
import net
import runprobe
from harness import FINDING, PIN, case, check, eq, in_child, skip
from keyfiles import key_line, make_identity, three_loads, write_file

OK = 0
EMPTY, FORMAT, NOT_FOUND, DENIED, NOT_FILE, READ, STRAY, SIZE, OPEN = \
    -302, -303, -305, -306, -307, -308, -309, -310, -301


def all_three(P, render, want, what):
    got = three_loads(P, render)
    eq(got, (want, want, want), what + " (public key, auth.key, enc.key)")


@case("T-123")
def t123():
    """A valid key with a trailing newline loads."""
    all_three(lib.proto(), lambda raw: key_line(raw), OK, "key and newline")


@case("T-124")
def t124():
    """A valid key without a trailing newline loads."""
    all_three(lib.proto(), lambda raw: ls.b64(raw).encode(), OK, "key without newline")


@case("T-125")
def t125():
    """A key with CRLF, or with several CRs, loads."""
    P = lib.proto()
    all_three(P, lambda raw: ls.b64(raw).encode() + b"\r\n", OK, "CRLF")
    all_three(P, lambda raw: ls.b64(raw).encode() + b"\r\r\n", OK, "CR CR LF")


@case("T-126")
def t126():
    """Only the first line is read."""
    P = lib.proto()
    junk = b"second line\n\0\xff\xfe binary \r\n"
    all_three(P, lambda raw: key_line(raw) + junk, OK, "anything after line 1")
    # The labelled files of v2.0: the kind of key and the SHA-256 of auth_pk.
    d = harness.tmpdir("labelled")
    ident = make_identity(d, write=False)
    digest = hashlib.sha256(ident.auth_pk).hexdigest()
    write_file(ident.auth_key, key_line(ident.auth_sk) + ("# auth.key %s\n" % digest).encode())
    write_file(ident.auth_pub, key_line(ident.auth_pk) + ("# auth.pub %s\n" % digest).encode())
    write_file(ident.enc_key, key_line(ident.enc_sk) + ("# enc.key %s\n" % digest).encode())
    rc, keys = P.load_keys(ident.auth_key, ident.enc_key)
    eq(rc, OK, "proto_load_keys on labelled files")
    rc, hexed = P.load_pubkey_hex(ident.auth_pub)
    eq(rc, OK, "proto_load_pubkey_hex on a labelled file")
    eq(hexed[:64], ident.hex.encode(), "the identity")


@case("T-127")
def t127():
    """An empty file is PROTO_E_KEY_EMPTY."""
    all_three(lib.proto(), lambda raw: b"", EMPTY, "a file of zero bytes")


@case("T-128")
def t128():
    """A blank first line is PROTO_E_KEY_EMPTY."""
    P = lib.proto()
    for blank in (b"\n", b"\r\n", b"   \n", b"\t\t\n", b" \t \r\n"):
        all_three(P, lambda raw, b=blank: b, EMPTY, "first line %r" % blank)


@case("T-129")
def t129():
    """A blank first line with the key on the second is PROTO_E_KEY_EMPTY."""
    all_three(lib.proto(), lambda raw: b"\n" + key_line(raw), EMPTY, "key on the second line")


@case("T-130")
def t130():
    """A space or a tab around the key is PROTO_E_KEY_STRAY."""
    P = lib.proto()
    for name, render in (("space before", lambda raw: b" " + key_line(raw)),
                         ("space after", lambda raw: ls.b64(raw).encode() + b" \n"),
                         ("tab before", lambda raw: b"\t" + key_line(raw)),
                         ("tab after", lambda raw: ls.b64(raw).encode() + b"\t\n")):
        all_three(P, render, STRAY, name)


@case("T-131")
def t131():
    """A UTF-8 byte order mark is PROTO_E_KEY_STRAY."""
    all_three(lib.proto(), lambda raw: b"\xef\xbb\xbf" + key_line(raw), STRAY, "a byte order mark")


@case("T-132")
def t132():
    """A non-breaking space is PROTO_E_KEY_STRAY."""
    P = lib.proto()
    all_three(P, lambda raw: ls.b64(raw).encode() + b"\xc2\xa0\n", STRAY, "NBSP after")
    all_three(P, lambda raw: b"\xc2\xa0" + key_line(raw), STRAY, "NBSP before")


@case("T-133")
def t133():
    """A quoted key is PROTO_E_KEY_STRAY."""
    P = lib.proto()
    all_three(P, lambda raw: b'"' + ls.b64(raw).encode() + b'"\n', STRAY, "double quotes")
    all_three(P, lambda raw: b"'" + ls.b64(raw).encode() + b"'\n", STRAY, "single quotes")


def with_char_inside(ch):
    def render(raw):
        text = ls.b64(raw)
        mid = len(text) // 2
        return (text[:mid] + ch + text[mid + 1:]).encode() + b"\n"
    return render


@case("T-134")
def t134():
    """A space inside the key is PROTO_E_KEY_FORMAT."""
    all_three(lib.proto(), with_char_inside(" "), FORMAT, "a space inside")


@case("T-135")
def t135():
    """A character outside the alphabet, inside the key, is PROTO_E_KEY_FORMAT."""
    P = lib.proto()
    for ch in "*.-_":
        all_three(P, with_char_inside(ch), FORMAT, "%r inside the key" % ch)


def urlsafe_with_leading_underscore(raw):
    raw = b"\xff" + raw[1:]                       # six bits of ones: '_' in the URL-safe alphabet
    return base64.urlsafe_b64encode(raw) + b"\n"


@case("T-136", FINDING)
def t136():
    """URL-safe base64 is PROTO_E_KEY_FORMAT wherever its - or _ falls."""
    got = three_loads(lib.proto(), urlsafe_with_leading_underscore)
    text = urlsafe_with_leading_underscore(b"\0" * 32)[:1]
    check(text in (b"_", b"-"), "test data is wrong: %r" % text)
    eq(got, (FORMAT, FORMAT, FORMAT), "a URL-safe key that begins with %r" % text)


@case("T-137")
def t137():
    """Missing padding is PROTO_E_KEY_FORMAT."""
    all_three(lib.proto(), lambda raw: ls.b64(raw).rstrip("=").encode() + b"\n", FORMAT, "no padding")


@case("T-138")
def t138():
    """One = too many is PROTO_E_KEY_FORMAT."""
    all_three(lib.proto(), lambda raw: ls.b64(raw).encode() + b"=\n", FORMAT, "one = too many")


ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"


def noncanonical_spelling(raw):
    text = ls.b64(raw)
    pad = len(text) - len(text.rstrip("="))
    i = len(text) - pad - 1                      # the last character that carries data
    v = ALPHABET.index(text[i])
    assert v & 1 == 0                            # its unused low bits are zero
    return (text[:i] + ALPHABET[v | 1] + text[i + 1:]).encode() + b"\n"


@case("T-139")
def t139():
    """A non-canonical spelling is PROTO_E_KEY_FORMAT."""
    all_three(lib.proto(), noncanonical_spelling, FORMAT, "unused bits of the last character set")


@case("T-140")
def t140():
    """Valid base64 of the wrong size is PROTO_E_KEY_SIZE."""
    P = lib.proto()
    d = harness.tmpdir("sizes")
    ident = make_identity(d)
    for n in (31, 33, 64):
        pub = write_file(os.path.join(d, "p%d" % n), key_line(os.urandom(n)))
        eq(P.load_pubkey_hex(pub)[0], SIZE, "a %d-byte public key" % n)
        enc = write_file(os.path.join(d, "e%d" % n), key_line(os.urandom(n)))
        eq(P.load_keys(ident.auth_key, enc)[0], SIZE, "a %d-byte enc.key" % n)
    short = write_file(os.path.join(d, "a32"), key_line(os.urandom(32)))
    eq(P.load_keys(short, ident.enc_key)[0], SIZE, "a 32-byte auth.key")
    long_ = write_file(os.path.join(d, "a65"), key_line(os.urandom(65)))
    eq(P.load_keys(long_, ident.enc_key)[0], SIZE, "a 65-byte auth.key")


@case("T-141")
def t141():
    """A first line longer than the 511-byte window is refused safely."""
    P = lib.proto()
    all_three(P, lambda raw: b"A" * 600 + b"\n", FORMAT, "600 A's")
    all_three(P, lambda raw: b"A" * 508 + b"\n", SIZE, "508 A's, valid base64 of 381 bytes")


@case("T-142")
def t142():
    """A huge file is refused quickly."""
    P = lib.proto()
    d = harness.tmpdir("huge")
    path = os.path.join(d, "huge.key")
    chunk = b"A" * (1024 * 1024)
    with open(path, "wb") as f:
        for _ in range(100):
            f.write(chunk)
    t0 = net.now()
    rc, _ = P.load_pubkey_hex(path)
    took = net.ms_since(t0)
    check(rc < 0, "a 100 MB file loaded")
    check(took < 1000 + harness.slack_ms(1000), "refusing the file took %.0f ms" % took)
    os.unlink(path)


@case("T-143", FINDING)
def t143():
    """A NUL byte after the key is refused."""
    got = three_loads(lib.proto(), lambda raw: ls.b64(raw).encode() + b"\0junk\n")
    eq(got, (STRAY, STRAY, STRAY), "a NUL after the key")


@case("T-144", FINDING)
def t144():
    """A UTF-16 file gets one diagnosis, whatever its byte order."""
    P = lib.proto()
    be = three_loads(P, lambda raw: (ls.b64(raw) + "\n").encode("utf-16-be"))
    le = three_loads(P, lambda raw: (ls.b64(raw) + "\n").encode("utf-16"))   # with a mark
    harness.note("utf-16-be: %r, utf-16 with mark: %r" % (be, le))
    eq(be, le, "the same file in two byte orders")
    eq(be, (STRAY, STRAY, STRAY), "a UTF-16 file")


def pubkey_rc(P, path):
    return P.load_pubkey_hex(path)[0]


def all_paths(P, path):
    """The code of each of the three loaders for a path, the other file being good."""
    d = harness.tmpdir("good")
    ident = make_identity(d)
    return (pubkey_rc(P, path), P.load_keys(path, ident.enc_key)[0], P.load_keys(ident.auth_key, path)[0])


@case("T-145")
def t145():
    """A path that leads nowhere is PROTO_E_KEY_NOT_FOUND."""
    P = lib.proto()
    d = harness.tmpdir("nowhere")
    ident = make_identity(d)
    os.symlink(os.path.join(d, "nothing"), os.path.join(d, "dangling"))
    os.symlink("loop-b", os.path.join(d, "loop-a"))
    os.symlink("loop-a", os.path.join(d, "loop-b"))
    paths = {
        "a missing file": os.path.join(d, "missing.key"),
        "a component that is a file": os.path.join(ident.auth_key, "x"),
        "a dangling symlink": os.path.join(d, "dangling"),
        "a symlink loop": os.path.join(d, "loop-a"),
        "a component longer than NAME_MAX": os.path.join(d, "n" * 300),
        "a path longer than PATH_MAX": os.path.join(d, *(["d" * 100] * 60)),
    }
    for what, path in paths.items():
        eq(all_paths(P, path), (NOT_FOUND,) * 3, what)


@case("T-146")
def t146():
    """A symlink to a valid key loads."""
    P = lib.proto()
    d = harness.tmpdir("links")
    ident = make_identity(d)
    link = os.path.join(d, "link.key")
    os.symlink(ident.enc_key, link)
    eq(P.load_keys(ident.auth_key, link)[0], OK, "a symlink to enc.key")
    link2 = os.path.join(d, "link.pub")
    os.symlink(ident.auth_pub, link2)
    eq(P.load_pubkey_hex(link2)[0], OK, "a symlink to auth.pub")


@case("T-147", tags=("notroot",))
def t147():
    """No permission is PROTO_E_KEY_DENIED."""
    P = lib.proto()
    d = harness.tmpdir("denied")
    ident = make_identity(d)
    os.chmod(ident.auth_pub, 0)
    eq(pubkey_rc(P, ident.auth_pub), DENIED, "mode 000")
    os.chmod(ident.auth_pub, 0o600)
    sub = os.path.join(d, "sub")
    os.mkdir(sub)
    inner = write_file(os.path.join(sub, "k"), key_line(ident.auth_pk))
    os.chmod(sub, 0o600)
    try:
        eq(pubkey_rc(P, inner), DENIED, "a parent directory without search permission")
    finally:
        os.chmod(sub, 0o700)


@case("T-148", timeout=60)
def t148():
    """A path that is not a regular file is PROTO_E_KEY_NOT_FILE."""
    P = lib.proto()
    d = harness.tmpdir("special")
    results = {}

    def probe():
        fifo = os.path.join(d, "fifo")
        os.mkfifo(fifo)
        held = os.open(fifo, os.O_RDONLY | os.O_NONBLOCK)      # a reader, so a writer can open
        writer = os.open(fifo, os.O_WRONLY | os.O_NONBLOCK)
        fifo2 = os.path.join(d, "fifo2")
        os.mkfifo(fifo2)
        cases = [("a directory", d), ("/dev/null", "/dev/null"), ("/dev/zero", "/dev/zero"),
                 ("a FIFO a writer holds open", fifo), ("a FIFO with no writer", fifo2)]
        for what, path in cases:
            rc = pubkey_rc(P, path)
            if rc != NOT_FILE:
                os._exit(10 + [c[0] for c in cases].index(what))
    how, code = in_child(probe, timeout=10)
    eq((how, code), ("exit", 0), "special files (exit %s: %d; a hang would be 'timeout')" % (how, code))


@case("T-149", FINDING)
def t149():
    """A Unix-domain socket at the path is PROTO_E_KEY_NOT_FILE."""
    P = lib.proto()
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.bind("k.sock")
    s.listen(1)
    eq(pubkey_rc(P, os.path.abspath("k.sock")), NOT_FILE, "a socket at the key path")


@case("T-150")
def t150():
    """Out of descriptors is PROTO_E_KEY_OPEN."""
    P = lib.proto()
    d = harness.tmpdir("nofile")
    ident = make_identity(d)
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    # open() takes the lowest free number, so the limit goes there: a hole below the highest descriptor
    # in use (a runner that closed one) would otherwise leave room for the key file.
    held = set(net.open_fds())
    lowest_free = next(n for n in range(len(held) + 1) if n not in held)
    resource.setrlimit(resource.RLIMIT_NOFILE, (lowest_free, hard))
    eq(pubkey_rc(P, ident.auth_pub), OPEN, "a key file with no descriptor to open it")


@case("T-151", tags=("seam",))
def t151():
    """A failing read() is PROTO_E_KEY_READ."""
    d = harness.tmpdir("seam")
    ident = make_identity(d)
    runprobe.must_pass("seam_crypto", ["read_eio", ident.auth_pub], seams=runprobe.CRYPTO_SEAMS)


@case("T-152", tags=("seam",))
def t152():
    """EINTR during the read is retried."""
    d = harness.tmpdir("seam")
    ident = make_identity(d)
    runprobe.must_pass("seam_crypto", ["read_eintr", ident.auth_pub], seams=runprobe.CRYPTO_SEAMS)


@case("T-153", tags=("seam",))
def t153():
    """A key delivered one byte per read() loads."""
    d = harness.tmpdir("seam")
    ident = make_identity(d)
    runprobe.must_pass("seam_crypto", ["read_onebyte", ident.auth_pub], seams=runprobe.CRYPTO_SEAMS)


@case("T-154")
def t154():
    """No descriptor leaks."""
    P = lib.proto()
    d = harness.tmpdir("leaks")
    ident = make_identity(d)
    bad = {
        "empty": write_file(os.path.join(d, "empty"), b""),
        "stray": write_file(os.path.join(d, "stray"), b" " + key_line(ident.auth_pk)),
        "format": write_file(os.path.join(d, "format"), b"AAAA*AAAA\n"),
        "size": write_file(os.path.join(d, "size"), key_line(os.urandom(31))),
        "missing": os.path.join(d, "missing"),
        "directory": d,
    }
    before = net.fd_count()
    for name, path in bad.items():
        pubkey_rc(P, path)
        P.load_keys(path, ident.enc_key)
        P.load_keys(ident.auth_key, path)
    pubkey_rc(P, ident.auth_pub)
    P.load_keys(ident.auth_key, ident.enc_key)
    eq(net.fd_count(), before, "open descriptors after every outcome")


@case("T-155", tags=("seam",))
def t155():
    """The file is opened read-only, non-blocking and close-on-exec."""
    d = harness.tmpdir("seam")
    ident = make_identity(d)
    runprobe.must_pass("seam_crypto", ["open_flags", ident.auth_pub], seams=runprobe.CRYPTO_SEAMS)


@case("T-156", tags=("seam",))
def t156():
    """The key's text is wiped on every way out."""
    d = harness.tmpdir("seam")
    ident = make_identity(d)
    files = {
        "ok": ident.auth_pub,
        "empty": write_file(os.path.join(d, "empty"), b"\n"),
        "stray": write_file(os.path.join(d, "stray"), b" " + key_line(ident.auth_pk)),
        "format": write_file(os.path.join(d, "format"), b"AAAA*AAAA\n"),
        "size": write_file(os.path.join(d, "size"), key_line(os.urandom(31))),
        "readfail": ident.auth_pub,
    }
    for kind, path in files.items():
        runprobe.must_pass("seam_crypto", ["memzero", kind, path], seams=runprobe.CRYPTO_SEAMS)


@case("T-157")
def t157():
    """A failed load leaves the caller's buffer alone."""
    P = lib.proto()
    d = harness.tmpdir("buf")
    ident = make_identity(d)
    bad = {
        "empty": write_file(os.path.join(d, "empty"), b""),
        "stray": write_file(os.path.join(d, "stray"), b" " + key_line(ident.auth_pk)),
        "format": write_file(os.path.join(d, "format"), b"AAAA*AAAA\n"),
        "size": write_file(os.path.join(d, "size"), key_line(os.urandom(31))),
        "missing": os.path.join(d, "missing"),
        "directory": d,
    }
    for name, path in bad.items():
        rc, buf = P.load_pubkey_hex(path, 65, fill=ord("Z"))
        check(rc < 0, "%s: loaded (rc %d)" % (name, rc))
        eq(buf, b"Z" * 65, "hex_out after the failure %s" % name)


@case("T-158")
def t158():
    """A relative path resolves against the working directory."""
    P = lib.proto()
    d = harness.tmpdir("cwd")
    ident = make_identity(d)
    empty = harness.tmpdir("elsewhere")

    def inside():
        os.chdir(d)
        if P.load_keys("auth.key", "enc.key")[0] != OK:
            os._exit(1)
        if P.load_pubkey_hex("auth.pub")[0] != OK:
            os._exit(2)
        os.chdir(empty)
        if P.load_pubkey_hex("auth.pub")[0] != NOT_FOUND:
            os._exit(3)
    eq(in_child(inside), ("exit", 0), "relative paths in a child of their own")
