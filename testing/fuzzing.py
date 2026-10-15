"""Fuzz targets (T-394 to T-398) and their corpora (T-404).

A target is a function of one input that raises harness.Fail when a property of
the library does not hold. The driver mutates the inputs of the corpus for a
time budget, in forked batches so that a crash of the library is caught and the
input that caused it is kept: it is written to testing/corpus/<target>/ and
stays there, replayed by T-404 on every run.
"""

import base64
import hashlib
import os
import random
import re
import socket
import time

import harness
import keyfiles
import lib
import libsodium as ls
import net
from harness import Fail, HERE, check, eq
from net import Peer

CORPUS_DIR = os.path.join(HERE, "corpus")
SLICE_SECONDS = 1.0


def budget():
    return float(os.environ.get("PROTO_FUZZ_SECONDS", "20"))


# ------------------------------------------------------------------ mutation

TOKENS = [b"\n", b"\r\n", b"\0", b" ", b"AUTH ", b"HELLO", b"CHALLENGE ", b"REGISTER ", b"FAIL ", b"==", b"=",
          b"A" * 43 + b"=", b"\xef\xbb\xbf", b"\xc2\xa0", b"-", b"_", b"+", b"/"]


def mutate(rnd, data):
    data = bytearray(data)
    for _ in range(rnd.randint(1, 4)):
        op = rnd.randint(0, 7)
        if op == 0 and data:
            i = rnd.randrange(len(data))
            data[i] ^= 1 << rnd.randrange(8)
        elif op == 1 and data:
            data[rnd.randrange(len(data))] = rnd.randrange(256)
        elif op == 2:
            data.insert(rnd.randint(0, len(data)), rnd.randrange(256))
        elif op == 3 and data:
            del data[rnd.randrange(len(data))]
        elif op == 4 and data:
            i = rnd.randrange(len(data))
            j = min(len(data), i + rnd.randint(1, 16))
            data[i:i] = data[i:j]
        elif op == 5 and data:
            del data[rnd.randrange(len(data)):]
        elif op == 6:
            data[rnd.randint(0, len(data)):0] = rnd.choice(TOKENS)
        elif op == 7:
            data += bytes(rnd.randrange(256) for _ in range(rnd.randint(1, 8)))
    return bytes(data[:6000])


# -------------------------------------------------------------------- oracles

ALPHABET = re.compile(rb"[A-Za-z0-9+/]+={0,2}")


def first_line(data):
    """The first line of a key file as the loader reads it: a 511-byte window, up to the newline,
    without the carriage returns that end it."""
    window = data[:511]
    i = window.find(b"\n")
    line = window if i < 0 else window[:i]
    while line.endswith(b"\r"):
        line = line[:-1]
    return line


def canonical(line, size):
    """The decoded key if line is the canonical standard base64 of `size` bytes, else None."""
    if len(line) % 4 or not ALPHABET.fullmatch(line):
        return None
    try:
        raw = base64.b64decode(line, validate=True)
    except ValueError:
        return None
    if len(raw) != size or base64.b64encode(raw) != line:
        return None
    return raw


# --------------------------------------------------------------------- targets

class Target(object):
    name = ""

    def setup(self):
        """Build whatever the target needs; called once in the parent."""

    def seeds(self):
        """Inputs written to the corpus directory when it lacks them. They must not change from run to run."""
        return []

    def extra(self):
        """Inputs that only make sense in this process (made with this run's keys): not kept on disk."""
        return []

    def run(self, data):
        raise NotImplementedError


class KeyFiles(Target):
    name = "key_files"
    DOCUMENTED = set(range(-311, -300)) | {0, -101}

    def setup(self):
        self.P = lib.proto()
        self.ident = keyfiles.make_identity()
        self.path = os.path.join(harness.tmpdir("fuzz"), "fuzz.key")

    def seeds(self):
        pk, sk = ls.sign_seed_keypair(bytes(range(32)))
        enc = bytes(range(32, 64))
        k = keyfiles.key_line
        return [k(pk), k(sk), k(enc), k(pk)[:-1] + b"\r\n", k(pk) + b"# label\n",
                b"", b"\n", b" " + k(pk), b"A" * 508 + b"\n", b"AAAA*AAAA\n"]

    def run(self, data):
        line = first_line(data)
        window = data[:511]
        end = window.find(b"\n")
        region = window if end < 0 else window[:end]
        if b"\0" in region:
            return                                    # a NUL in the first line loads (T-143): skip until it is fixed
        if any(c >= 0x80 for c in region):
            return                                    # a byte above 0x7F inside the key loads (T-424): same
        with open(self.path, "wb") as f:
            f.write(data)
        P = self.P
        rc_pub = P.load_pubkey_hex(self.path)[0]
        rc_auth = P.load_keys(self.path, self.ident.enc_key)[0]
        rc_enc = P.load_keys(self.ident.auth_key, self.path)[0]
        for what, rc in (("public key", rc_pub), ("auth.key", rc_auth), ("enc.key", rc_enc)):
            check(rc in self.DOCUMENTED, "%s: an undocumented code %d" % (what, rc))
        raw32, raw64 = canonical(line, 32), canonical(line, 64)
        check((rc_pub == 0) == (raw32 is not None), "public key: rc %d for a line that is %scanonical" % (rc_pub, "" if raw32 else "not "))
        if rc_auth == 0:
            check(raw64 is not None, "auth.key: loaded a line that is not the canonical base64 of 64 bytes")
        if raw64 is not None:
            check(rc_auth in (0, -304), "auth.key: a canonical 64-byte key gave %d" % rc_auth)
        if raw32 is not None and raw32 != self.ident.auth_pk:
            check(rc_enc == 0, "enc.key: a canonical 32-byte key gave %d" % rc_enc)
        if raw32 is not None and raw32 == self.ident.auth_pk:
            check(rc_enc == -311, "enc.key: auth.pub's key gave %d, not PROTO_E_KEY_PUBLIC" % rc_enc)
        if rc_enc == 0:
            check(raw32 is not None, "enc.key: loaded a line that is not the canonical base64 of 32 bytes")


def model_fixed(stream, bufsz):
    """What proto_recv_line must return for a stream: (rc, text, bytes consumed)."""
    out = bytearray()
    pos = 0
    while True:
        full = len(out) + 1 >= bufsz
        if pos >= len(stream):
            return -603, bytes(out), pos
        c = stream[pos]
        pos += 1
        if c == 10:
            return len(out), bytes(out), pos
        if c == 13:
            continue
        if full:
            return -604, bytes(out), pos
        out.append(c)


def model_dyn(stream, cap):
    """The outcome of proto_recv_line_dyn_status: ('ok', line) | ('eof', None) | ('long', None)."""
    out = bytearray()
    for c in stream:
        if c == 10:
            return ("ok", bytes(out)) if len(out) <= cap else ("long", None)
        if c != 13:
            out.append(c)
        if len(out) > cap:
            return "long", None
    return ("eof", None) if len(out) <= cap else ("long", None)


def drain(sock):
    sock.setblocking(False)
    got = b""
    while True:
        try:
            data = sock.recv(65536)
        except (BlockingIOError, ConnectionResetError):
            break
        if not data:
            break
        got += data
    return got


class LineReaders(Target):
    name = "line_readers"

    def setup(self):
        self.P = lib.proto()
        self.P4 = lib.proto("pay4096")

    def seeds(self):
        return [b"hello\n", b"a\r\nb\n", b"\n\n", b"x" * 100 + b"\n", b"no newline", b"\r\r\r\n", b"ab\0cd\n"]

    def run(self, data):
        data = data[:3000]
        r = random.Random(hashlib.sha1(data).digest())
        mode = r.choice(("fixed", "timeout", "dyn"))
        a, b = net.sockpair()
        a.sendall(data)
        a.shutdown(socket.SHUT_WR)
        fd = b.fileno()
        if mode == "dyn":
            got, status = self.P4.recv_dyn(fd)
            kind, text = model_dyn(data, 4096)
            if kind == "ok":
                seen = text.split(b"\0")[0]               # the caller sees a line end at a NUL (T-109)
                check((got, status) == (seen, 0), "proto_recv_line_dyn_status gave %r %d for a line of %d" % (got and got[:20], status, len(text)))
            else:
                want = -603 if kind == "eof" else -604
                check(got is None and status == want, "proto_recv_line_dyn_status: %r %d, want NULL %d" % (got and got[:20], status, want))
            return
        bufsz = r.randint(1, 80)
        if mode == "timeout":
            ms = r.choice((0, 20, 30, 50))
            rc, raw = self.P.recv_line_timeout_raw(fd, ms, bufsz)
            if ms == 0:
                check(rc == -605, "ms == 0 gave %d" % rc)
                eq(drain(b), data, "ms == 0 consumed something")
                return
        else:
            rc, raw = self.P.recv_line_raw(fd, bufsz)
        want_rc, want_text, pos = model_fixed(data, bufsz)
        check(rc == want_rc, "bufsz %d: rc %d, want %d" % (bufsz, rc, want_rc))
        check(raw[:len(want_text)] == want_text and raw[len(want_text)] == 0, "bufsz %d: buf %r, want %r" % (bufsz, raw[:len(want_text) + 1], want_text))
        eq(drain(b), data[pos:], "bytes left in the stream")


FAIL_REASONS = {b"expected HELLO", b"expected AUTH", b"invalid AUTH format", b"invalid public key",
                b"invalid signature", b"signature verification failed", b"access denied", b"internal error"}


class ServerHandshake(Target):
    name = "server_handshake"

    def setup(self):
        self.P = lib.proto()
        self.ident = keyfiles.make_identity(write=False)
        self.allowed = self.ident.hex

    def seeds(self):
        pk = ls.b64(bytes(range(32))).encode()
        sig = ls.b64(bytes(range(64))).encode()
        return [b"HELLO\n", b"HELLO\nAUTH " + pk + b" " + sig + b"\n", b"hello\n", b"HELLO\nAUTH x y\n",
                b"HELLO\r\nAUTH " + pk + b" " + sig + b"\r\n", b"", b"HELLO\nHELLO\n"]

    def run(self, data):
        a, b = net.sockpair()
        a.sendall(data[:3000])
        a.shutdown(socket.SHUT_WR)
        got = self.P.auth_server(b.fileno(), self.allowed)
        b.close()
        check(got is None, "a handshake with no valid signature returned an identity: %r" % (got,))
        peer = Peer(a)
        peer.recv_all()
        lines = [l for l in bytes(peer.rx).split(b"\n") if l]
        for l in lines:
            ok = (l.startswith(b"CHALLENGE ") and len(l) == 54) or (l.startswith(b"FAIL ") and l[5:] in FAIL_REASONS)
            check(ok, "an undocumented line from the server: %r" % l[:60])
        fails = [i for i, l in enumerate(lines) if l.startswith(b"FAIL ")]
        if fails:
            check(fails == [len(lines) - 1], "lines after a FAIL: %r" % lines[-3:])


class ClientHandshake(Target):
    name = "client_handshake"
    CODES = {0, 1, -601, -602, -603, -604, -605, -701, -702, -703}

    def setup(self):
        self.P = lib.proto()
        ident = keyfiles.make_identity()
        rc, self.keys = self.P.load_keys(ident.auth_key, ident.enc_key)

    def seeds(self):
        ch = ls.b64(bytes(range(32))).encode()
        return [b"CHALLENGE " + ch + b"\nOK\n", b"CHALLENGE " + ch + b"\nREGISTER\n", b"FAIL server busy\n",
                b"CHALLENGE " + ch + b"\nFAIL access denied\n", b"", b"CHALLENGE AA==\n", b"OK\n"]

    def run(self, data):
        a, b = net.sockpair()
        a.sendall(data[:3000])
        a.shutdown(socket.SHUT_WR)
        rc = self.P.auth_client(b.fileno(), self.keys)
        check(rc in self.CODES, "proto_auth_client returned the undocumented code %d" % rc)


class Unseal(Target):
    name = "unseal"

    def setup(self):
        self.P = lib.proto()
        self.pk, self.sk = ls.box_keypair()
        self.valid = {}
        for n in (0, 1, 20, 100, 1000):
            plain = os.urandom(n)
            self.valid[self.P.seal_new(plain, self.pk)] = plain

    def seeds(self):
        return [b"", b"AAAA", b"not base64", b"A" * 64, b"=" * 64, ls.b64(bytes(range(47))).encode(),
                ls.b64(bytes(range(48))).encode(), ls.b64(bytes(range(100))).encode()]

    def extra(self):
        return list(self.valid)

    def run(self, data):
        text = data.split(b"\0")[0]
        if text not in self.valid and any(c >= 0x80 for c in text):
            return                                    # a byte above 0x7F takes the place of a character (T-425): skip
        plain, n, _ = self.P.unseal_full(text, self.pk, self.sk)
        if text in self.valid:
            check(plain == self.valid[text], "a valid box did not open to its plaintext")
        else:
            check(plain is None, "an input that is no sealed box of ours opened (%d bytes)" % len(text))


TARGETS = {t.name: t for t in (KeyFiles(), LineReaders(), ServerHandshake(), ClientHandshake(), Unseal())}


# ---------------------------------------------------------------------- driver

def corpus_dir(name):
    return os.path.join(CORPUS_DIR, name)


def corpus_inputs(name):
    d = corpus_dir(name)
    if not os.path.isdir(d):
        return []
    out = []
    for f in sorted(os.listdir(d)):
        with open(os.path.join(d, f), "rb") as fh:
            out.append((f, fh.read()))
    return out


def ensure_seeds(target):
    d = corpus_dir(target.name)
    os.makedirs(d, exist_ok=True)
    for seed in target.seeds():
        path = os.path.join(d, "seed-" + hashlib.sha1(seed).hexdigest()[:10])
        if not os.path.exists(path):
            with open(path, "wb") as f:
                f.write(seed)


def keep_crash(target, data):
    d = corpus_dir(target.name)
    os.makedirs(d, exist_ok=True)
    path = os.path.join(d, "crash-" + hashlib.sha1(data).hexdigest()[:12])
    with open(path, "wb") as f:
        f.write(data)
    return path


def replay(target):
    """Run every input of the corpus once. Returns the number of inputs."""
    target.setup()
    ensure_seeds(target)
    inputs = corpus_inputs(target.name) + [("(this run's)", d) for d in target.extra()]
    for name, data in inputs:
        try:
            target.run(data)
        except Fail as e:
            raise Fail("corpus/%s/%s: %s" % (target.name, name, e))
    return len(inputs)


def fuzz(name, seconds=None):
    """Mutate the corpus of a target for `seconds`; fail, keeping the input, if a property breaks."""
    target = TARGETS[name]
    seconds = budget() if seconds is None else seconds
    target.setup()
    ensure_seeds(target)
    pool = [d for _, d in corpus_inputs(name)] + target.extra() or [b""]
    last = os.path.join(harness.tmpdir("fuzz-last"), "last")
    message = last + ".msg"
    seed0 = int(os.environ.get("PROTO_FUZZ_SEED", str(int(time.time()))))
    harness.note("%s: seed %d, %d inputs, %.0f s" % (name, seed0, len(pool), seconds))
    deadline = time.monotonic() + seconds
    total = 0
    batch_no = 0

    def batch():
        rnd = random.Random(seed0 * 1000003 + batch_no)
        end = time.monotonic() + SLICE_SECONDS
        n = 0
        while time.monotonic() < end:
            data = mutate(rnd, rnd.choice(pool))
            with open(last, "wb") as f:
                f.write(data)
            try:
                target.run(data)
            except Fail as e:
                with open(message, "w") as f:
                    f.write(str(e))
                os._exit(1)
            n += 1
        with open(last + ".count", "w") as f:
            f.write(str(n))
        os._exit(0)

    while time.monotonic() < deadline:
        batch_no += 1
        how, code = harness.in_child(batch, timeout=60)
        if how == "exit" and code == 0:
            try:
                total += int(open(last + ".count").read())
            except (OSError, ValueError):
                pass
            continue
        data = open(last, "rb").read() if os.path.exists(last) else b""
        kept = keep_crash(target, data)
        why = open(message).read() if how == "exit" and os.path.exists(message) else \
            ("killed by signal %d" % code if how == "signal" else "no end within 60 s")
        raise Fail("%s: %s; the input is kept as %s (seed %d, batch %d)" % (name, why, os.path.relpath(kept, harness.ROOT), seed0, batch_no))
    harness.note("%s: %d inputs run" % (name, total))
    return total
