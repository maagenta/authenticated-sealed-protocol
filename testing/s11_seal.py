"""XII. proto_seal, proto_seal_new, proto_unseal_new (T-179 to T-202).
XIII. proto_sign_challenge, proto_verify_challenge (T-203 to T-211).
"""

import ctypes
import os
import re

import harness
import lib
import libsodium as ls
import runprobe
from harness import FINDING, case, check, eq, skip

SIZE_MAX = lib.SIZE_MAX
SEAL_MSG_MAX = (SIZE_MAX - 5) // 4 * 3 - 48
PARAM, TOO_SMALL, CRYPTO = -101, -102, -401


def keypair():
    return ls.box_keypair()


def b64_len(n):
    """Characters of a sealed message of n bytes."""
    return (n + 48 + 2) // 3 * 4


@case("T-179")
def t179():
    """A sealed message opens to the same bytes."""
    P = lib.proto()
    pk, sk = keypair()
    for n in (0, 1, 2, 3, 4, 47, 48, 49, 255, 256, 4096, 65535, 1024 * 1024):
        msg = os.urandom(n)
        sealed = P.seal_new(msg, pk)
        check(sealed is not None, "proto_seal_new returned NULL for %d bytes" % n)
        plain, out_len, terminator = P.unseal_full(sealed, pk, sk)
        check(plain == msg, "the message of %d bytes did not open to itself" % n)
        eq(out_len, n, "out_len for %d bytes" % n)
        eq(terminator, 0, "the byte after the plaintext of %d bytes" % n)


@case("T-180", tags=("slow",), timeout=300)
def t180():
    """16 MiB seals and opens."""
    P = lib.proto()
    pk, sk = keypair()
    msg = os.urandom(16 * 1024 * 1024)
    sealed = P.seal_new(msg, pk)
    check(sealed is not None, "proto_seal_new returned NULL for 16 MiB")
    plain, out_len, _ = P.unseal_full(sealed, pk, sk)
    check(plain == msg, "16 MiB did not open to itself")


@case("T-181")
def t181():
    """Sealing is binary-safe, and the output is one clean line."""
    P = lib.proto()
    pk, sk = keypair()
    msg = b"\0\n\r\xff" * 200 + b"line one\r\nline two\n\0"
    sealed = P.seal_new(msg, pk)
    for ch in (b"\n", b"\r", b" ", b"\t"):
        check(ch not in sealed, "the base64 contains %r" % ch)
    plain, n, _ = P.unseal_full(sealed, pk, sk)
    check(plain == msg, "the binary message did not open to itself")


@case("T-182")
def t182():
    """The output is standard base64 of the documented length."""
    P = lib.proto()
    pk, sk = keypair()
    for n in (0, 1, 2, 3, 100, 1000, 5001):
        sealed = P.seal_new(os.urandom(n), pk)
        check(re.fullmatch(rb"[A-Za-z0-9+/]*={0,2}", sealed), "unexpected characters in the base64 of %d bytes" % n)
        eq(len(sealed), b64_len(n), "length of the base64 of %d bytes" % n)
    eq(len(P.seal_new(b"", pk)), 64, "the base64 of an empty message")


@case("T-183")
def t183():
    """The same message sealed twice gives two different ciphertexts."""
    P = lib.proto()
    pk, sk = keypair()
    a, b = P.seal_new(b"same message", pk), P.seal_new(b"same message", pk)
    check(a != b, "two seals of one message are identical")
    for s in (a, b):
        eq(P.unseal_full(s, pk, sk)[0], b"same message", "opening")


@case("T-184")
def t184():
    """proto_seal refuses a buffer one byte short, without an abort."""
    P = lib.proto()
    pk, sk = keypair()
    msg = b"hello"
    need = lib.base64_buffer_size(len(msg) + 48)
    buf = ctypes.create_string_buffer(need)
    eq(P.c_seal(msg, len(msg), pk, buf, need), 0, "an exactly sized buffer")
    for size in (need - 1, 1, 0):
        buf = ctypes.create_string_buffer(b"Z" * need)
        eq(P.c_seal(msg, len(msg), pk, buf, size), TOO_SMALL, "a buffer of %d" % size)
        eq(buf.raw[:need], b"Z" * need, "out_b64 after a refusal with size %d" % size)


@case("T-185")
def t185():
    """A length no message can have is PROTO_E_PARAM, without an abort."""
    P = lib.proto()
    pk, sk = keypair()
    buf = ctypes.create_string_buffer(64)
    for n in (SIZE_MAX, SIZE_MAX - 47, SEAL_MSG_MAX + 1):
        eq(P.c_seal(None, n, pk, buf, 0), PARAM, "proto_seal(NULL, %d)" % n)
    eq(P.c_seal(None, SEAL_MSG_MAX, pk, buf, 0), TOO_SMALL, "proto_seal(NULL, SEAL_MSG_MAX)")


@case("T-186", tags=("linux",))
def t186():
    """The same boundaries hold in the 32-bit build."""
    import suite
    suite.require_toolchain(["-m32"])
    suite.run_suite("m32", extra=["-m32"], scenario="seal_bounds")


@case("T-187")
def t187():
    """proto_seal_new returns NULL for those lengths."""
    P = lib.proto()
    pk, sk = keypair()
    for n in (SIZE_MAX, SIZE_MAX - 47, SEAL_MSG_MAX + 1):
        check(not P.c_seal_new(None, n, pk), "proto_seal_new(NULL, %d) returned a pointer" % n)


SMALL_ORDER_X25519 = [
    "00" * 32,
    "01" + "00" * 31,
    "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
    "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
]


@case("T-188")
def t188():
    """A low-order public key is PROTO_E_CRYPTO."""
    P = lib.proto()
    for hexpk in SMALL_ORDER_X25519:
        pk = bytes.fromhex(hexpk)
        buf = ctypes.create_string_buffer(lib.base64_buffer_size(1 + 48))
        eq(P.c_seal(b"x", 1, pk, buf, len(buf)), CRYPTO, "proto_seal to the point %s..." % hexpk[:8])
        check(P.seal_new(b"x", pk) is None, "proto_seal_new to the point %s... returned a string" % hexpk[:8])


@case("T-189", tags=("seam",))
def t189():
    """A failed allocation is PROTO_E_NOMEM."""
    runprobe.must_pass("seam_crypto", ["malloc_fail"], seams=runprobe.CRYPTO_SEAMS)


@case("T-190")
def t190():
    """The wrong secret key opens nothing."""
    P = lib.proto()
    pk, sk = keypair()
    pk2, sk2 = keypair()
    sealed = P.seal_new(b"for the first", pk)
    plain, out_len, _ = P.unseal_full(sealed, pk, sk2)
    eq((plain, out_len), (None, 0xDEAD), "the right pk with the wrong sk")
    plain, out_len, _ = P.unseal_full(sealed, pk2, sk2)
    eq((plain, out_len), (None, 0xDEAD), "another recipient's pair")


@case("T-191")
def t191():
    """The right secret key with another public key opens nothing."""
    P = lib.proto()
    pk, sk = keypair()
    pk2, sk2 = keypair()
    sealed = P.seal_new(b"for the first", pk)
    eq(P.unseal_full(sealed, pk2, sk)[0], None, "the right sk with another pk")


@case("T-192")
def t192():
    """Any flipped bit makes the open fail."""
    P = lib.proto()
    pk, sk = keypair()
    msg = os.urandom(100)
    cipher = ls.b64d(P.seal_new(msg, pk))
    for i in range(len(cipher)):
        bad = bytearray(cipher)
        bad[i] ^= 1 << (i % 8)
        got = P.unseal_full(ls.b64(bytes(bad)), pk, sk)[0]
        check(got is None, "a flipped bit in byte %d of %d still opened" % (i, len(cipher)))


@case("T-193")
def t193():
    """A truncated box opens nothing."""
    P = lib.proto()
    pk, sk = keypair()
    sealed = P.seal_new(b"a message of some length", pk)
    cipher = ls.b64d(sealed)
    eq(P.unseal_full(sealed[:-4], pk, sk)[0], None, "four characters off the end")
    eq(P.unseal_full(ls.b64(cipher[:47]), pk, sk)[0], None, "a box of 47 bytes")
    eq(P.unseal_full(b"", pk, sk)[0], None, "an empty string")


@case("T-194")
def t194():
    """Extra bytes make the open fail."""
    P = lib.proto()
    pk, sk = keypair()
    sealed = P.seal_new(b"a message", pk)
    eq(P.unseal_full(sealed + b"AAAA", pk, sk)[0], None, "AAAA appended")


@case("T-195")
def t195():
    """Bad encoding makes the open fail."""
    P = lib.proto()
    pk, sk = keypair()
    padded = None
    for _ in range(100):                         # a box whose base64 has '=' and '+' or '/'
        s = P.seal_new(b"x", pk)
        if s.endswith(b"=") and (b"+" in s or b"/" in s):
            padded = s
            break
    check(padded, "could not make a sealed box with padding and a '+' or '/'")
    cases = {
        "missing padding": padded.rstrip(b"="),
        "the URL-safe alphabet": padded.replace(b"+", b"-").replace(b"/", b"_"),
        "a space inside": padded[:10] + b" " + padded[10:],
        "a newline inside": padded[:10] + b"\n" + padded[10:],
        "a trailing CR": padded + b"\r",
    }
    for what, text in cases.items():
        eq(P.unseal_full(text, pk, sk)[0], None, what)


@case("T-196")
def t196():
    """The box of an empty message opens to the empty string."""
    P = lib.proto()
    pk, sk = keypair()
    plain, n, terminator = P.unseal_full(P.seal_new(b"", pk), pk, sk)
    eq((plain, n, terminator), (b"", 0, 0), "an empty message")


@case("T-197")
def t197():
    """out_len == NULL is accepted."""
    P = lib.proto()
    pk, sk = keypair()
    sealed = P.seal_new(b"no length asked", pk)
    p = P.c_unseal_new(sealed, pk, sk, None)
    check(p, "proto_unseal_new returned NULL with out_len NULL")
    try:
        eq(ctypes.string_at(p), b"no length asked", "the plaintext, NUL-terminated")
    finally:
        lib.libc.free(p)


@case("T-198", FINDING)
def t198():
    """proto_unseal_new(NULL, ...) returns NULL."""
    P = lib.proto()
    pk, sk = keypair()
    p = P.c_unseal_new(None, pk, sk, None)
    check(not p, "proto_unseal_new(NULL, ...) returned a pointer")


@case("T-199")
def t199():
    """The output interoperates with plain libsodium."""
    P = lib.proto()
    pk, sk = keypair()
    msg = os.urandom(333)
    ours = P.seal_new(msg, pk)
    eq(ls.box_seal_open(ls.b64d(ours), pk, sk), msg, "crypto_box_seal_open of our output")
    theirs = ls.b64(ls.box_seal(msg, pk))
    eq(P.unseal_full(theirs, pk, sk)[0], msg, "proto_unseal_new of crypto_box_seal's output")


@case("T-200")
def t200():
    """proto_seal and proto_seal_new are interchangeable."""
    P = lib.proto()
    pk, sk = keypair()
    msg = b"interchangeable"
    rc, text = P.seal(msg, pk)
    eq(rc, 0, "proto_seal")
    heap = P.seal_new(msg, pk)
    eq(len(text), len(heap), "length of the two outputs")
    for s in (text, heap):
        eq(P.unseal_full(s, pk, sk)[0], msg, "opening")


@case("T-201", tags=("seam",))
def t201():
    """Opening allocates what the documents say."""
    runprobe.must_pass("seam_crypto", ["unseal_alloc"], seams=runprobe.CRYPTO_SEAMS)


@case("T-202")
def t202():
    """A failed open returns nothing and leaks nothing."""
    runprobe.must_pass("seam_crypto", ["unseal_failures"], seams=runprobe.CRYPTO_SEAMS)


# --------------------------------------------------- XIII. signing

SMALL_ORDER_ED25519 = [
    "01" + "00" * 31,
    "ecff" + "ff" * 29 + "7f",
    "00" * 31 + "80",
    "00" * 32,
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
]


@case("T-203")
def t203():
    """A signature verifies with the matching public key."""
    P = lib.proto()
    pk, sk = ls.sign_keypair()
    challenge = os.urandom(32)
    rc, sig = P.sign(challenge, sk)
    eq(rc, 0, "proto_sign_challenge")
    eq(P.verify(challenge, sig, pk), 0, "proto_verify_challenge")


@case("T-204")
def t204():
    """Signing is deterministic."""
    P = lib.proto()
    pk, sk = ls.sign_keypair()
    ch = os.urandom(32)
    check(P.sign(ch, sk)[1] == P.sign(ch, sk)[1], "two signatures of one challenge differ")
    check(P.sign(ch, sk)[1] != P.sign(os.urandom(32), sk)[1], "two challenges gave one signature")


@case("T-205")
def t205():
    """Signatures interoperate with plain libsodium."""
    P = lib.proto()
    pk, sk = ls.sign_keypair()
    ch = os.urandom(32)
    rc, sig = P.sign(ch, sk)
    eq(sig, ls.sign_detached(ch, sk), "the signature against crypto_sign_detached")
    check(ls.verify_detached(sig, ch, pk), "crypto_sign_verify_detached refuses our signature")


@case("T-206")
def t206():
    """Any flipped bit fails verification."""
    P = lib.proto()
    pk, sk = ls.sign_keypair()
    ch = os.urandom(32)
    rc, sig = P.sign(ch, sk)

    def flipped(raw, i):
        b = bytearray(raw)
        b[i // 8] ^= 1 << (i % 8)
        return bytes(b)

    for i in range(0, len(sig) * 8, 7):
        eq(P.verify(ch, flipped(sig, i), pk), -402, "signature with bit %d flipped" % i)
    for i in range(0, 256, 5):
        eq(P.verify(flipped(ch, i), sig, pk), -402, "challenge with bit %d flipped" % i)
        eq(P.verify(ch, sig, flipped(pk, i)), -402, "public key with bit %d flipped" % i)
    other = os.urandom(32)
    eq(P.verify(other, sig, pk), -402, "a signature for another challenge")


@case("T-207")
def t207():
    """The length of the message is part of it."""
    P = lib.proto()
    pk, sk = ls.sign_keypair()
    ch = os.urandom(32)
    rc, sig = P.sign(ch, sk)
    eq(P.verify(ch[:31], sig, pk), -402, "clen 31")
    eq(P.verify(ch + b"\0", sig, pk), -402, "clen 33")


@case("T-208")
def t208():
    """Empty and large messages sign and verify."""
    P = lib.proto()
    pk, sk = ls.sign_keypair()
    for n in (0, 1024 * 1024):
        msg = os.urandom(n)
        rc, sig = P.sign(msg, sk)
        eq(rc, 0, "proto_sign_challenge of %d bytes" % n)
        eq(P.verify(msg, sig, pk), 0, "proto_verify_challenge of %d bytes" % n)


@case("T-209")
def t209():
    """An all-zero signature with an all-zero key does not verify."""
    P = lib.proto()
    ch = os.urandom(32)
    zero_sig = b"\0" * 64
    eq(P.verify(ch, zero_sig, b"\0" * 32), -402, "all zeros")
    for hexpk in SMALL_ORDER_ED25519:
        eq(P.verify(ch, zero_sig, bytes.fromhex(hexpk)), -402, "the small-order key %s..." % hexpk[:8])


@case("T-210")
def t210():
    """A non-canonical signature does not verify."""
    P = lib.proto()
    pk, sk = ls.sign_keypair()
    ch = os.urandom(32)
    rc, sig = P.sign(ch, sk)
    bad = ls.noncanonical(sig)
    check(bad != sig, "test data is wrong")
    eq(P.verify(ch, bad, pk), -402, "S + L in place of S")


@case("T-211")
def t211():
    """Verification returns one of two codes."""
    P = lib.proto()
    pk, sk = ls.sign_keypair()
    seen = set()
    for i in range(10000):
        ch = os.urandom(32 if i % 3 else i % 40)
        if i % 100 == 0:
            sig = P.sign(ch, sk)[1]
            rc = P.verify(ch, sig, pk)
        else:
            rc = P.verify(ch, os.urandom(64), os.urandom(32))
        seen.add(rc)
    check(seen <= {0, -402}, "proto_verify_challenge returned %s" % sorted(seen))
