"""X. proto_load_keys (T-159 to T-170).
XI. proto_load_pubkey_hex (T-171 to T-178).
"""

import ctypes
import os
import subprocess
import threading

import harness
import keyfiles
import lib
import libsodium as ls
import net
import runprobe
from harness import FINDING, PIN, case, check, eq, in_child
from keyfiles import key_line, make_identity, write_file

OK = 0
EMPTY, FORMAT, NOT_FOUND, SIZE, PUBLIC, PARAM = -302, -303, -305, -310, -311, -101


def load_filled(P, auth, enc):
    out = lib.Keys.filled(0xAA)
    rc, _ = P.load_keys(auth, enc, out)
    return rc, out


@case("T-159")
def t159():
    """The files keygen writes load, and the public keys are derived."""
    P = lib.proto()
    d = harness.tmpdir("keygen")
    p = subprocess.run([lib.build_keygen()], cwd=d, stdin=subprocess.DEVNULL,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    eq(p.returncode, 0, "keygen exit status")
    rc, keys = P.load_keys(os.path.join(d, "auth.key"), os.path.join(d, "enc.key"))
    eq(rc, OK, "proto_load_keys on keygen's files")
    check(bytes(keys.auth_pk) == bytes(keys.auth_sk)[32:], "auth_pk is not the last 32 bytes of auth_sk")
    eq(bytes(keys.enc_pk), ls.scalarmult_base(bytes(keys.enc_sk)), "enc_pk")
    rc, hexed = P.load_pubkey_hex(os.path.join(d, "auth.pub"))
    eq(rc, OK, "proto_load_pubkey_hex on auth.pub")
    eq(hexed[:64], bytes(keys.auth_pk).hex().encode(), "the identity")


@case("T-160")
def t160():
    """Keys made with plain libsodium load."""
    P = lib.proto()
    ident = make_identity()
    rc, keys = P.load_keys(ident.auth_key, ident.enc_key)
    eq(rc, OK, "proto_load_keys")
    eq(bytes(keys.auth_sk), ident.auth_sk, "auth_sk")
    eq(bytes(keys.auth_pk), ident.auth_pk, "auth_pk")
    eq(bytes(keys.enc_sk), ident.enc_sk, "enc_sk")
    eq(bytes(keys.enc_pk), ident.enc_pk, "enc_pk")


@case("T-161")
def t161():
    """A damaged public half of auth.key is PROTO_E_KEY_MISMATCH."""
    P = lib.proto()
    ident = make_identity()
    sk = bytearray(ident.auth_sk)
    sk[40] ^= 0x01                                         # inside the public half
    write_file(ident.auth_key, key_line(bytes(sk)))
    rc, out = load_filled(P, ident.auth_key, ident.enc_key)
    eq(rc, -304, "proto_load_keys")
    check(out.is_zero(), "out is not all zero after PROTO_E_KEY_MISMATCH")


@case("T-162")
def t162():
    """Swapped paths are PROTO_E_KEY_SIZE."""
    P = lib.proto()
    ident = make_identity()
    rc, out = load_filled(P, ident.enc_key, ident.auth_key)
    eq(rc, SIZE, "the two paths swapped")
    check(out.is_zero(), "out is not all zero after the swap")
    rc, out = load_filled(P, ident.auth_key, ident.auth_key)
    eq(rc, SIZE, "the same path twice")
    check(out.is_zero(), "out is not all zero after the same path twice")


@case("T-163")
def t163():
    """A failed load leaves nothing in out."""
    P = lib.proto()
    ident = make_identity()
    d = ident.dir
    bad = {
        "missing": os.path.join(d, "missing"),
        "empty": write_file(os.path.join(d, "empty"), b""),
        "wrong size": write_file(os.path.join(d, "size"), key_line(os.urandom(31))),
        "damaged": write_file(os.path.join(d, "damaged"), b"AAAA*AAAA\n"),
    }
    for name, path in bad.items():
        rc, out = load_filled(P, ident.auth_key, path)
        check(rc < 0, "%s enc.key loaded" % name)
        check(out.is_zero(), "a good auth.key and a %s enc.key left the secret key in out" % name)
        rc, out = load_filled(P, path, ident.enc_key)
        check(rc < 0, "%s auth.key loaded" % name)
        check(out.is_zero(), "a %s auth.key and a good enc.key left something in out" % name)


@case("T-164")
def t164():
    """NULL arguments are PROTO_E_PARAM."""
    P = lib.proto()
    ident = make_identity()
    out = lib.Keys.filled(0xAA)
    eq(P.c_load_keys(None, ident.enc_key.encode(), ctypes.byref(out)), PARAM, "NULL auth path")
    check(out.is_zero(), "out is not all zero after a NULL auth path")
    out = lib.Keys.filled(0xAA)
    eq(P.c_load_keys(ident.auth_key.encode(), None, ctypes.byref(out)), PARAM, "NULL enc path")
    check(out.is_zero(), "out is not all zero after a NULL enc path")
    eq(P.c_load_keys(ident.auth_key.encode(), ident.enc_key.encode(), None), PARAM, "NULL out")


@case("T-165", PIN)
def t165():
    """All-zero keys load."""
    P = lib.proto()
    d = harness.tmpdir("zeros")
    ident = make_identity(d, write=False)
    pk, sk = ls.sign_seed_keypair(b"\0" * 32)
    write_file(ident.auth_key, key_line(sk))
    write_file(ident.enc_key, key_line(b"\0" * 32))
    rc, keys = P.load_keys(ident.auth_key, ident.enc_key)
    eq(rc, OK, "an auth.key from a zero seed and an enc.key of zeros")
    eq(bytes(keys.enc_sk), b"\0" * 32, "enc_sk")


@case("T-166")
def t166():
    """The code does not say which file failed."""
    P = lib.proto()
    ident = make_identity()
    empty = write_file(os.path.join(ident.dir, "empty"), b"")
    both = P.load_keys(empty, empty)[0]
    only_auth = P.load_keys(empty, ident.enc_key)[0]
    only_enc = P.load_keys(ident.auth_key, empty)[0]
    eq((both, only_auth, only_enc), (EMPTY, EMPTY, EMPTY), "an empty file in either place")


@case("T-167")
def t167():
    """The loader keeps no state."""
    P = lib.proto()
    one, two = make_identity(), make_identity()
    results = []

    def worker():
        for _ in range(50):
            rc, k = P.load_keys(one.auth_key, one.enc_key)
            results.append((rc, k.raw()))
    ts = [threading.Thread(target=worker) for _ in range(8)]
    [t.start() for t in ts]
    [t.join(60) for t in ts]
    want = P.load_keys(one.auth_key, one.enc_key)[1].raw()
    check(len(results) == 400 and all(r == (OK, want) for r in results), "a thread loaded something else")
    a = P.load_keys(one.auth_key, one.enc_key)[1].raw()
    b = P.load_keys(two.auth_key, two.enc_key)[1].raw()
    c = P.load_keys(one.auth_key, one.enc_key)[1].raw()
    check(a != b, "two identities came back the same")
    check(a == c, "the same files gave different bytes")
    rc, err, _ = runprobe.threads("load", one.auth_key, one.enc_key)
    check(rc == 0 and not runprobe.tsan_report(err), "threads load: " + err[-600:])


@case("T-168")
def t168():
    """auth.pub given as enc.key is refused with PROTO_E_KEY_PUBLIC."""
    P = lib.proto()
    ident = make_identity()
    text = ls.b64(ident.auth_pk).encode()
    variants = {
        "auth.pub itself": ident.auth_pub,
        "a copy under another name": write_file(os.path.join(ident.dir, "copy.key"), key_line(ident.auth_pk)),
        "with CRLF": write_file(os.path.join(ident.dir, "crlf.key"), text + b"\r\n"),
        "without a newline": write_file(os.path.join(ident.dir, "nonl.key"), text),
    }
    for what, path in variants.items():
        rc, out = load_filled(P, ident.auth_key, path)
        eq(rc, PUBLIC, "proto_load_keys with %s as enc.key" % what)
        check(out.is_zero(), "out is not all zero with %s as enc.key" % what)


@case("T-169", timeout=300)
def t169():
    """No good key pair is refused as PROTO_E_KEY_PUBLIC."""
    P = lib.proto()
    d = harness.tmpdir("many")
    auth, enc = os.path.join(d, "auth.key"), os.path.join(d, "enc.key")
    for i in range(2000):
        auth_pk, auth_sk = ls.sign_keypair()
        enc_pk, enc_sk = ls.box_keypair()
        write_file(auth, key_line(auth_sk))
        write_file(enc, key_line(enc_sk))
        rc, keys = P.load_keys(auth, enc)
        if rc != OK:
            check(False, "identity %d was refused: %d" % (i, rc))
        sealed = P.seal_new(b"probe %d" % i, bytes(keys.enc_pk))
        plain, n = P.unseal_new(sealed, bytes(keys.enc_pk), bytes(keys.enc_sk))
        if plain != b"probe %d" % i:
            check(False, "identity %d does not seal and open" % i)


@case("T-170")
def t170():
    """Another identity's auth.pub given as enc.key still loads."""
    P = lib.proto()
    mine, other = make_identity(), make_identity()
    rc, out = load_filled(P, mine.auth_key, other.auth_pub)
    eq(rc, OK, "proto_load_keys with another identity's auth.pub as enc.key")


# ----------------------------------------------------- XI. proto_load_pubkey_hex

@case("T-171")
def t171():
    """auth.pub loads as 64 lowercase hex characters."""
    P = lib.proto()
    ident = make_identity()
    rc, buf = P.load_pubkey_hex(ident.auth_pub)
    eq(rc, OK, "proto_load_pubkey_hex")
    eq(buf[:64], ident.auth_pk.hex().encode(), "the hex")
    eq(buf[64], 0, "the terminator")
    check(buf[:64] == buf[:64].lower(), "not lowercase")


@case("T-172")
def t172():
    """A buffer too small is PROTO_E_BUFFER_TOO_SMALL, without an abort."""
    P = lib.proto()
    ident = make_identity()
    eq(P.load_pubkey_hex(ident.auth_pub, 65)[0], OK, "hex_sz 65")
    eq(P.load_pubkey_hex(ident.auth_pub, 64)[0], -102, "hex_sz 64")
    eq(P.c_load_pubkey_hex(ident.auth_pub.encode(), None, 0), -102, "hex_sz 0")


@case("T-173", PIN)
def t173():
    """The size is checked before the path."""
    P = lib.proto()
    buf = ctypes.create_string_buffer(65)
    eq(P.c_load_pubkey_hex(None, buf, 10), -102, "NULL path, hex_sz 10")
    eq(P.c_load_pubkey_hex(None, buf, 65), PARAM, "NULL path, hex_sz 65")


@case("T-174", FINDING)
def t174():
    """A NULL hex_out is refused."""
    P = lib.proto()
    ident = make_identity()
    eq(P.c_load_pubkey_hex(ident.auth_pub.encode(), None, 65), PARAM, "hex_out NULL, hex_sz 65")


@case("T-175")
def t175():
    """auth.key given as auth.pub is PROTO_E_KEY_SIZE."""
    P = lib.proto()
    ident = make_identity()
    eq(P.load_pubkey_hex(ident.auth_key)[0], SIZE, "auth.key as auth.pub")


@case("T-176")
def t176():
    """enc.key given as auth.pub loads."""
    P = lib.proto()
    ident = make_identity()
    eq(P.load_pubkey_hex(ident.enc_key)[0], OK, "enc.key as auth.pub")


@case("T-177")
def t177():
    """proto_serve accepts the output as an allowlist."""
    P = lib.proto()
    ident = make_identity()
    rc, buf = P.load_pubkey_hex(ident.auth_pub)
    eq(rc, OK, "proto_load_pubkey_hex")
    P.serve_stop()                                         # set up, then return at once
    rc = P.serve(net.free_port(), buf[:64].decode())
    eq(rc, OK, "proto_serve with the loaded identity (not PROTO_E_BAD_ALLOWLIST)")


@case("T-178")
def t178():
    """A larger buffer gets exactly 65 bytes."""
    P = lib.proto()
    ident = make_identity()
    rc, buf = P.load_pubkey_hex(ident.auth_pub, 100, fill=ord("Z"))
    eq(rc, OK, "hex_sz 100")
    eq(buf[:64], ident.auth_pk.hex().encode(), "the hex")
    eq(buf[64], 0, "the terminator")
    eq(buf[65:], b"Z" * 35, "the bytes after the terminator")
