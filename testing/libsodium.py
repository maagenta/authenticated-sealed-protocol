"""libsodium through ctypes: the oracle the tests check the library against.

The tests never link PyNaCl; they call the same libsodium the library uses,
so a mismatch between the two is the library's.
"""

import base64
import ctypes
import os

import lib

SEALBYTES = 48
SIGN_PK, SIGN_SK, SIGN_SIG = 32, 64, 64
BOX_PK, BOX_SK = 32, 32

_dll = []


def S():
    if not _dll:
        d = ctypes.CDLL(lib.sodium_library_path())
        if d.sodium_init() < 0:
            raise RuntimeError("sodium_init failed")
        _dll.append(d)
    return _dll[0]


def sign_keypair():
    pk = ctypes.create_string_buffer(SIGN_PK)
    sk = ctypes.create_string_buffer(SIGN_SK)
    S().crypto_sign_keypair(pk, sk)
    return pk.raw, sk.raw


def sign_seed_keypair(seed):
    pk = ctypes.create_string_buffer(SIGN_PK)
    sk = ctypes.create_string_buffer(SIGN_SK)
    S().crypto_sign_seed_keypair(pk, sk, seed)
    return pk.raw, sk.raw


def sign_detached(msg, sk):
    sig = ctypes.create_string_buffer(SIGN_SIG)
    n = ctypes.c_ulonglong(0)
    S().crypto_sign_detached(sig, ctypes.byref(n), msg, ctypes.c_ulonglong(len(msg)), sk)
    return sig.raw


def verify_detached(sig, msg, pk):
    return S().crypto_sign_verify_detached(sig, msg, ctypes.c_ulonglong(len(msg)), pk) == 0


def box_keypair():
    pk = ctypes.create_string_buffer(BOX_PK)
    sk = ctypes.create_string_buffer(BOX_SK)
    S().crypto_box_keypair(pk, sk)
    return pk.raw, sk.raw


def scalarmult_base(sk):
    pk = ctypes.create_string_buffer(BOX_PK)
    S().crypto_scalarmult_base(pk, sk)
    return pk.raw


def box_seal(msg, pk):
    out = ctypes.create_string_buffer(len(msg) + SEALBYTES)
    rc = S().crypto_box_seal(out, msg, ctypes.c_ulonglong(len(msg)), pk)
    if rc != 0:
        raise RuntimeError("crypto_box_seal failed")
    return out.raw


def box_seal_open(cipher, pk, sk):
    if len(cipher) < SEALBYTES:
        return None
    out = ctypes.create_string_buffer(max(len(cipher) - SEALBYTES, 1))
    rc = S().crypto_box_seal_open(out, cipher, ctypes.c_ulonglong(len(cipher)), pk, sk)
    return None if rc != 0 else out.raw[:len(cipher) - SEALBYTES]


def b64(raw):
    return base64.b64encode(raw).decode("ascii")


def b64d(text):
    return base64.b64decode(text, validate=True)


def base642bin(text):
    """sodium_base642bin with the standard alphabet and nothing to skip: the bytes, or None when it refuses."""
    d = S()
    d.sodium_base642bin.restype = ctypes.c_int
    d.sodium_base642bin.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_char_p, ctypes.c_size_t,
                                    ctypes.c_char_p, ctypes.POINTER(ctypes.c_size_t), ctypes.c_void_p, ctypes.c_int]
    out = ctypes.create_string_buffer(len(text) + 3)
    n = ctypes.c_size_t(0)
    rc = d.sodium_base642bin(out, len(out), text, len(text), None, ctypes.byref(n), None, 1)
    return None if rc != 0 else out.raw[:n.value]


def hexlower(raw):
    return raw.hex()


# Order of the Ed25519 group, to build the non-canonical signature S + L.
L = 2 ** 252 + 27742317777372353535851937790883648493


def noncanonical(sig):
    s = int.from_bytes(sig[32:], "little") + L
    return sig[:32] + (s % 2 ** 256).to_bytes(32, "little")


def random_bytes(n):
    return os.urandom(n)
