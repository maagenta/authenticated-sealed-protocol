"""XXVI. Found by the fuzz targets (T-424, T-425)."""

import lib
import libsodium as ls
from harness import FINDING, case, check, eq, skip
from keyfiles import three_loads

FORMAT = -303
ALPHABET = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"


def twins():
    """{byte above 0x7F: the characters of the alphabet libsodium's decoder takes it for}.

    Where `char` is signed the decoder compares more than eight bits of a negative value and takes
    most of these bytes for a character; where it is unsigned (arm64 Linux) it takes none."""
    plain = {c: ls.base642bin(bytes([c]) + b"AAA") for c in ALPHABET}
    res = {}
    for v in range(0x80, 0x100):
        got = ls.base642bin(bytes([v]) + b"AAA")
        res[v] = [c for c in ALPHABET if got is not None and got == plain[c]]
    return res


def a_byte_the_decoder_accepts():
    """The byte the decoder takes for a character, and the characters it stands for; else skip."""
    for v, chars in twins().items():
        if chars:
            return v, chars
    skip("the decoder of this libsodium takes no byte above 0x7F for a character (char is unsigned here)")


@case("T-424", FINDING)
def t424():
    """A byte above 0x7F inside a key is PROTO_E_KEY_FORMAT."""
    byte, _ = a_byte_the_decoder_accepts()

    def with_high_byte(raw):
        text = ls.b64(raw).encode()
        mid = len(text) // 2
        return text[:mid] + bytes([byte]) + text[mid + 1:] + b"\n"
    got = three_loads(lib.proto(), with_high_byte)
    eq(got, (FORMAT, FORMAT, FORMAT),
       "a byte 0x%02X in the middle of the key (public key, auth.key, enc.key)" % byte)


@case("T-425", FINDING)
def t425():
    """A byte above 0x7F in place of a character of a sealed box opens nothing."""
    _, _ = a_byte_the_decoder_accepts()
    stand_for = {c for chars in twins().values() for c in chars}
    P = lib.proto()
    # A box where one of the first 24 characters is one that such a byte can stand for: about one in four.
    for _ in range(500):
        pk, sk = ls.box_keypair()
        sealed = P.seal_new(b"a message to alter", pk)
        if any(c in stand_for for c in sealed[:24]):
            break
    else:
        raise RuntimeError("no sealed box among 500 has a character that a byte above 0x7F can stand for")
    eq(P.unseal_full(sealed, pk, sk)[0], b"a message to alter", "the unaltered box")
    opened = []
    for i in range(24):
        for v in range(0x80, 0x100):
            altered = sealed[:i] + bytes([v]) + sealed[i + 1:]
            if P.unseal_full(altered, pk, sk)[0] is not None:
                opened.append((i, hex(v)))
    check(not opened, "%d altered boxes opened, e.g. byte %s at character %d" % (
        len(opened), opened[0][1] if opened else "", opened[0][0] if opened else 0))
