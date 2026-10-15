"""Key-file fixtures: identities written the way keygen writes them."""

import os

import harness
import libsodium as ls


class Identity(object):
    def __init__(self, directory, auth_pk, auth_sk, enc_pk, enc_sk):
        self.dir = directory
        self.auth_pk, self.auth_sk = auth_pk, auth_sk
        self.enc_pk, self.enc_sk = enc_pk, enc_sk
        self.auth_key = os.path.join(directory, "auth.key")
        self.auth_pub = os.path.join(directory, "auth.pub")
        self.enc_key = os.path.join(directory, "enc.key")

    @property
    def hex(self):
        return self.auth_pk.hex()


def write_file(path, data, mode=0o600):
    if isinstance(data, str):
        data = data.encode("latin-1")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    try:
        os.write(fd, data)
    finally:
        os.close(fd)
    os.chmod(path, mode)
    return path


def key_line(raw):
    """One key as keygen writes it: standard base64 and a newline."""
    return (ls.b64(raw) + "\n").encode("ascii")


def make_identity(directory=None, write=True):
    directory = directory or harness.tmpdir("id")
    auth_pk, auth_sk = ls.sign_keypair()
    enc_pk, enc_sk = ls.box_keypair()
    ident = Identity(directory, auth_pk, auth_sk, enc_pk, enc_sk)
    if write:
        write_file(ident.auth_key, key_line(auth_sk))
        write_file(ident.auth_pub, key_line(auth_pk))
        write_file(ident.enc_key, key_line(enc_sk))
    return ident


def three_loads(P, render):
    """Pass one file mutation through the three ways a key file is loaded.

    render(raw_key) returns the bytes of the file for a key. It is applied to a
    32-byte public key (proto_load_pubkey_hex), to a 64-byte auth.key and to a
    32-byte enc.key (both through proto_load_keys, the other file being good).
    Returns (rc_pub, rc_auth, rc_enc).
    """
    d = harness.tmpdir("loads")
    ident = make_identity(os.path.join(d), write=True)
    bad_pub = write_file(os.path.join(d, "bad.pub"), render(ident.auth_pk))
    bad_auth = write_file(os.path.join(d, "bad.auth"), render(ident.auth_sk))
    bad_enc = write_file(os.path.join(d, "bad.enc"), render(ident.enc_sk))
    rc_pub, _ = P.load_pubkey_hex(bad_pub)
    rc_auth, _ = P.load_keys(bad_auth, ident.enc_key)
    rc_enc, _ = P.load_keys(ident.auth_key, bad_enc)
    return rc_pub, rc_auth, rc_enc
