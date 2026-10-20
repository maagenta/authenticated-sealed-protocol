"""The protocol, spoken from Python: peers the library is tested against."""

import os

import libsodium as ls
from harness import Fail, check
from net import Peer


def parse_auth(line):
    """('AUTH', pk_b64, sig_b64) fields of an AUTH line, or None."""
    parts = line.split(b" ")
    if len(parts) != 3 or parts[0] != b"AUTH":
        return None
    return parts[1], parts[2]


def server_handshake(peer, expected_pk=None, reply=b"OK", challenge=None, require_ok=True):
    """Play the server side of HELLO / CHALLENGE / AUTH over a Peer.

    Sends reply (a line without its newline) when the signature is good and the
    key is the expected one, else FAIL access denied. Returns what was seen.
    """
    info = {"lines": [], "challenge": None, "pk": None, "sig": None, "ok": False}
    hello = peer.recv_line()
    if hello is None:
        return info                                 # the client hung up first: nobody to answer
    info["lines"].append(hello)
    if hello != b"HELLO":
        peer.send_line(b"FAIL expected HELLO")
        return info
    challenge = challenge if challenge is not None else os.urandom(32)
    info["challenge"] = challenge
    peer.send_line(b"CHALLENGE " + ls.b64(challenge).encode())
    auth = peer.recv_line()
    if auth is None:
        return info
    info["lines"].append(auth)
    fields = parse_auth(auth)
    if not fields:
        peer.send_line(b"FAIL invalid AUTH format")
        return info
    pk, sig = ls.b64d(fields[0]), ls.b64d(fields[1])
    info["pk"], info["sig"] = pk, sig
    if not ls.verify_detached(sig, challenge, pk):
        peer.send_line(b"FAIL signature verification failed")
        return info
    if expected_pk is not None and pk != expected_pk:
        peer.send_line(b"FAIL access denied")
        return info
    info["ok"] = True
    if reply is not None:
        peer.send_line(reply)
    return info


def accept_and_serve(lsock, expected_pk=None, reply=b"OK", wait_for_eof=True, timeout=10.0):
    """Accept one connection, run the server handshake, then wait for the client to go."""
    lsock.settimeout(timeout)
    conn, _ = lsock.accept()
    conn.settimeout(None)
    peer = Peer(conn)
    try:
        info = server_handshake(peer, expected_pk, reply)
        info["peer"] = peer
        if wait_for_eof:
            while True:
                line = peer.recv_line(timeout)
                if line is None:
                    break
                info["lines"].append(line)
                if line == b"QUIT":
                    peer.send_line(b"BYE")
        return info
    finally:
        peer.close()
        lsock.close()


def client_handshake(peer, ident, hello=b"HELLO", expect_challenge=True):
    """Play the client side: send HELLO, answer the challenge. Returns the server's verdict line."""
    peer.send_line(hello)
    line = peer.recv_line()
    check(line is not None and line.startswith(b"CHALLENGE "), "no challenge: %r" % (line,))
    challenge = ls.b64d(line[len(b"CHALLENGE "):])
    sig = ls.sign_detached(challenge, ident.auth_sk)
    peer.send_line(b"AUTH " + ls.b64(ident.auth_pk).encode() + b" " + ls.b64(sig).encode())
    return peer.recv_line()
