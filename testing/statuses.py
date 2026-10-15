"""The 44 members of proto_status_t, with the text proto_strerror gives each.

T-407 keeps this table in step with status.h and docs.md; T-027 pins the
texts. A new code is added here, in status.h, in status.c and in docs.md.
"""

# (name, value, family, message)
STATUS = [
    ("PROTO_OK", 0, "success", "success"),
    ("PROTO_REGISTER_REQUESTED", 1, "success", "server requested registration"),
    ("PROTO_KEEPALIVE_DEFAULTED", 2, "success", "keepalive on, timing left at system defaults"),

    ("PROTO_E_PARAM", -101, "caller", "invalid argument"),
    ("PROTO_E_BUFFER_TOO_SMALL", -102, "caller", "buffer too small for the result"),
    ("PROTO_E_NO_ALLOWLIST", -103, "caller", "no allowlist configured"),
    ("PROTO_E_BAD_ALLOWLIST", -104, "caller", "allowlist is not 64 lowercase hex characters"),
    ("PROTO_E_NO_HANDLER", -105, "caller", "no connection handler given"),
    ("PROTO_E_BAD_ADDRESS", -106, "caller", "bind address is not an IPv4 literal"),
    ("PROTO_E_BAD_PORT", -107, "caller", "port is not in 1..65535"),

    ("PROTO_E_NOMEM", -201, "resources", "out of memory"),
    ("PROTO_E_SODIUM", -202, "resources", "libsodium initialization failed"),

    ("PROTO_E_KEY_OPEN", -301, "key files", "could not open key file"),
    ("PROTO_E_KEY_EMPTY", -302, "key files", "key file's first line is blank"),
    ("PROTO_E_KEY_FORMAT", -303, "key files", "key file is not base64"),
    ("PROTO_E_KEY_MISMATCH", -304, "key files",
     "key file is damaged: its public key does not match its secret key"),
    ("PROTO_E_KEY_NOT_FOUND", -305, "key files", "no key file at that path"),
    ("PROTO_E_KEY_DENIED", -306, "key files", "no permission to read key file"),
    ("PROTO_E_KEY_NOT_FILE", -307, "key files", "key path is not a regular file"),
    ("PROTO_E_KEY_READ", -308, "key files", "could not read key file"),
    ("PROTO_E_KEY_STRAY", -309, "key files",
     "key file has stray characters around the key (a space, a tab or an invisible mark)"),
    ("PROTO_E_KEY_SIZE", -310, "key files",
     "key file holds a key of the wrong size: probably the wrong file"),
    ("PROTO_E_KEY_PUBLIC", -311, "key files",
     "key file holds the identity's public key where a secret key belongs: auth.pub given as enc.key"),

    ("PROTO_E_CRYPTO", -401, "cryptography", "cryptographic operation failed"),
    ("PROTO_E_BAD_SIGNATURE", -402, "cryptography", "signature verification failed"),

    ("PROTO_E_SOCKET", -501, "sockets", "could not create socket"),
    ("PROTO_E_RESOLVE", -502, "sockets", "could not resolve host"),
    ("PROTO_E_CONNECT", -503, "sockets", "could not connect to host"),
    ("PROTO_E_BIND", -504, "sockets", "could not bind port"),
    ("PROTO_E_PORT_IN_USE", -505, "sockets", "port already in use"),
    ("PROTO_E_PERM_DENIED", -506, "sockets", "permission denied binding port"),
    ("PROTO_E_LISTEN", -507, "sockets", "could not listen on socket"),
    ("PROTO_E_KEEPALIVE", -508, "sockets", "keepalive not supported on this socket"),
    ("PROTO_E_ACCEPT", -509, "sockets", "accept failed; listening socket no longer usable"),
    ("PROTO_E_CONNECT_TIMEOUT", -510, "sockets", "connection attempt timed out"),

    ("PROTO_E_WRITE", -601, "lines", "write failed"),
    ("PROTO_E_READ", -602, "lines", "read failed"),
    ("PROTO_E_PEER_CLOSED", -603, "lines", "peer closed the connection"),
    ("PROTO_E_LINE_TOO_LONG", -604, "lines", "line longer than the limit"),
    ("PROTO_E_TIMEOUT", -605, "lines", "read timed out"),

    ("PROTO_E_UNEXPECTED_REPLY", -701, "handshake", "unexpected reply from server"),
    ("PROTO_E_BAD_CHALLENGE", -702, "handshake", "malformed challenge from server"),
    ("PROTO_E_REJECTED", -703, "handshake", "server refused the handshake"),
    ("PROTO_E_REGISTER_REJECTED", -704, "handshake", "server refused registration"),
]

VALUE = {name: value for name, value, _, _ in STATUS}
NAME = {value: name for name, value, _, _ in STATUS}
MESSAGE = {value: msg for _, value, _, msg in STATUS}

# Every code is also available as a module attribute: statuses.PROTO_E_READ.
globals().update(VALUE)


def name_of(value):
    return NAME.get(value, "unknown(%d)" % value)


def show(value):
    """'PROTO_E_READ (-602)', for failure messages."""
    return "%s (%d)" % (name_of(value), value)
