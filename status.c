#include "status.h"

const char *proto_strerror(int code) {
    switch (code) {
    case PROTO_OK:                  return "success";
    case PROTO_REGISTER_REQUESTED:  return "server requested registration";
    case PROTO_KEEPALIVE_DEFAULTED: return "keepalive on, timing left at system defaults";

    case PROTO_E_PARAM:             return "invalid argument";
    case PROTO_E_BUFFER_TOO_SMALL:  return "buffer too small for the result";
    case PROTO_E_NO_ALLOWLIST:      return "no allowlist configured";
    case PROTO_E_BAD_ALLOWLIST:     return "allowlist is not 64 hex characters";
    case PROTO_E_NO_HANDLER:        return "no connection handler given";

    case PROTO_E_NOMEM:             return "out of memory";
    case PROTO_E_SODIUM:            return "libsodium initialization failed";

    case PROTO_E_KEY_OPEN:          return "could not open key file";
    case PROTO_E_KEY_EMPTY:         return "key file is empty";
    case PROTO_E_KEY_FORMAT:        return "key file is not base64 of the expected size";

    case PROTO_E_CRYPTO:            return "cryptographic operation failed";
    case PROTO_E_BAD_SIGNATURE:     return "signature verification failed";

    case PROTO_E_SOCKET:            return "could not create socket";
    case PROTO_E_RESOLVE:           return "could not resolve host";
    case PROTO_E_CONNECT:           return "could not connect to host";
    case PROTO_E_BIND:              return "could not bind port";
    case PROTO_E_PORT_IN_USE:       return "port already in use";
    case PROTO_E_PERM_DENIED:       return "permission denied binding port";
    case PROTO_E_LISTEN:            return "could not listen on socket";
    case PROTO_E_KEEPALIVE:         return "keepalive not supported on this socket";

    case PROTO_E_WRITE:             return "write failed";
    case PROTO_E_READ:              return "read failed";
    case PROTO_E_PEER_CLOSED:       return "peer closed the connection";
    case PROTO_E_LINE_TOO_LONG:     return "line longer than the buffer";

    case PROTO_E_UNEXPECTED_REPLY:  return "unexpected reply from server";
    case PROTO_E_BAD_CHALLENGE:     return "malformed challenge from server";
    case PROTO_E_REJECTED:          return "server refused the handshake";
    case PROTO_E_REGISTER_REJECTED: return "server refused registration";

    default:                        return "unknown status code";
    }
}
