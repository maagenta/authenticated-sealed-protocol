#include "status.h"

const char *proto_strerror(int code) {
    switch (code) {
    case PROTO_OK:                  return "success";
    case PROTO_REGISTER_REQUESTED:  return "server requested registration";
    case PROTO_KEEPALIVE_DEFAULTED: return "keepalive on, timing left at system defaults";

    case PROTO_E_PARAM:             return "invalid argument";
    case PROTO_E_BUFFER_TOO_SMALL:  return "buffer too small for the result";
    case PROTO_E_NO_ALLOWLIST:      return "no allowlist configured";
    case PROTO_E_BAD_ALLOWLIST:     return "allowlist is not 64 lowercase hex characters";
    case PROTO_E_NO_HANDLER:        return "no connection handler given";
    case PROTO_E_BAD_ADDRESS:       return "bind address is not an IPv4 literal";
    case PROTO_E_BAD_PORT:          return "port is not in 1..65535";

    case PROTO_E_NOMEM:             return "out of memory";
    case PROTO_E_SODIUM:            return "libsodium initialization failed";

    case PROTO_E_KEY_OPEN:          return "could not open key file";
    case PROTO_E_KEY_EMPTY:         return "key file's first line is blank";
    case PROTO_E_KEY_FORMAT:        return "key file is not base64";
    case PROTO_E_KEY_MISMATCH:      return "key file is damaged: its public key does not match its secret key";
    case PROTO_E_KEY_NOT_FOUND:     return "no key file at that path";
    case PROTO_E_KEY_DENIED:        return "no permission to read key file";
    case PROTO_E_KEY_NOT_FILE:      return "key path is not a regular file";
    case PROTO_E_KEY_READ:          return "could not read key file";
    case PROTO_E_KEY_STRAY:         return "key file has stray characters around the key (a space, a tab or an invisible mark)";
    case PROTO_E_KEY_SIZE:          return "key file holds a key of the wrong size: probably the wrong file";
    case PROTO_E_KEY_PUBLIC:        return "key file holds the identity's public key where a secret key belongs: auth.pub given as enc.key";

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
    case PROTO_E_ACCEPT:            return "accept failed; listening socket no longer usable";
    case PROTO_E_CONNECT_TIMEOUT:   return "connection attempt timed out";

    case PROTO_E_WRITE:             return "write failed";
    case PROTO_E_READ:              return "read failed";
    case PROTO_E_PEER_CLOSED:       return "peer closed the connection";
    case PROTO_E_LINE_TOO_LONG:     return "line longer than the limit";
    case PROTO_E_TIMEOUT:           return "read timed out";

    case PROTO_E_UNEXPECTED_REPLY:  return "unexpected reply from server";
    case PROTO_E_BAD_CHALLENGE:     return "malformed challenge from server";
    case PROTO_E_REJECTED:          return "server refused the handshake";
    case PROTO_E_REGISTER_REJECTED: return "server refused registration";

    default:                        return "unknown status code";
    }
}
