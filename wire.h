#ifndef PROTO_WIRE_H
#define PROTO_WIRE_H

#include <stddef.h>
#include "error.h"

/*
 * Line-oriented framing over a connected socket.
 * Every message is one '\n'-terminated line; '\r' is ignored on read.
 * Binary payloads are carried base64-encoded inside a line.
 */

/* Write line + '\n'. Returns PROTO_OK or PROTO_E_WRITE. */
int proto_send_line(int fd, const char *line);

/* Read one line into a fixed buffer (NUL-terminated, newline stripped).
 * Use for short control lines. Returns the line length, or PROTO_E_PARAM,
 * PROTO_E_PEER_CLOSED, PROTO_E_READ, or PROTO_E_LINE_TOO_LONG when the line
 * did not fit. buf is NUL-terminated even on the error paths. */
int proto_recv_line(int fd, char *buf, size_t bufsz);

/* Read one line of arbitrary length (heap-allocated, NUL-terminated).
 * Caller frees. Returns NULL on error/EOF. Use for variable/large payloads. */
char *proto_recv_line_dyn(int fd);

/* Write "<prefix><body>\n" without an intermediate buffer. body may be large.
 * Returns PROTO_OK or PROTO_E_WRITE. */
int proto_send_prefixed(int fd, const char *prefix,
                        const char *body, size_t body_len);

/* Keepalive: ask the kernel to probe an idle connection so a peer that
 * vanishes without closing eventually fails the socket instead of leaving a
 * read() blocked forever. Nothing in this library enables it; both ends opt
 * in by calling this. Any argument <= 0 leaves that knob at the system
 * default (about two hours before the first probe). Returns PROTO_OK;
 * PROTO_KEEPALIVE_DEFAULTED (positive, not a failure) if probing is on but a
 * knob was rejected; PROTO_E_KEEPALIVE if the socket refused probing. */
int proto_keepalive(int fd, int idle_s, int intvl_s, int count);

#endif /* PROTO_WIRE_H */
