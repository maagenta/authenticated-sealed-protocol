#ifndef PROTO_WIRE_H
#define PROTO_WIRE_H

#include <stddef.h>
#include "status.h"

/*
 * Line-oriented framing over a connected socket.
 * Every message is one '\n'-terminated line; '\r' is ignored on read.
 * Binary payloads are carried base64-encoded inside a line.
 */

/* Write line + '\n'. Short writes are resumed and EINTR is retried, so this
 * either sends the whole line or fails. A peer that has gone yields
 * PROTO_E_WRITE, not SIGPIPE. Returns PROTO_OK or PROTO_E_WRITE. */
int proto_send_line(int fd, const char *line);

/* Read one line into a fixed buffer (NUL-terminated, newline stripped).
 * Blocks until a line arrives; a signal does not interrupt it — see docs.md
 * on cancelling a blocked call. Returns the line length, or PROTO_E_PARAM,
 * PROTO_E_PEER_CLOSED, PROTO_E_READ, or PROTO_E_LINE_TOO_LONG when the line
 * did not fit. buf is NUL-terminated even on the error paths. */
int proto_recv_line(int fd, char *buf, size_t bufsz);

/* Like proto_recv_line, but gives up with PROTO_E_TIMEOUT if the whole line
 * has not arrived within ms milliseconds. The deadline covers the line, not
 * each byte, so a peer trickling one byte at a time cannot stretch it.
 * ms < 0 means no deadline. */
int proto_recv_line_timeout(int fd, char *buf, size_t bufsz, int ms);

/* Read one line of arbitrary length (heap-allocated, NUL-terminated).
 * Caller frees. Blocks until a line arrives; a signal does not interrupt it.
 * Returns NULL on error/EOF. Use for variable/large payloads. */
char *proto_recv_line_dyn(int fd);

/* Write "<prefix><body>\n" without an intermediate buffer. body may be large;
 * short writes are resumed, so this either sends everything or fails. A peer
 * that has gone yields PROTO_E_WRITE, not SIGPIPE.
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
