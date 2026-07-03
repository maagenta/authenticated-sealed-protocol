#ifndef PROTO_WIRE_H
#define PROTO_WIRE_H

#include <stddef.h>

/*
 * Line-oriented framing over a connected socket.
 * Every message is one '\n'-terminated line; '\r' is ignored on read.
 * Binary payloads are carried base64-encoded inside a line.
 */

/* Write line + '\n'. Returns 0 on success, -1 on error. */
int proto_send_line(int fd, const char *line);

/* Read one line into a fixed buffer (NUL-terminated, newline stripped).
 * Returns the line length, or -1 on error/EOF. Use for short control lines. */
int proto_recv_line(int fd, char *buf, size_t bufsz);

/* Read one line of arbitrary length (heap-allocated, NUL-terminated).
 * Caller frees. Returns NULL on error/EOF. Use for variable/large payloads. */
char *proto_recv_line_dyn(int fd);

/* Write "<prefix><body>\n" without an intermediate buffer. body may be large.
 * Returns 0 on success, -1 on error. */
int proto_send_prefixed(int fd, const char *prefix,
                        const char *body, size_t body_len);

#endif /* PROTO_WIRE_H */
