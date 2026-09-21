#include "wire.h"
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <poll.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

/* Writing to a socket whose peer has gone raises SIGPIPE, which kills the
 * process by default — before the write can return, so the PROTO_E_WRITE
 * path never runs. MSG_NOSIGNAL asks for EPIPE instead, per call, without
 * imposing a process-wide signal disposition on the application. Linux,
 * macOS and the BSDs have it; on a platform without it the write goes out
 * unprotected and the application must handle SIGPIPE itself. */
#ifdef MSG_NOSIGNAL
#define SEND_FLAGS MSG_NOSIGNAL
#else
#define SEND_FLAGS 0
#endif

/* send() may transfer fewer bytes than asked without failing, and a signal
 * may interrupt it after a partial transfer. Treating either as an error
 * would report failure with part of the line already on the wire, leaving
 * the stream desynchronized. Resume instead, and only give up when the
 * connection really fails. EAGAIN counts as a failure: the library is
 * documented as blocking, so a non-blocking fd is outside its contract.
 * send() rather than write() so the flag applies; the fd is documented as
 * a connected socket, which is all send() accepts. */
static int write_all(int fd, const void *buf, size_t n) {
    const char *p = buf;
    while (n > 0) {
        ssize_t w = send(fd, p, n, SEND_FLAGS);
        if (w < 0) {
            if (errno == EINTR) continue;   /* interrupted, nothing lost */
            return PROTO_E_WRITE;
        }
        if (w == 0) return PROTO_E_WRITE;   /* no progress; give up */
        p += w;
        n -= (size_t)w;
    }
    return PROTO_OK;
}

int proto_send_line(int fd, const char *line) {
    int rc = write_all(fd, line, strlen(line));
    if (rc != PROTO_OK) return rc;
    return write_all(fd, "\n", 1);
}

/* Read one byte, retrying when a signal interrupts the call — nothing was
 * consumed in that case, so it is not a connection failure. The cost is that
 * a signal handler alone cannot break a caller out of a blocked read; a
 * shutdown() on the fd from the handler can, and surfaces as a real error.
 * Returns 1 on a byte read, 0 at end of stream, -1 on a real error. */
static ssize_t read_byte(int fd, char *c) {
    for (;;) {
        ssize_t n = read(fd, c, 1);
        if (n < 0 && errno == EINTR) continue;
        return n;
    }
}

/* Milliseconds on a clock that never jumps, for deadlines. */
static long long now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/* Block until fd has data or the deadline passes. Returns 1 = readable,
 * 0 = deadline reached, -1 = error. A signal restarts the wait with the
 * time that remains, so the deadline holds regardless of interruptions. */
static int wait_readable(int fd, long long deadline) {
    for (;;) {
        long long left = deadline - now_ms();
        if (left <= 0) return 0;
        struct pollfd p = { .fd = fd, .events = POLLIN };
        int rc = poll(&p, 1, (int)left);
        if (rc < 0 && errno == EINTR) continue;
        return rc < 0 ? -1 : (rc > 0);
    }
}

/* One line into buf, giving up at the deadline if there is one (0 = none).
 * The deadline bounds the whole line, checked before every byte, so a peer
 * trickling one byte at a time cannot hold the caller past it. */
static int recv_line_until(int fd, char *buf, size_t bufsz, long long deadline) {
    if (bufsz == 0) return PROTO_E_PARAM;   /* no room even for the terminator */
    size_t i = 0;
    int terminated = 0;
    while (i + 1 < bufsz) {      /* leave room for '\0'; never underflows */
        /* buf is NUL-terminated on every error path, so a caller that logs
         * it after a failure reads a short string, not stale stack. */
        if (deadline) {
            int r = wait_readable(fd, deadline);
            if (r == 0) { buf[i] = '\0'; return PROTO_E_TIMEOUT; }
            if (r <  0) { buf[i] = '\0'; return PROTO_E_READ; }
        }
        char c;
        ssize_t n = read_byte(fd, &c);
        if (n == 0) { buf[i] = '\0'; return PROTO_E_PEER_CLOSED; }
        if (n <  0) { buf[i] = '\0'; return PROTO_E_READ; }
        if (c == '\n') { terminated = 1; break; }
        if (c == '\r') continue;
        buf[i++] = c;
    }
    buf[i] = '\0';
    /* Ran out of room before the newline: the rest of the line is still in
     * the socket and would surface as a bogus next line. Say so instead of
     * returning a length that looks like a complete read. */
    if (!terminated) return PROTO_E_LINE_TOO_LONG;
    return (int)i;
}

int proto_recv_line(int fd, char *buf, size_t bufsz) {
    return recv_line_until(fd, buf, bufsz, 0);
}

int proto_recv_line_timeout(int fd, char *buf, size_t bufsz, int ms) {
    return recv_line_until(fd, buf, bufsz, ms < 0 ? 0 : now_ms() + ms);
}

char *proto_recv_line_dyn(int fd) {
    size_t sz = 4096, i = 0;
    char *buf = malloc(sz);
    if (!buf) return NULL;
    while (1) {
        char c;
        if (read_byte(fd, &c) <= 0) { free(buf); return NULL; }
        if (c == '\n') break;
        if (c == '\r') continue;
        if (i + 1 >= sz) {
            sz *= 2;
            char *nb = realloc(buf, sz);
            if (!nb) { free(buf); return NULL; }
            buf = nb;
        }
        buf[i++] = c;
    }
    buf[i] = '\0';
    return buf;
}

int proto_send_prefixed(int fd, const char *prefix,
                        const char *body, size_t body_len) {
    int rc;
    if ((rc = write_all(fd, prefix, strlen(prefix))) != PROTO_OK) return rc;
    if ((rc = write_all(fd, body, body_len))         != PROTO_OK) return rc;
    return write_all(fd, "\n", 1);
}

int proto_keepalive(int fd, int idle_s, int intvl_s, int count) {
    int on = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &on, sizeof on) != 0)
        return PROTO_E_KEEPALIVE;

    /* Systems spell the idle knob differently; the other two agree. Test for
     * the constant rather than the platform: Linux, FreeBSD and NetBSD have
     * TCP_KEEPIDLE, macOS has TCP_KEEPALIVE. */
#ifdef TCP_KEEPIDLE
    const int idle_opt = TCP_KEEPIDLE;
#else
    const int idle_opt = TCP_KEEPALIVE;
#endif

    /* Timing is best-effort: a rejected knob leaves the connection probing at
     * the system default rather than not probing at all. */
    int rc = PROTO_OK;
    if (idle_s > 0 && setsockopt(fd, IPPROTO_TCP, idle_opt,
                                 &idle_s, sizeof idle_s) != 0) rc = PROTO_KEEPALIVE_DEFAULTED;
    if (intvl_s > 0 && setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL,
                                  &intvl_s, sizeof intvl_s) != 0) rc = PROTO_KEEPALIVE_DEFAULTED;
    if (count > 0 && setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT,
                                &count, sizeof count) != 0) rc = PROTO_KEEPALIVE_DEFAULTED;
    return rc;
}
