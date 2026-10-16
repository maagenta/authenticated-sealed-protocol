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

/* Read up to n bytes of the current line into buf, never past its newline.
 *
 * Reading a byte at a time never takes bytes of the next line by mistake,
 * but costs one system call per byte. Reading a block would be fast but
 * would pull the next line out of the socket, and an API on a bare fd has
 * nowhere to keep it. MSG_PEEK gives both: look at what the socket holds
 * without consuming it, find the newline, then read exactly up to it. The
 * bytes seen are still there for the real read — a stream socket hands
 * them out in order and nobody else reads this fd — so the two calls agree.
 *
 * Returns the bytes stored (the newline is consumed but not stored) and sets
 * *done when the newline was consumed; 0 at end of stream; -1 on error.
 * EINTR is retried: nothing was consumed, so it is not a failure.
 *
 * A descriptor that is not a socket has no MSG_PEEK — a pipe, which is what
 * a protocol tunnelled through another program's stdin and stdout runs on,
 * and what a test harness tends to use. There the only way to never take a
 * byte of the next line is to take one byte at a time. *peekable carries
 * that verdict between the calls that read one line, so the peek is tried
 * once per line rather than once per byte; the caller starts it at 1. */
static ssize_t read_line_part(int fd, char *buf, size_t n, int *done,
                              int *peekable) {
    *done = 0;
    if (n > READ_CHUNK) n = READ_CHUNK;

    ssize_t seen = -1;
    if (*peekable) {
        do seen = recv(fd, buf, n, MSG_PEEK);
        while (seen < 0 && errno == EINTR);
        if (seen < 0 && errno == ENOTSOCK) *peekable = 0;
    }
    if (!*peekable) {
        do seen = read(fd, buf, 1);
        while (seen < 0 && errno == EINTR);
        if (seen == 1 && buf[0] == '\n') { *done = 1; return 0; }
        return seen;
    }
    if (seen <= 0) return seen;

    const char *nl = memchr(buf, '\n', (size_t)seen);
    size_t take = nl ? (size_t)(nl - buf) + 1 : (size_t)seen;
    /* Consume exactly what was seen: it is already there, so this cannot
     * block, and only a signal can cut it short. */
    for (size_t got = 0; got < take; ) {
        ssize_t r = read(fd, buf + got, take - got);
        if (r < 0 && errno == EINTR) continue;
        if (r <= 0) return -1;
        got += (size_t)r;
    }
    if (nl) { *done = 1; return (ssize_t)(take - 1); }
    return (ssize_t)take;
}

/* Drop every '\r' in buf[0..n); returns the new length. */
static size_t strip_cr(char *buf, size_t n) {
    size_t w = 0;
    for (size_t r = 0; r < n; r++)
        if (buf[r] != '\r') buf[w++] = buf[r];
    return w;
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
 * The deadline bounds the whole line, checked before every read, so a peer
 * trickling bytes cannot hold the caller past it. */
static int recv_line_until(int fd, char *buf, size_t bufsz, long long deadline) {
    if (bufsz == 0) return PROTO_E_PARAM;   /* no room even for the terminator */
    size_t i = 0;
    int peekable = 1;                       /* until a recv says otherwise */
    for (;;) {
        /* buf is NUL-terminated on every exit, so a caller that logs it
         * after a failure reads a short string, not stale stack. */
        if (i + 1 >= bufsz) {
            /* The buffer holds all it can. One more character decides which
             * of two things happened, and the caller's buffer has no room
             * to hold it, so it is read into a byte on the stack: a newline
             * means the line ends exactly at the limit and fits; anything
             * else means it is longer. Without this the line would have to
             * be one character shorter than the documented limit to pass,
             * which is not what "longer than bufsz - 1" promises. */
            if (deadline) {
                int r = wait_readable(fd, deadline);
                if (r == 0) { buf[i] = '\0'; return PROTO_E_TIMEOUT; }
                if (r <  0) { buf[i] = '\0'; return PROTO_E_READ; }
            }
            char c;
            int ended;
            ssize_t n = read_line_part(fd, &c, 1, &ended, &peekable);
            if (n <  0)           { buf[i] = '\0'; return PROTO_E_READ; }
            if (n == 0 && !ended) { buf[i] = '\0'; return PROTO_E_PEER_CLOSED; }
            if (ended)            { buf[i] = '\0'; return (int)i; }
            if (c == '\r') continue;     /* not a character of the line */
            /* Too long. The rest of it is still in the socket, bar this one
             * character, and would surface as a bogus next line — which is
             * why this is an error rather than a short read. */
            buf[i] = '\0';
            return PROTO_E_LINE_TOO_LONG;
        }
        if (deadline) {
            int r = wait_readable(fd, deadline);
            if (r == 0) { buf[i] = '\0'; return PROTO_E_TIMEOUT; }
            if (r <  0) { buf[i] = '\0'; return PROTO_E_READ; }
        }
        int done;
        ssize_t n = read_line_part(fd, buf + i, bufsz - 1 - i, &done, &peekable);
        if (n <  0)          { buf[i] = '\0'; return PROTO_E_READ; }
        if (n == 0 && !done) { buf[i] = '\0'; return PROTO_E_PEER_CLOSED; }
        i += strip_cr(buf + i, (size_t)n);
        if (done) { buf[i] = '\0'; return (int)i; }
    }
}

int proto_recv_line(int fd, char *buf, size_t bufsz) {
    return recv_line_until(fd, buf, bufsz, 0);
}

int proto_recv_line_timeout(int fd, char *buf, size_t bufsz, int ms) {
    return recv_line_until(fd, buf, bufsz, ms < 0 ? 0 : now_ms() + ms);
}

/* Room for a line at the cap, one character past it, and the terminator.
 * The extra character is what makes the limit exact rather than a matter of
 * how the peer's bytes happened to arrive: a line is too long only once a
 * character past MAX_PAYLOAD has actually been stored. */
#define MAX_PAYLOAD_BUF ((size_t)MAX_PAYLOAD + 2)

char *proto_recv_line_dyn(int fd) {
    return proto_recv_line_dyn_status(fd, NULL);
}

char *proto_recv_line_dyn_status(int fd, int *status) {
    int ignored = PROTO_OK;
    if (!status) status = &ignored;

    size_t sz = MAX_PAYLOAD_BUF < 4096 ? MAX_PAYLOAD_BUF : 4096;
    size_t i = 0;
    int peekable = 1;                       /* until a recv says otherwise */
    char *buf = malloc(sz);
    if (!buf) { *status = PROTO_E_NOMEM; return NULL; }
    for (;;) {
        if (i + 1 >= sz) {           /* full: grow, but never past the cap */
            if (sz >= MAX_PAYLOAD_BUF) {
                free(buf); *status = PROTO_E_LINE_TOO_LONG; return NULL;
            }
            size_t want = sz <= MAX_PAYLOAD_BUF / 2 ? sz * 2 : MAX_PAYLOAD_BUF;
            char *nb = realloc(buf, want);
            if (!nb) { free(buf); *status = PROTO_E_NOMEM; return NULL; }
            buf = nb;
            sz = want;
        }
        int done;
        ssize_t n = read_line_part(fd, buf + i, sz - 1 - i, &done, &peekable);
        if (n <  0)          { free(buf); *status = PROTO_E_READ;        return NULL; }
        if (n == 0 && !done) { free(buf); *status = PROTO_E_PEER_CLOSED; return NULL; }
        i += strip_cr(buf + i, (size_t)n);
        /* A character past the cap is stored before this is noticed — that
         * is what the spare byte above is for. The rest of the line stays
         * in the socket; the caller answers and closes. */
        if (i > (size_t)MAX_PAYLOAD) {
            free(buf); *status = PROTO_E_LINE_TOO_LONG; return NULL;
        }
        if (done) break;
    }
    buf[i] = '\0';
    *status = PROTO_OK;
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
    /* Timing is best-effort: a rejected knob leaves the connection probing at
     * the system default rather than not probing at all. A system that has
     * no idle knob at all (or hides it under a strict -D_POSIX_C_SOURCE)
     * counts as a rejected knob. */
    int rc = PROTO_OK;
#if defined(TCP_KEEPIDLE)
    if (idle_s > 0 && setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE,
                                 &idle_s, sizeof idle_s) != 0) rc = PROTO_KEEPALIVE_DEFAULTED;
#elif defined(TCP_KEEPALIVE)
    if (idle_s > 0 && setsockopt(fd, IPPROTO_TCP, TCP_KEEPALIVE,
                                 &idle_s, sizeof idle_s) != 0) rc = PROTO_KEEPALIVE_DEFAULTED;
#else
    if (idle_s > 0) rc = PROTO_KEEPALIVE_DEFAULTED;
#endif
    /* OpenBSD has no TCP_KEEPINTVL or TCP_KEEPCNT: the knobs are left at the
     * system default there, which is the same best-effort outcome as a
     * rejected setsockopt(). */
#ifdef TCP_KEEPINTVL
    if (intvl_s > 0 && setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL,
                                  &intvl_s, sizeof intvl_s) != 0) rc = PROTO_KEEPALIVE_DEFAULTED;
#else
    if (intvl_s > 0) rc = PROTO_KEEPALIVE_DEFAULTED;
#endif
#ifdef TCP_KEEPCNT
    if (count > 0 && setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT,
                                &count, sizeof count) != 0) rc = PROTO_KEEPALIVE_DEFAULTED;
#else
    if (count > 0) rc = PROTO_KEEPALIVE_DEFAULTED;
#endif
    return rc;
}
