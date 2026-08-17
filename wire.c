#include "wire.h"
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

int proto_send_line(int fd, const char *line) {
    size_t len = strlen(line);
    if (write(fd, line, len) != (ssize_t)len) return -1;
    if (write(fd, "\n", 1) != 1) return -1;
    return 0;
}

int proto_recv_line(int fd, char *buf, size_t bufsz) {
    if (bufsz == 0) return -1;   /* no room even for the terminator */
    size_t i = 0;
    while (i + 1 < bufsz) {      /* leave room for '\0'; never underflows */
        char c;
        if (read(fd, &c, 1) <= 0) return -1;
        if (c == '\n') break;
        if (c == '\r') continue;
        buf[i++] = c;
    }
    buf[i] = '\0';
    return (int)i;
}

char *proto_recv_line_dyn(int fd) {
    size_t sz = 4096, i = 0;
    char *buf = malloc(sz);
    if (!buf) return NULL;
    while (1) {
        char c;
        if (read(fd, &c, 1) <= 0) { free(buf); return NULL; }
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
    size_t plen = strlen(prefix);
    return (write(fd, prefix, plen) == (ssize_t)plen &&
            write(fd, body, body_len) == (ssize_t)body_len &&
            write(fd, "\n", 1) == 1) ? 0 : -1;
}

int proto_keepalive(int fd, int idle_s, int intvl_s, int count) {
    int on = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &on, sizeof on) != 0)
        return -1;

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
    int rc = 0;
    if (idle_s > 0 && setsockopt(fd, IPPROTO_TCP, idle_opt,
                                 &idle_s, sizeof idle_s) != 0) rc = -1;
    if (intvl_s > 0 && setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL,
                                  &intvl_s, sizeof intvl_s) != 0) rc = -1;
    if (count > 0 && setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT,
                                &count, sizeof count) != 0) rc = -1;
    return rc;
}
