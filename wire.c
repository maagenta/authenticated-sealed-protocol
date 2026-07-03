#include "wire.h"
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

int proto_send_line(int fd, const char *line) {
    size_t len = strlen(line);
    if (write(fd, line, len) != (ssize_t)len) return -1;
    if (write(fd, "\n", 1) != 1) return -1;
    return 0;
}

int proto_recv_line(int fd, char *buf, size_t bufsz) {
    size_t i = 0;
    while (i < bufsz - 1) {
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
