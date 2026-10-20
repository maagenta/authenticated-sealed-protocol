/* seam_wire.c -- wire.c with its libc calls replaced, to count and to fail them.
 *
 * wire.c is compiled with
 *     -Dsend=seam_send -Drecv=count_recv -Dread=count_read
 *     -Dmalloc=seam_malloc -Drealloc=seam_realloc -Dfree=seam_free
 * so every such call it makes lands here, where it is counted, shortened or
 * failed on request and then passed on to the real one.
 *
 *   seam_wire short_write     T-042
 *   seam_wire pipe_peek       T-072
 *   seam_wire big_line        T-073
 *   seam_wire dyn_alloc       T-104
 *   seam_wire dyn_bound       T-105
 *   seam_wire malloc_fail     T-106
 *   seam_wire realloc_fail    T-107
 */
#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "probe.h"
#include "wire.h"

/* ------------------------------------------------------------------ seams */

static int send_mode;                 /* 1: at most 7 bytes a call, 1 on every third */
static unsigned long send_calls;
static unsigned long recv_calls, read_calls;
static unsigned long malloc_calls, realloc_calls, free_calls;
static size_t max_alloc, first_alloc;
static size_t alloc_sizes[64];
static int fail_malloc, fail_realloc;
static void *last_malloc, *freed[16];
static int nfreed;

ssize_t seam_send(int fd, const void *buf, size_t n, int flags) {
    send_calls++;
    if (send_mode) {
        size_t cap = (send_calls % 3 == 0) ? 1 : 7;
        if (n > cap) n = cap;
    }
    return send(fd, buf, n, flags);
}

ssize_t count_recv(int fd, void *buf, size_t n, int flags) {
    recv_calls++;
    return recv(fd, buf, n, flags);
}

ssize_t count_read(int fd, void *buf, size_t n) {
    read_calls++;
    return read(fd, buf, n);
}

static void note_alloc(size_t n) {
    if (n > max_alloc) max_alloc = n;
    if (malloc_calls + realloc_calls <= 64) alloc_sizes[malloc_calls + realloc_calls - 1] = n;
}

void *seam_malloc(size_t n) {
    malloc_calls++;
    note_alloc(n);
    if (fail_malloc) { fail_malloc = 0; return NULL; }
    last_malloc = malloc(n);
    return last_malloc;
}

void *seam_realloc(void *p, size_t n) {
    realloc_calls++;
    note_alloc(n);
    if (fail_realloc) { fail_realloc = 0; return NULL; }
    return realloc(p, n);
}

void seam_free(void *p) {
    free_calls++;
    if (nfreed < 16) freed[nfreed++] = p;
    free(p);
}

static void reset(void) {
    send_mode = 0;
    send_calls = recv_calls = read_calls = 0;
    malloc_calls = realloc_calls = free_calls = 0;
    max_alloc = first_alloc = 0;
    memset(alloc_sizes, 0, sizeof alloc_sizes);
    fail_malloc = fail_realloc = 0;
    last_malloc = NULL;
    nfreed = 0;
}

/* ---------------------------------------------------------------- helpers */

struct sender {
    int fd;
    const char *data;
    size_t len;
    int close_after;
    pthread_t tid;
};

static void *send_thread(void *arg) {
    struct sender *s = arg;
    size_t off = 0;
    while (off < s->len) {
        ssize_t w = write(s->fd, s->data + off, s->len - off);
        if (w <= 0) break;
        off += (size_t)w;
    }
    if (s->close_after) close(s->fd);
    return NULL;
}

static void start_sender(struct sender *s, int fd, const char *data, size_t len, int close_after) {
    s->fd = fd; s->data = data; s->len = len; s->close_after = close_after;
    if (pthread_create(&s->tid, NULL, send_thread, s) != 0) FAILF("pthread_create");
}

static char *make_line(size_t n, char fill, int newline) {
    char *p = malloc(n + 2);
    if (!p) FAILF("out of memory");
    for (size_t i = 0; i < n; i++) p[i] = (char)(fill + (i % 23));
    if (newline) p[n++] = '\n';
    p[n] = '\0';
    return p;
}

static void make_pair(int sv[2]) {
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) FAILF("socketpair");
}

static void make_tcp(int sv[2]) {
    int ls = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a = { 0 };
    socklen_t al = sizeof a;
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (ls < 0 || bind(ls, (struct sockaddr *)&a, sizeof a) != 0 || listen(ls, 1) != 0 ||
        getsockname(ls, (struct sockaddr *)&a, &al) != 0) FAILF("tcp listener");
    sv[0] = socket(AF_INET, SOCK_STREAM, 0);
    if (connect(sv[0], (struct sockaddr *)&a, sizeof a) != 0) FAILF("tcp connect");
    sv[1] = accept(ls, NULL, NULL);
    if (sv[1] < 0) FAILF("tcp accept");
    close(ls);
}

/* -------------------------------------------------------------- scenarios */

struct drain {
    int fd;
    char *buf;
    size_t cap, have;
    pthread_t tid;
};

static void *drain_thread(void *arg) {
    struct drain *d = arg;
    while (d->have < d->cap) {
        ssize_t n = read(d->fd, d->buf + d->have, d->cap - d->have);
        if (n <= 0) break;
        d->have += (size_t)n;
    }
    return NULL;
}

/* T-042: short writes are resumed. A line under 4 KiB goes out in one write and a longer one in three
 * (write_line in wire.c), so each function sends one of each size. */
static void short_write(void) {
    static const size_t lens[] = { 3000, 6000 };          /* the line; its body is 500 bytes shorter */
    int sv[2];
    make_pair(sv);
    char *lines[2], *bodies[2];
    size_t want = 0;
    for (int i = 0; i < 2; i++) {
        lines[i] = make_line(lens[i], 'a', 0);
        bodies[i] = make_line(lens[i] - 500, 'A', 0);
        want += lens[i] + 1 + 4 + (lens[i] - 500) + 1;
    }
    /* Read while the writing goes on: a send of a few bytes costs a whole buffer of the socket's budget
     * on Linux (each one is accounted at its size plus the kernel's overhead), so a thousand of them
     * fill a socketpair that nobody reads and the writer waits for ever. */
    struct drain d = { sv[1], malloc(want + 8), want + 8, 0, 0 };
    if (!d.buf || pthread_create(&d.tid, NULL, drain_thread, &d) != 0) FAILF("cannot start the reader");
    send_mode = 1;
    for (int i = 0; i < 2; i++) {
        unsigned long before = send_calls;
        CHECK_EQ(proto_send_line(sv[0], lines[i]), PROTO_OK);
        CHECK(send_calls - before > lens[i] / 7);
        before = send_calls;
        CHECK_EQ(proto_send_prefixed(sv[0], "PUT ", bodies[i], lens[i] - 500), PROTO_OK);
        CHECK(send_calls - before > (lens[i] - 500) / 7);
    }
    send_mode = 0;
    close(sv[0]);                                   /* the reader sees the end of the stream */
    pthread_join(d.tid, NULL);

    CHECK_EQ(d.have, want);
    const char *got = d.buf;
    for (int i = 0; i < 2; i++) {
        size_t n = lens[i], b = lens[i] - 500;
        CHECK(memcmp(got, lines[i], n) == 0 && got[n] == '\n');
        got += n + 1;
        CHECK(memcmp(got, "PUT ", 4) == 0 && memcmp(got + 4, bodies[i], b) == 0 && got[4 + b] == '\n');
        got += 4 + b + 1;
        free(lines[i]);
        free(bodies[i]);
    }
    free(d.buf);
    close(sv[1]);
}

/* T-072: on a pipe the peek is tried once per line. */
static void pipe_peek(void) {
    int p[2];
    if (pipe(p) != 0) FAILF("pipe");
    char *line = make_line(1000, 'a', 1);
    CHECK_EQ(write(p[1], line, 1001), 1001);
    char buf[2048];
    reset();
    CHECK_EQ(proto_recv_line(p[0], buf, sizeof buf), 1000);
    CHECK_EQ(recv_calls, 1);
    CHECK_EQ(read_calls, 1001);
}

/* T-073: a large line costs a few calls, not one per byte. */
static void big_line_on(int sv[2], const char *what) {
    size_t n = 1024 * 1024;
    char *line = make_line(n, 'a', 1);
    char *buf = malloc(n + 16);
    struct sender s;
    reset();
    start_sender(&s, sv[0], line, n + 1, 0);
    int rc = proto_recv_line(sv[1], buf, n + 16);
    pthread_join(s.tid, NULL);
    CHECK_EQ(rc, (int)n);
    CHECK(memcmp(buf, line, n) == 0);
    unsigned long calls = recv_calls + read_calls;
    fprintf(stderr, "%s: %lu calls\n", what, calls);
    /* One recv and one read per piece the socket holds. NetBSD hands a waiting
     * reader a socketpair's bytes one 2 KiB mbuf cluster at a time: ~1026 calls.
     * One byte at a time would be over a million. */
    if (calls >= 4096) FAILF("%s: %lu system calls for a 1 MiB line", what, calls);
    free(line); free(buf);
}

static void big_line(void) {
    int sv[2];
    make_pair(sv);
    big_line_on(sv, "socketpair");
    make_tcp(sv);
    big_line_on(sv, "tcp");
}

/* T-104: the buffer starts at 4096 bytes and doubles. */
static void dyn_alloc(void) {
    int sv[2];
    make_pair(sv);
    char *small = make_line(3 * 1024, 'a', 1);
    reset();
    CHECK_EQ(write(sv[0], small, 3 * 1024 + 1), 3 * 1024 + 1);
    char *got = proto_recv_line_dyn(sv[1]);
    CHECK(got != NULL);
    CHECK_EQ(malloc_calls, 1);
    CHECK_EQ(realloc_calls, 0);
    CHECK_EQ(alloc_sizes[0], 4096);
    free(got);
    free(small);

    size_t n = 1024 * 1024;
    char *big = make_line(n, 'a', 1);
    struct sender s;
    reset();
    start_sender(&s, sv[0], big, n + 1, 0);
    got = proto_recv_line_dyn(sv[1]);
    pthread_join(s.tid, NULL);
    CHECK(got != NULL && strlen(got) == n);
    CHECK_EQ(malloc_calls, 1);
    CHECK(realloc_calls <= 9);
    CHECK_EQ(alloc_sizes[0], 4096);
    for (unsigned long i = 1; i <= realloc_calls; i++)
        CHECK_EQ(alloc_sizes[i], alloc_sizes[i - 1] * 2);
    free(got);
    free(big);
}

/* T-105: memory is bounded by the cap. */
static void dyn_bound(void) {
    int sv[2];
    make_pair(sv);
    size_t total = (size_t)MAX_PAYLOAD + 100;
    char *data = malloc(total);
    memset(data, 'a', total);
    struct sender s;
    reset();
    start_sender(&s, sv[0], data, total, 0);
    int status = 999;
    char *got = proto_recv_line_dyn_status(sv[1], &status);
    CHECK(got == NULL);
    CHECK_EQ(status, PROTO_E_LINE_TOO_LONG);
    CHECK(max_alloc <= (size_t)MAX_PAYLOAD + 2);
    pthread_join(s.tid, NULL);
    /* Only MAX_PAYLOAD + 1 characters were taken: 99 are left. */
    size_t left = 0;
    char buf[256];
    for (;;) {
        ssize_t r = recv(sv[1], buf, sizeof buf, MSG_DONTWAIT);
        if (r <= 0) break;
        left += (size_t)r;
    }
    CHECK_EQ(left, 99);
    free(data);
}

/* T-106: a failed first malloc is PROTO_E_NOMEM, and nothing was read. */
static void malloc_fail(void) {
    int sv[2];
    make_pair(sv);
    CHECK_EQ(write(sv[0], "hello\n", 6), 6);
    reset();
    fail_malloc = 1;
    int status = 999;
    char *got = proto_recv_line_dyn_status(sv[1], &status);
    CHECK(got == NULL);
    CHECK_EQ(status, PROTO_E_NOMEM);
    char buf[16];
    CHECK_EQ(recv(sv[1], buf, sizeof buf, MSG_DONTWAIT), 6);
    CHECK(memcmp(buf, "hello\n", 6) == 0);
}

/* T-107: a failed realloc is PROTO_E_NOMEM, and the buffer is freed. */
static void realloc_fail(void) {
    int sv[2];
    make_pair(sv);
    char *line = make_line(10000, 'a', 1);
    struct sender s;
    reset();
    fail_realloc = 1;
    start_sender(&s, sv[0], line, 10001, 0);
    int status = 999;
    char *got = proto_recv_line_dyn_status(sv[1], &status);
    CHECK(got == NULL);
    CHECK_EQ(status, PROTO_E_NOMEM);
    CHECK_EQ(realloc_calls, 1);
    CHECK_EQ(free_calls, 1);
    CHECK(freed[0] == last_malloc);
    close(sv[1]);                       /* the sender may still be writing */
    pthread_join(s.tid, NULL);
    free(line);
}

int main(int argc, char **argv) {
    if (argc < 2) FAILF("usage: seam_wire SCENARIO");
    signal(SIGPIPE, SIG_IGN);           /* a sender may outlive its reader */
    reset();
    const char *sc = argv[1];
    if (!strcmp(sc, "short_write")) short_write();
    else if (!strcmp(sc, "pipe_peek")) pipe_peek();
    else if (!strcmp(sc, "big_line")) big_line();
    else if (!strcmp(sc, "dyn_alloc")) dyn_alloc();
    else if (!strcmp(sc, "dyn_bound")) dyn_bound();
    else if (!strcmp(sc, "malloc_fail")) malloc_fail();
    else if (!strcmp(sc, "realloc_fail")) realloc_fail();
    else FAILF("unknown scenario %s", sc);
    puts("ok");
    return 0;
}
