/* seam_serve.c -- serve.c with the calls it makes to the kernel replaced.
 *
 * serve.c is compiled with
 *     -Dsocket=seam_socket -Dsocketpair=seam_socketpair -Dlisten=seam_listen
 *     -Daccept=seam_accept -Dfork=seam_fork -Dpoll=seam_poll
 * so that each can be made to fail on request, shortened or slowed down. The
 * probe runs proto_serve in its main thread and plays the clients, and the
 * stop, from other threads.
 *
 *   socketpair_fail   T-301  the stop channel cannot be made
 *   socket_fail       T-302  the listener cannot be made
 *   listen_fail       T-303  listen() fails
 *   accept_broken     T-304  accept() fails with EBADF, then with EINVAL
 *   accept_emfile     T-305  accept() runs out of descriptors or memory
 *   accept_retry      T-306  accept() fails with EINTR and ECONNABORTED
 *   fork_fail         T-307  fork() fails: the client is told the server is busy
 *   poll_fail         T-309  poll() fails
 *   accept_reset      T-321  a client resets between poll() and accept()
 *   reaper_errno      T-353  the reaper keeps errno
 *   busy_stop         T-347  a stop asked while the loop is on the busy path
 *   dispositions      T-351  what a setup failure after the signals changed leaves behind
 */
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "auth.h"
#include "crypto.h"
#include "probe.h"
#include "serve.h"
#include "wire.h"

/* ------------------------------------------------------------------ seams */

static volatile int fail_socketpair, fail_socket, fail_listen, fail_fork;
static volatile int accept_errno;
static volatile long accept_fail_left;               /* -1: every call */
static volatile int accept_sleep_ms, accept_raise_chld;
static volatile long poll_fail_left;
static volatile unsigned long accept_calls, poll_calls, chld_raised;

static void sleep_ms(int ms) {
    nanosleep(&(struct timespec){ ms / 1000, (long)(ms % 1000) * 1000000L }, NULL);
}

static double now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1000.0 + (double)ts.tv_nsec / 1e6;
}

int seam_socketpair(int d, int t, int p, int sv[2]) {
    if (fail_socketpair) { errno = EMFILE; return -1; }
    return socketpair(d, t, p, sv);
}

int seam_socket(int d, int t, int p) {
    if (fail_socket) { errno = EMFILE; return -1; }
    return socket(d, t, p);
}

int seam_listen(int fd, int backlog) {
    if (fail_listen) { errno = EOPNOTSUPP; return -1; }
    return listen(fd, backlog);
}

int seam_accept(int fd, struct sockaddr *a, socklen_t *l) {
    accept_calls++;
    if (accept_sleep_ms) { int ms = accept_sleep_ms; accept_sleep_ms = 0; sleep_ms(ms); }
    if (accept_fail_left != 0) {
        if (accept_fail_left > 0) accept_fail_left--;
        errno = accept_errno;
        if (accept_raise_chld) { chld_raised++; raise(SIGCHLD); }
        return -1;
    }
    return accept(fd, a, l);
}

pid_t seam_fork(void) {
    if (fail_fork) { errno = EAGAIN; return -1; }
    return fork();
}

int seam_poll(struct pollfd *f, nfds_t n, int timeout) {
    poll_calls++;
    if (poll_fail_left > 0) { poll_fail_left--; errno = ENOMEM; return -1; }
    return poll(f, n, timeout);
}

/* ---------------------------------------------------------------- helpers */

static proto_keys_t g_keys;
static char g_allowed[65];

static void handler(int fd, const char *id, void *ctx) {
    (void)id; (void)ctx;
    proto_send_line(fd, "OK");
}

static int free_port(void) {
    int s = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a;
    socklen_t al = sizeof a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(s, (struct sockaddr *)&a, sizeof a) != 0 || getsockname(s, (struct sockaddr *)&a, &al) != 0)
        FAILF("free port");
    close(s);
    return ntohs(a.sin_port);
}

static int bindable(int port) {
    int s = socket(AF_INET, SOCK_STREAM, 0);
    int one = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_ANY);
    a.sin_port = htons((uint16_t)port);
    int ok = bind(s, (struct sockaddr *)&a, sizeof a) == 0;
    close(s);
    return ok;
}

static int tcp_connect(int port) {
    int s = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = htons((uint16_t)port);
    if (connect(s, (struct sockaddr *)&a, sizeof a) != 0) { close(s); return -1; }
    return s;
}

/* A full handshake as a client; returns proto_auth_client's code. */
static int handshake(int port, double *ms) {
    double t0 = now_ms();
    int s = tcp_connect(port);
    if (s < 0) return PROTO_E_CONNECT;
    int rc = proto_auth_client(s, &g_keys);
    close(s);
    if (ms) *ms = now_ms() - t0;
    return rc;
}

/* A client that connects, says nothing, and reads what it is sent. */
static int silent_read(int port, char *line, size_t n, int ms, double *took) {
    double t0 = now_ms();
    int s = tcp_connect(port);
    if (s < 0) return PROTO_E_CONNECT;
    int rc = proto_recv_line_timeout(s, line, n, ms);
    close(s);
    if (took) *took = now_ms() - t0;
    return rc;
}

static int serve_on(int port, const char *bind_addr) {
    proto_serve_opts_t o = { .bind_addr = bind_addr, .drain_ms = 0 };
    return proto_serve(port, g_allowed, handler, NULL, &o);
}

struct delayed { int ms; };

static void *stop_later(void *arg) {
    sleep_ms(((struct delayed *)arg)->ms);
    proto_serve_stop();
    return NULL;
}

static pthread_t start_stop_in(struct delayed *d, int ms) {
    pthread_t t;
    d->ms = ms;
    if (pthread_create(&t, NULL, stop_later, d) != 0) FAILF("pthread_create");
    return t;
}

struct holder { int port; int delay; int fd; };

static void *hold_connection(void *arg) {                    /* connect and stay connected */
    struct holder *h = arg;
    sleep_ms(h->delay);
    h->fd = tcp_connect(h->port);
    return NULL;
}

static pthread_t start_holder(struct holder *h, int port, int delay) {
    pthread_t t;
    h->port = port; h->delay = delay; h->fd = -1;
    if (pthread_create(&t, NULL, hold_connection, h) != 0) FAILF("pthread_create");
    return t;
}

/* -------------------------------------------------------------- scenarios */

static void reset_seams(void) {
    fail_socketpair = fail_socket = fail_listen = fail_fork = 0;
    accept_errno = 0; accept_fail_left = 0; accept_sleep_ms = 0; accept_raise_chld = 0;
    poll_fail_left = 0;
    accept_calls = poll_calls = chld_raised = 0;
}

static void socketpair_fail(void) {
    int port = free_port();
    fail_socketpair = 1;
    CHECK_EQ(serve_on(port, "127.0.0.1"), PROTO_E_SOCKET);
    fail_socketpair = 0;
    CHECK(bindable(port));
}

static void socket_fail(void) {
    int port = free_port();
    fail_socket = 1;
    CHECK_EQ(serve_on(port, "127.0.0.1"), PROTO_E_SOCKET);
    fail_socket = 0;
    CHECK(bindable(port));
}

static void listen_fail(void) {
    int port = free_port();
    fail_listen = 1;
    CHECK_EQ(serve_on(port, "127.0.0.1"), PROTO_E_LISTEN);
    fail_listen = 0;
    CHECK(bindable(port));
}

static void accept_broken(void) {
    static const int errs[] = { EBADF, EINVAL };
    for (size_t i = 0; i < sizeof errs / sizeof errs[0]; i++) {
        reset_seams();
        int port = free_port();
        accept_errno = errs[i];
        accept_fail_left = -1;
        struct holder h;
        pthread_t t = start_holder(&h, port, 150);
        CHECK_EQ(serve_on(port, "127.0.0.1"), PROTO_E_ACCEPT);
        pthread_join(t, NULL);
        if (h.fd >= 0) close(h.fd);
    }
}

static void accept_emfile(void) {
    static const int errs[] = { EMFILE, ENFILE, ENOBUFS, ENOMEM };
    for (size_t i = 0; i < sizeof errs / sizeof errs[0]; i++) {
        reset_seams();
        int port = free_port();
        accept_errno = errs[i];
        accept_fail_left = -1;
        struct holder h;
        struct delayed d;
        pthread_t th = start_holder(&h, port, 100);
        pthread_t ts = start_stop_in(&d, 1350);
        double t0 = now_ms();
        CHECK_EQ(serve_on(port, "127.0.0.1"), PROTO_OK);
        double took = now_ms() - t0;
        pthread_join(th, NULL);
        pthread_join(ts, NULL);
        if (h.fd >= 0) close(h.fd);
        unsigned long calls = accept_calls;
        fprintf(stderr, "errno %d: %lu accept calls in %.0f ms\n", errs[i], calls, took);
        CHECK(calls >= 6 && calls <= 16);                  /* about every 100 ms, not a busy loop */
        CHECK(took < 1350 + 800);                          /* and a stop still ends it */
    }
}

struct once { int port; int rc; double ms; int stop; };

static void *handshake_once(void *arg) {
    struct once *o = arg;
    sleep_ms(80);
    o->rc = handshake(o->port, &o->ms);
    if (o->stop) proto_serve_stop();
    return NULL;
}

static void accept_retry(void) {
    static const int errs[] = { EINTR, ECONNABORTED };
    for (size_t i = 0; i < sizeof errs / sizeof errs[0]; i++) {
        reset_seams();
        int port = free_port();
        accept_errno = errs[i];
        accept_fail_left = 3;
        struct once o = { port, -999, 0, 1 };
        pthread_t t;
        if (pthread_create(&t, NULL, handshake_once, &o) != 0) FAILF("pthread_create");
        double t0 = now_ms();
        CHECK_EQ(serve_on(port, "127.0.0.1"), PROTO_OK);
        double took = now_ms() - t0;
        pthread_join(t, NULL);
        CHECK_EQ(o.rc, PROTO_OK);                          /* the next client was served */
        CHECK(took < 1500);                                /* the retries were at once */
        CHECK(accept_calls >= 4);
    }
}

struct busy { int port; int rcA; double msA; char lineB[64]; int rcB; double msB; int rcC; };

static void *busy_clients(void *arg) {
    struct busy *b = arg;
    sleep_ms(100);
    b->rcA = handshake(b->port, &b->msA);                  /* fork fails */
    b->rcB = silent_read(b->port, b->lineB, sizeof b->lineB, 1500, &b->msB);
    fail_fork = 0;
    b->rcC = handshake(b->port, NULL);                     /* the server goes on */
    for (int i = 0; i < 2 && b->rcC == PROTO_E_TIMEOUT; i++)   /* a loaded ASan build may be slow */
        b->rcC = handshake(b->port, NULL);
    proto_serve_stop();
    return NULL;
}

static void fork_fail(void) {
    reset_seams();
    int port = free_port();
    fail_fork = 1;
    struct busy b = { port, -999, 0, "", -999, 0, -999 };
    pthread_t t;
    if (pthread_create(&t, NULL, busy_clients, &b) != 0) FAILF("pthread_create");
    CHECK_EQ(serve_on(port, "127.0.0.1"), PROTO_OK);
    pthread_join(t, NULL);
    CHECK_EQ(b.rcA, PROTO_E_REJECTED);
    CHECK(b.msA < 300);
    CHECK(b.rcB > 0 && !strcmp(b.lineB, "FAIL server busy"));
    CHECK(b.msB < 600);                                     /* within about 100 ms of silence */
    CHECK_EQ(b.rcC, PROTO_OK);
}

struct polled { int port; unsigned long calls_early; int rc; };

static void *poll_clients(void *arg) {
    struct polled *p = arg;
    sleep_ms(450);
    p->calls_early = poll_calls;
    sleep_ms(500);
    p->rc = handshake(p->port, NULL);
    proto_serve_stop();
    return NULL;
}

static void poll_fail(void) {
    reset_seams();
    int port = free_port();
    poll_fail_left = 5;
    struct polled p = { port, 0, -999 };
    pthread_t t;
    if (pthread_create(&t, NULL, poll_clients, &p) != 0) FAILF("pthread_create");
    CHECK_EQ(serve_on(port, "127.0.0.1"), PROTO_OK);
    pthread_join(t, NULL);
    CHECK(p.calls_early <= 8);                             /* retried after a pause, not in a busy loop */
    CHECK_EQ(p.rc, PROTO_OK);                              /* and the server recovered */
}

static void *reset_client(void *arg) {
    struct holder *h = arg;
    sleep_ms(h->delay);
    int s = tcp_connect(h->port);
    if (s >= 0) {
        struct linger lg = { 1, 0 };
        setsockopt(s, SOL_SOCKET, SO_LINGER, &lg, sizeof lg);
        close(s);                                          /* a reset, not an orderly close */
    }
    return NULL;
}

static void accept_reset(void) {
    reset_seams();
    alarm(15);                                             /* a wedged accept() must not hang the probe */
    int port = free_port();
    accept_sleep_ms = 300;
    struct holder h;
    pthread_t tc, ts;
    struct delayed d;
    h.port = port; h.delay = 50;
    if (pthread_create(&tc, NULL, reset_client, &h) != 0) FAILF("pthread_create");
    ts = start_stop_in(&d, 150);                           /* during the sleep */
    double t0 = now_ms();
    CHECK_EQ(serve_on(port, "127.0.0.1"), PROTO_OK);
    double took = now_ms() - t0;
    pthread_join(tc, NULL);
    pthread_join(ts, NULL);
    alarm(0);
    fprintf(stderr, "returned %.0f ms after the start\n", took);
    CHECK(took < 3000);
}

static void reaper_errno(void) {
    reset_seams();
    int port = free_port();
    accept_errno = EMFILE;
    accept_fail_left = 12;
    accept_raise_chld = 1;
    struct holder h;
    struct delayed d;
    pthread_t th = start_holder(&h, port, 100);
    pthread_t ts = start_stop_in(&d, 1600);
    CHECK_EQ(serve_on(port, "127.0.0.1"), PROTO_OK);        /* not PROTO_E_ACCEPT over an ECHILD */
    pthread_join(th, NULL);
    pthread_join(ts, NULL);
    if (h.fd >= 0) close(h.fd);
    CHECK(chld_raised >= 5);
}

/* T-351: a setup failure after the dispositions changed leaves them changed. */
static void dispositions(void) {
    static const char *names[] = { "socket", "listen", "socketpair" };
    static const int want[] = { PROTO_E_SOCKET, PROTO_E_LISTEN, PROTO_E_SOCKET };
    for (int i = 0; i < 3; i++) {
        pid_t pid = fork();
        if (pid < 0) FAILF("fork");
        if (pid == 0) {
            reset_seams();
            signal(SIGPIPE, SIG_DFL);
            signal(SIGCHLD, SIG_DFL);
            if (i == 0) fail_socket = 1;
            if (i == 1) fail_listen = 1;
            if (i == 2) fail_socketpair = 1;
            int rc = serve_on(free_port(), "127.0.0.1");
            void (*p)(int) = signal(SIGPIPE, SIG_DFL);
            int pipe_ignored = p == SIG_IGN;
            p = signal(SIGCHLD, SIG_DFL);
            int chld_changed = p != SIG_DFL && p != SIG_IGN;
            _exit((rc == want[i] ? 0 : 4) | (pipe_ignored ? 1 : 0) | (chld_changed ? 2 : 0));
        }
        int status = 0;
        waitpid(pid, &status, 0);
        if (!WIFEXITED(status) || WEXITSTATUS(status) != 3)
            FAILF("after a failed %s the child exited with %d (3: SIGPIPE ignored and a SIGCHLD handler installed)",
                  names[i], WIFEXITED(status) ? WEXITSTATUS(status) : -1);
    }
}

static void *silent_connect(void *arg) {
    struct holder *h = arg;
    sleep_ms(h->delay);
    char line[64];
    silent_read(h->port, line, sizeof line, 1000, NULL);
    return NULL;
}

static void busy_stop(void) {
    reset_seams();
    int port = free_port();
    fail_fork = 1;
    struct holder h;
    pthread_t tc, ts;
    struct delayed d;
    h.port = port; h.delay = 50;
    if (pthread_create(&tc, NULL, silent_connect, &h) != 0) FAILF("pthread_create");
    ts = start_stop_in(&d, 90);                            /* inside the 100 ms read of the busy path */
    double t0 = now_ms();
    CHECK_EQ(serve_on(port, "127.0.0.1"), PROTO_OK);
    double took = now_ms() - t0;
    pthread_join(tc, NULL);
    pthread_join(ts, NULL);
    fprintf(stderr, "returned %.0f ms after the start (stop asked at 90)\n", took);
    CHECK(took < 90 + 500);
}

int main(int argc, char **argv) {
    if (argc < 2) FAILF("usage: seam_serve SCENARIO");
    signal(SIGPIPE, SIG_IGN);
    CHECK_EQ(proto_init(), PROTO_OK);
    crypto_sign_keypair(g_keys.auth_pk, g_keys.auth_sk);
    crypto_box_keypair(g_keys.enc_pk, g_keys.enc_sk);
    sodium_bin2hex(g_allowed, sizeof g_allowed, g_keys.auth_pk, 32);
    const char *sc = argv[1];
    if (!strcmp(sc, "socketpair_fail")) socketpair_fail();
    else if (!strcmp(sc, "socket_fail")) socket_fail();
    else if (!strcmp(sc, "listen_fail")) listen_fail();
    else if (!strcmp(sc, "accept_broken")) accept_broken();
    else if (!strcmp(sc, "accept_emfile")) accept_emfile();
    else if (!strcmp(sc, "accept_retry")) accept_retry();
    else if (!strcmp(sc, "fork_fail")) fork_fail();
    else if (!strcmp(sc, "poll_fail")) poll_fail();
    else if (!strcmp(sc, "accept_reset")) accept_reset();
    else if (!strcmp(sc, "reaper_errno")) reaper_errno();
    else if (!strcmp(sc, "busy_stop")) busy_stop();
    else if (!strcmp(sc, "dispositions")) dispositions();
    else FAILF("unknown scenario %s", sc);
    puts("ok");
    return 0;
}
