/* seam_auth.c -- auth.c with its libc calls replaced, to craft addresses and fail allocations.
 *
 * auth.c is compiled with
 *     -Dgetaddrinfo=seam_getaddrinfo -Dfreeaddrinfo=seam_freeaddrinfo -Dsocket=seam_socket
 *     -Dconnect=seam_connect -Dgetsockopt=seam_getsockopt -Dclose=seam_close
 *     -Dstrdup=seam_strdup -Dmalloc=seam_malloc -Dfree=seam_free
 * and wire.c with -Dsend=seam_send, so that every one of these calls lands here.
 *
 *   seam_auth server_alloc    T-252  a failed strdup or malloc is answered with FAIL internal error
 *   seam_auth bad_port        T-261  a port out of range is refused before any resolution
 *   seam_auth walk            T-268  the address walk of proto_connect
 *   seam_auth eintr           T-269  a connect() interrupted before it connects
 *   seam_auth etimedout       T-270  the kernel giving up on a connection first
 *   seam_auth close_noop      T-286  proto_close with fd == -1 makes no system call
 *
 * An address does what its ai_protocol says (the library hands it to socket()):
 * K_REFUSE is refused at once, K_SILENT never answers, K_GOOD connects to a server
 * thread, K_LACKS is a family this host does not have, K_EINTR is a connect()
 * interrupted before it connects, K_ETIMEDOUT is a connection the kernel gave up on.
 */
#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "auth.h"
#include "crypto.h"
#include "probe.h"
#include "wire.h"

enum { K_REFUSE = 1, K_SILENT, K_GOOD, K_LACKS, K_EINTR, K_ETIMEDOUT };

/* ------------------------------------------------------------------ seams */

static int fd_kind[1024];
static struct addrinfo *crafted;
static unsigned long gai_calls, close_calls, send_calls;
static unsigned long malloc_calls, free_calls;
static unsigned long fail_strdup, fail_malloc;       /* fail the Nth call; 0: never */
static unsigned long strdup_calls, malloc_seen;

static proto_keys_t g_keys;
static char g_allowed[65];
static int silent_w[16], nsilent;
static int held[16], nheld;
static pthread_t threads[16];
static int nthreads;

int seam_getaddrinfo(const char *host, const char *serv, const struct addrinfo *hints, struct addrinfo **res) {
    (void)host; (void)serv; (void)hints;
    gai_calls++;
    if (!crafted) return EAI_NONAME;
    *res = crafted;
    return 0;
}

void seam_freeaddrinfo(struct addrinfo *ai) { (void)ai; }

static void *server_thread(void *arg) {
    int fd = (int)(long)arg;
    char *who = proto_auth_server(fd, g_allowed);
    if (who) proto_send_line(fd, "OK");
    free(who);
    close(fd);
    return NULL;
}

int seam_socket(int domain, int type, int proto) {
    (void)domain; (void)type;
    int fd = -1;
    switch (proto) {
    case K_LACKS:
        errno = EAFNOSUPPORT;
        return -1;
    case K_SILENT: {
        int p[2];
        if (pipe(p) != 0) FAILF("pipe");
        fd = p[0];
        silent_w[nsilent++] = p[1];                  /* never written, never closed: silence */
        break;
    }
    case K_GOOD:
    case K_EINTR: {
        int sv[2];
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) FAILF("socketpair");
        fd = sv[0];
        if (pthread_create(&threads[nthreads++], NULL, server_thread, (void *)(long)sv[1]) != 0) FAILF("pthread_create");
        break;
    }
    case K_ETIMEDOUT: {
        int sv[2];
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) FAILF("socketpair");
        fd = sv[0];
        held[nheld++] = sv[1];
        break;
    }
    default:
        fd = socket(AF_UNIX, SOCK_STREAM, 0);
    }
    if (fd >= 0 && fd < 1024) fd_kind[fd] = proto;
    return fd;
}

int seam_connect(int fd, const struct sockaddr *a, socklen_t l) {
    (void)a; (void)l;
    switch (fd_kind[fd]) {
    case K_REFUSE: errno = ECONNREFUSED; return -1;
    case K_SILENT:
    case K_ETIMEDOUT: errno = EINPROGRESS; return -1;
    case K_EINTR: errno = EINTR; return -1;
    default: return 0;                              /* K_GOOD */
    }
}

int seam_getsockopt(int fd, int level, int name, void *val, socklen_t *len) {
    if (level == SOL_SOCKET && name == SO_ERROR && fd >= 0 && fd < 1024 && fd_kind[fd] == K_ETIMEDOUT) {
        *(int *)val = ETIMEDOUT;
        return 0;
    }
    return getsockopt(fd, level, name, val, len);
}

int seam_close(int fd) {
    close_calls++;
    if (fd >= 0 && fd < 1024) fd_kind[fd] = 0;
    return close(fd);
}

ssize_t seam_send(int fd, const void *buf, size_t n, int flags) {
    send_calls++;
    return send(fd, buf, n, flags);
}

char *seam_strdup(const char *s) {
    strdup_calls++;
    if (fail_strdup && strdup_calls == fail_strdup) return NULL;
    malloc_calls++;
    return strdup(s);
}

void *seam_malloc(size_t n) {
    malloc_seen++;
    if (fail_malloc && malloc_seen == fail_malloc) return NULL;
    malloc_calls++;
    return malloc(n);
}

void seam_free(void *p) {
    if (p) free_calls++;
    free(p);
}

/* ---------------------------------------------------------------- helpers */

static int count_fds(void) {
    int n = 0;
    for (int fd = 0; fd < 256; fd++)
        if (fcntl(fd, F_GETFD) >= 0) n++;
    return n;
}

static void cleanup(void) {
    for (int i = 0; i < nthreads; i++) pthread_join(threads[i], NULL);
    nthreads = 0;
    for (int i = 0; i < nsilent; i++) close(silent_w[i]);
    for (int i = 0; i < nheld; i++) close(held[i]);
    nsilent = nheld = 0;
}

static void make_keys(void) {
    crypto_sign_keypair(g_keys.auth_pk, g_keys.auth_sk);
    crypto_box_keypair(g_keys.enc_pk, g_keys.enc_sk);
    sodium_bin2hex(g_allowed, sizeof g_allowed, g_keys.auth_pk, 32);
}

static double now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1000.0 + (double)ts.tv_nsec / 1e6;
}

/* ------------------------------------------------------------- server_alloc */

static void *auth_server_thread(void *arg) {
    int fd = *(int *)arg;
    char *who = proto_auth_server(fd, g_allowed);
    free(who);
    return (void *)(who != NULL);
}

static void talk(int fd, char *reply, size_t reply_sz) {
    char line[256];
    CHECK_EQ(proto_send_line(fd, "HELLO"), PROTO_OK);
    CHECK(proto_recv_line(fd, line, sizeof line) > 10);
    unsigned char ch[CHALLENGE_LEN], sig[AUTH_SIG_LEN];
    size_t n = 0;
    CHECK_EQ(sodium_base642bin(ch, sizeof ch, line + 10, strlen(line + 10), NULL, &n, NULL,
                               sodium_base64_VARIANT_ORIGINAL), 0);
    CHECK_EQ(proto_sign_challenge(ch, n, g_keys.auth_sk, sig), PROTO_OK);
    char pk64[64], sig64[128], cmd[300];
    sodium_bin2base64(pk64, sizeof pk64, g_keys.auth_pk, 32, sodium_base64_VARIANT_ORIGINAL);
    sodium_bin2base64(sig64, sizeof sig64, sig, 64, sodium_base64_VARIANT_ORIGINAL);
    snprintf(cmd, sizeof cmd, "AUTH %s %s", pk64, sig64);
    CHECK_EQ(proto_send_line(fd, cmd), PROTO_OK);
    int rc = proto_recv_line(fd, reply, reply_sz);
    CHECK(rc >= 0);
}

static void server_alloc(void) {
    for (int mode = 0; mode < 2; mode++) {
        int sv[2];
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) FAILF("socketpair");
        malloc_calls = free_calls = strdup_calls = malloc_seen = 0;
        fail_strdup = mode == 0 ? 1 : 0;
        fail_malloc = mode == 1 ? 1 : 0;
        pthread_t t;
        if (pthread_create(&t, NULL, auth_server_thread, &sv[1]) != 0) FAILF("pthread_create");
        char reply[64];
        talk(sv[0], reply, sizeof reply);
        void *accepted;
        pthread_join(t, &accepted);
        fail_strdup = fail_malloc = 0;
        CHECK(!strcmp(reply, "FAIL internal error"));
        CHECK(accepted == NULL);
        CHECK_EQ(malloc_calls, free_calls);               /* nothing leaked */
        close(sv[0]);
        close(sv[1]);
    }
}

/* ---------------------------------------------------------------- bad_port */

static struct addrinfo *craft(const int *kinds, int n) {
    static struct sockaddr_in dummy;
    dummy.sin_family = AF_INET;
    struct addrinfo *head = NULL, **tail = &head;
    for (int i = 0; i < n; i++) {
        struct addrinfo *ai = calloc(1, sizeof *ai);
        ai->ai_family = AF_INET;
        ai->ai_socktype = SOCK_STREAM;
        ai->ai_protocol = kinds[i];
        ai->ai_addr = (struct sockaddr *)&dummy;
        ai->ai_addrlen = sizeof dummy;
        *tail = ai;
        tail = &ai->ai_next;
    }
    return head;
}

static void free_crafted(void) {
    while (crafted) {
        struct addrinfo *next = crafted->ai_next;
        free(crafted);
        crafted = next;
    }
}

static void bad_port(void) {
    static const int ports[] = { 0, -1, 65536, 70000, -2147483647 - 1, 2147483647 };
    proto_conn_t c;
    memset(&c, 0, sizeof c);
    c.fd = -1;
    c.keys = g_keys;
    gai_calls = 0;
    for (size_t i = 0; i < sizeof ports / sizeof ports[0]; i++)
        CHECK_EQ(proto_connect(&c, "localhost", ports[i]), PROTO_E_BAD_PORT);
    CHECK_EQ(gai_calls, 0);
    int kinds[] = { K_REFUSE };
    crafted = craft(kinds, 1);
    CHECK_EQ(proto_connect(&c, "localhost", 5000), PROTO_E_CONNECT);
    CHECK_EQ(gai_calls, 1);                              /* the seam does see a valid port */
    free_crafted();
}

/* ------------------------------------------------------------------- walk */

struct walk {
    const char *name;
    int group;                                           /* 0 walk, 1 eintr, 2 etimedout */
    int kinds[3];
    int n;
    int want;
    int silent;                                          /* how many deadlines it must cost */
};

static void walk(int group) {
    static const struct walk table[] = {
        { "refusing, good", 0, { K_REFUSE, K_GOOD }, 2, PROTO_OK, 0 },
        { "silent, good", 0, { K_SILENT, K_GOOD }, 2, PROTO_OK, 1 },
        { "silent, refusing", 0, { K_SILENT, K_REFUSE }, 2, PROTO_E_CONNECT, 1 },
        { "silent, silent", 0, { K_SILENT, K_SILENT }, 2, PROTO_E_CONNECT_TIMEOUT, 2 },
        { "a family this host lacks, refusing", 0, { K_LACKS, K_REFUSE }, 2, PROTO_E_CONNECT, 0 },
        { "a family this host lacks", 0, { K_LACKS }, 1, PROTO_E_SOCKET, 0 },
        { "connect() interrupted", 1, { K_EINTR }, 1, PROTO_OK, 0 },
        { "the kernel gave up first", 2, { K_ETIMEDOUT }, 1, PROTO_E_CONNECT_TIMEOUT, 0 },
    };
    for (size_t i = 0; i < sizeof table / sizeof table[0]; i++) {
        const struct walk *w = &table[i];
        if (w->group != group) continue;
        proto_conn_t c;
        memset(&c, 0, sizeof c);
        c.fd = -1;
        c.keys = g_keys;
        crafted = craft(w->kinds, w->n);
        int before = count_fds();
        double t0 = now_ms();
        int rc = proto_connect(&c, "example.test", 5000);
        double took = now_ms() - t0;
        if (rc != w->want) FAILF("%s: got %d (%s), want %d", w->name, rc, proto_strerror(rc), w->want);
        if (rc == PROTO_OK) {
            CHECK(c.fd >= 0);
            proto_close(&c);
        } else {
            CHECK_EQ(c.fd, -1);
        }
        cleanup();
        free_crafted();
        CHECK_EQ(c.fd, -1);
        if (count_fds() != before) FAILF("%s: descriptors leaked (%d before, %d after)", w->name, before, count_fds());
        double lo = w->silent * CONNECT_TIMEOUT_MS - 40.0, hi = w->silent * CONNECT_TIMEOUT_MS + 2500.0;
        if (took < lo || took > hi) FAILF("%s took %.0f ms, outside [%.0f, %.0f]", w->name, took, lo, hi);
        /* a silent address must cost its deadline: an unanswered one is not a quick refusal */
        if (w->silent == 0 && took > 1500.0) FAILF("%s took %.0f ms", w->name, took);
    }
}

/* ------------------------------------------------------------- close_noop */

static void close_noop(void) {
    proto_conn_t c;
    memset(&c, 0, sizeof c);
    c.fd = -1;
    close_calls = send_calls = 0;
    proto_close(&c);
    proto_close(&c);
    CHECK_EQ(close_calls, 0);
    CHECK_EQ(send_calls, 0);
    CHECK_EQ(c.fd, -1);
}

int main(int argc, char **argv) {
    if (argc < 2) FAILF("usage: seam_auth SCENARIO");
    signal(SIGPIPE, SIG_IGN);
    CHECK_EQ(proto_init(), PROTO_OK);
    make_keys();
    const char *sc = argv[1];
    if (!strcmp(sc, "server_alloc")) server_alloc();
    else if (!strcmp(sc, "bad_port")) bad_port();
    else if (!strcmp(sc, "walk")) walk(0);
    else if (!strcmp(sc, "eintr")) walk(1);
    else if (!strcmp(sc, "etimedout")) walk(2);
    else if (!strcmp(sc, "close_noop")) close_noop();
    else FAILF("unknown scenario %s", sc);
    puts("ok");
    return 0;
}
