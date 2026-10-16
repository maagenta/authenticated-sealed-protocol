/* suite.c -- the core scenarios of the suite in one C program.
 *
 * The Python harness cannot host a 32-bit build, a musl build, a fortified
 * build or a sanitizer's runtime, so those builds run this instead: the same
 * calls the Python tests make, on the same kinds of input.
 *
 *   suite [SCENARIO ...]     default: every scenario, in this order
 *
 *   wire         lines over a socketpair, a pipe and TCP; the buffer limits
 *   keys         key files: the good ones, and each way a file can be wrong
 *   seal         sealing and opening, and what must fail to open
 *   seal_bounds  lengths no message can have, with no message at all
 *   sign         signing and verifying
 *   handshake    proto_auth_client against proto_auth_server, in two threads
 *   serve        proto_serve in a child; proto_connect, a command, proto_close, a stop
 */
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "auth.h"
#include "crypto.h"
#include "probe.h"
#include "serve.h"
#include "wire.h"

#define SEAL_MSG_MAX ((SIZE_MAX - 5) / 4 * 3 - crypto_box_SEALBYTES)

static void write_all(int fd, const void *p, size_t n) {
    const char *s = p;
    while (n) {
        ssize_t w = write(fd, s, n);
        if (w <= 0) FAILF("write");
        s += w; n -= (size_t)w;
    }
}

static void put(int fd, const char *s) { write_all(fd, s, strlen(s)); }

static void pair(int sv[2]) {
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) FAILF("socketpair");
}

/* ------------------------------------------------------------------- wire */

static int tcp_pair(int sv[2]) {
    int ls = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a;
    socklen_t al = sizeof a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (ls < 0 || bind(ls, (struct sockaddr *)&a, sizeof a) != 0 || listen(ls, 1) != 0 ||
        getsockname(ls, (struct sockaddr *)&a, &al) != 0) FAILF("tcp listener");
    sv[0] = socket(AF_INET, SOCK_STREAM, 0);
    if (connect(sv[0], (struct sockaddr *)&a, sizeof a) != 0) FAILF("tcp connect");
    sv[1] = accept(ls, NULL, NULL);
    close(ls);
    return sv[1] >= 0 ? 0 : -1;
}

static void wire(void) {
    int sv[2];
    char buf[64], small[5];

    for (int code = -800; code <= 3; code++)                        /* every code has a message */
        CHECK(proto_strerror(code) != NULL && *proto_strerror(code) != '\0');

    pair(sv);
    put(sv[0], "hello\r\nabcd\n\nabcde\nrest\nlast");
    CHECK_EQ(proto_recv_line(sv[1], buf, sizeof buf), 5);
    CHECK(!strcmp(buf, "hello"));
    CHECK_EQ(proto_recv_line(sv[1], small, sizeof small), 4);        /* an exact fit */
    CHECK(!strcmp(small, "abcd"));
    CHECK_EQ(proto_recv_line(sv[1], buf, sizeof buf), 0);            /* an empty line */
    CHECK_EQ(proto_recv_line(sv[1], small, sizeof small), PROTO_E_LINE_TOO_LONG);
    CHECK(!strcmp(small, "abcd"));
    CHECK_EQ(proto_recv_line(sv[1], buf, sizeof buf), 0);            /* the rest, empty */
    CHECK_EQ(proto_recv_line(sv[1], buf, sizeof buf), 4);
    CHECK(!strcmp(buf, "rest"));
    close(sv[0]);
    CHECK_EQ(proto_recv_line(sv[1], buf, sizeof buf), PROTO_E_PEER_CLOSED);
    CHECK(!strcmp(buf, "last"));
    CHECK_EQ(proto_recv_line(sv[1], buf, 0), PROTO_E_PARAM);
    CHECK_EQ(proto_recv_line(-1, buf, sizeof buf), PROTO_E_READ);
    close(sv[1]);

    pair(sv);                                                       /* a deadline */
    CHECK_EQ(proto_recv_line_timeout(sv[1], buf, sizeof buf, 50), PROTO_E_TIMEOUT);
    put(sv[0], "late\n");
    CHECK_EQ(proto_recv_line_timeout(sv[1], buf, sizeof buf, 1000), 4);
    close(sv[0]); close(sv[1]);

    pair(sv);                                                       /* sending */
    CHECK_EQ(proto_send_line(sv[0], "OK"), PROTO_OK);
    CHECK_EQ(proto_send_prefixed(sv[0], "PUT ", "body", 4), PROTO_OK);
    CHECK_EQ(proto_recv_line(sv[1], buf, sizeof buf), 2);
    CHECK_EQ(proto_recv_line(sv[1], buf, sizeof buf), 8);
    CHECK(!strcmp(buf, "PUT body"));
    close(sv[1]);
    signal(SIGPIPE, SIG_DFL);
    CHECK_EQ(proto_send_line(sv[0], "x"), PROTO_E_WRITE);            /* no SIGPIPE */
    close(sv[0]);

    pair(sv);                                                       /* heap lines */
    int status = 999;
    put(sv[0], "dynamic line\n\n");
    char *d = proto_recv_line_dyn_status(sv[1], &status);
    CHECK(d && !strcmp(d, "dynamic line") && status == PROTO_OK);
    free(d);
    d = proto_recv_line_dyn(sv[1]);
    CHECK(d && !*d);
    free(d);
    close(sv[0]);
    CHECK(proto_recv_line_dyn_status(sv[1], &status) == NULL);
    CHECK_EQ(status, PROTO_E_PEER_CLOSED);
    close(sv[1]);

    int p[2];                                                       /* a pipe, a byte at a time */
    if (pipe(p) != 0) FAILF("pipe");
    put(p[1], "pipe line\nnext\n");
    CHECK_EQ(proto_recv_line(p[0], buf, sizeof buf), 9);
    CHECK_EQ(proto_recv_line(p[0], buf, sizeof buf), 4);
    close(p[0]); close(p[1]);

    CHECK_EQ(tcp_pair(sv), 0);                                      /* keepalive on TCP */
#if defined(TCP_KEEPINTVL) && defined(TCP_KEEPCNT)
    CHECK_EQ(proto_keepalive(sv[0], 10, 5, 3), PROTO_OK);
#else                                                               /* OpenBSD: no per-socket knobs */
    CHECK_EQ(proto_keepalive(sv[0], 10, 5, 3), PROTO_KEEPALIVE_DEFAULTED);
#endif
    CHECK_EQ(proto_keepalive(-1, 10, 5, 3), PROTO_E_KEEPALIVE);
    close(sv[0]); close(sv[1]);
}

/* ------------------------------------------------------------------- keys */

static void write_key(const char *dir, const char *name, const unsigned char *raw, size_t n, const char *prefix) {
    char path[512], b64[256];
    snprintf(path, sizeof path, "%s/%s", dir, name);
    sodium_bin2base64(b64, sizeof b64, raw, n, sodium_base64_VARIANT_ORIGINAL);
    FILE *f = fopen(path, "w");
    if (!f) FAILF("cannot write %s", path);
    fprintf(f, "%s%s\n", prefix, b64);
    fclose(f);
}

static void write_text(const char *dir, const char *name, const char *text) {
    char path[512];
    snprintf(path, sizeof path, "%s/%s", dir, name);
    FILE *f = fopen(path, "w");
    if (!f) FAILF("cannot write %s", path);
    fputs(text, f);
    fclose(f);
}

static void make_keys(proto_keys_t *k) {
    crypto_sign_keypair(k->auth_pk, k->auth_sk);
    crypto_box_keypair(k->enc_pk, k->enc_sk);
}

static void keys(void) {
    char dir[] = "/tmp/proto-suite-XXXXXX";
    if (!mkdtemp(dir)) FAILF("mkdtemp");
    char a[600], e[600], pub[600], p2[600];
    snprintf(a, sizeof a, "%s/auth.key", dir);
    snprintf(e, sizeof e, "%s/enc.key", dir);
    snprintf(pub, sizeof pub, "%s/auth.pub", dir);
    snprintf(p2, sizeof p2, "%s/other", dir);
    proto_keys_t k, got;
    make_keys(&k);
    write_key(dir, "auth.key", k.auth_sk, sizeof k.auth_sk, "");
    write_key(dir, "enc.key", k.enc_sk, sizeof k.enc_sk, "");
    write_key(dir, "auth.pub", k.auth_pk, sizeof k.auth_pk, "");

    CHECK_EQ(proto_load_keys(a, e, &got), PROTO_OK);
    CHECK(!memcmp(got.auth_pk, k.auth_pk, 32) && !memcmp(got.enc_pk, k.enc_pk, 32));
    char hex[65], want[65];
    CHECK_EQ(proto_load_pubkey_hex(pub, hex, sizeof hex), PROTO_OK);
    sodium_bin2hex(want, sizeof want, k.auth_pk, 32);
    CHECK(!strcmp(hex, want));
    CHECK_EQ(proto_load_pubkey_hex(pub, hex, 64), PROTO_E_BUFFER_TOO_SMALL);

    write_text(dir, "other", "");
    CHECK_EQ(proto_load_pubkey_hex(p2, hex, sizeof hex), PROTO_E_KEY_EMPTY);
    write_key(dir, "other", k.auth_pk, 32, " ");
    CHECK_EQ(proto_load_pubkey_hex(p2, hex, sizeof hex), PROTO_E_KEY_STRAY);
    write_text(dir, "other", "AAAA*AAAA\n");
    CHECK_EQ(proto_load_pubkey_hex(p2, hex, sizeof hex), PROTO_E_KEY_FORMAT);
    write_key(dir, "other", k.auth_pk, 31, "");
    CHECK_EQ(proto_load_pubkey_hex(p2, hex, sizeof hex), PROTO_E_KEY_SIZE);
    CHECK_EQ(proto_load_pubkey_hex("/nonexistent/key", hex, sizeof hex), PROTO_E_KEY_NOT_FOUND);
    CHECK_EQ(proto_load_pubkey_hex(dir, hex, sizeof hex), PROTO_E_KEY_NOT_FILE);
    CHECK_EQ(proto_load_pubkey_hex(NULL, hex, sizeof hex), PROTO_E_PARAM);

    unsigned char sk[64];
    memcpy(sk, k.auth_sk, 64);
    sk[40] ^= 1;                                             /* damage the public half */
    write_key(dir, "other", sk, 64, "");
    memset(&got, 0xAA, sizeof got);
    CHECK_EQ(proto_load_keys(p2, e, &got), PROTO_E_KEY_MISMATCH);
    unsigned char zero[sizeof got];
    memset(zero, 0, sizeof zero);
    CHECK(!memcmp(&got, zero, sizeof got));                  /* nothing left behind */
    memset(&got, 0xAA, sizeof got);
    CHECK_EQ(proto_load_keys(a, pub, &got), PROTO_E_KEY_PUBLIC);   /* auth.pub as enc.key */
    CHECK(!memcmp(&got, zero, sizeof got));
    CHECK_EQ(proto_load_keys(e, a, &got), PROTO_E_KEY_SIZE);
    CHECK_EQ(proto_load_keys(a, e, NULL), PROTO_E_PARAM);
}

/* ------------------------------------------------------------------- seal */

static void seal(void) {
    unsigned char pk[32], sk[32], pk2[32], sk2[32];
    crypto_box_keypair(pk, sk);
    crypto_box_keypair(pk2, sk2);
    static const size_t lens[] = { 0, 1, 2, 3, 47, 48, 49, 255, 4096, 65535 };
    for (size_t i = 0; i < sizeof lens / sizeof lens[0]; i++) {
        size_t n = lens[i], out_len = 7;
        unsigned char *msg = malloc(n + 1);
        randombytes_buf(msg, n);
        char *b64 = proto_seal_new(msg, n, pk);
        CHECK(b64 != NULL);
        unsigned char *plain = proto_unseal_new(b64, pk, sk, &out_len);
        CHECK(plain != NULL && out_len == n && !memcmp(plain, msg, n) && plain[n] == 0);
        free(plain);
        CHECK(proto_unseal_new(b64, pk2, sk2, &out_len) == NULL);     /* another recipient */
        CHECK(proto_unseal_new(b64, pk, sk2, NULL) == NULL);          /* the wrong secret key */
        size_t len = strlen(b64);
        b64[len / 2] = b64[len / 2] == 'A' ? 'B' : 'A';
        CHECK(proto_unseal_new(b64, pk, sk, NULL) == NULL);           /* damaged */
        free(b64);
        free(msg);
    }
    char out[128];
    size_t need = sodium_base64_ENCODED_LEN(5 + crypto_box_SEALBYTES, sodium_base64_VARIANT_ORIGINAL);
    char *big = malloc(need);
    CHECK_EQ(proto_seal((const unsigned char *)"hello", 5, pk, big, need), PROTO_OK);
    CHECK_EQ(proto_seal((const unsigned char *)"hello", 5, pk, out, need - 1), PROTO_E_BUFFER_TOO_SMALL);
    free(big);
    static const char *bad[] = { "", "A", "AAAA", "not base64!", "====" };
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++)
        CHECK(proto_unseal_new(bad[i], pk, sk, NULL) == NULL);
    unsigned char zero_pk[32] = { 0 };
    CHECK_EQ(proto_seal((const unsigned char *)"x", 1, zero_pk, out, sizeof out), PROTO_E_CRYPTO);
}

static void seal_bounds(void) {
    unsigned char pk[32], sk[32];
    crypto_box_keypair(pk, sk);
    char out[8];
    CHECK_EQ(proto_seal(NULL, SIZE_MAX, pk, out, 0), PROTO_E_PARAM);
    CHECK_EQ(proto_seal(NULL, SIZE_MAX - 47, pk, out, 0), PROTO_E_PARAM);
    CHECK_EQ(proto_seal(NULL, SEAL_MSG_MAX + 1, pk, out, 0), PROTO_E_PARAM);
    CHECK_EQ(proto_seal(NULL, SEAL_MSG_MAX, pk, out, 0), PROTO_E_BUFFER_TOO_SMALL);
    CHECK(proto_seal_new(NULL, SIZE_MAX, pk) == NULL);
    CHECK(proto_seal_new(NULL, SIZE_MAX - 47, pk) == NULL);
    /* This length makes proto_seal_new ask malloc for SIZE_MAX - 2 bytes, which valgrind reports as a
     * "fishy" size. The request failing is what the check is for, so valgrind does not run this line;
     * every other build does. */
    if (!getenv("PROTO_SUITE_VALGRIND"))
        CHECK(proto_seal_new(NULL, SEAL_MSG_MAX + 1, pk) == NULL);
}

/* ------------------------------------------------------------------- sign */

static void sign(void) {
    unsigned char pk[32], sk[64], sig[64], ch[32];
    crypto_sign_keypair(pk, sk);
    randombytes_buf(ch, sizeof ch);
    CHECK_EQ(proto_sign_challenge(ch, sizeof ch, sk, sig), PROTO_OK);
    CHECK_EQ(proto_verify_challenge(ch, sizeof ch, sig, pk), PROTO_OK);
    CHECK_EQ(proto_verify_challenge(ch, 31, sig, pk), PROTO_E_BAD_SIGNATURE);
    for (int bit = 0; bit < 64 * 8; bit += 13) {
        unsigned char bad[64];
        memcpy(bad, sig, 64);
        bad[bit / 8] ^= (unsigned char)(1 << (bit % 8));
        CHECK_EQ(proto_verify_challenge(ch, sizeof ch, bad, pk), PROTO_E_BAD_SIGNATURE);
    }
    unsigned char zero_sig[64] = { 0 }, zero_pk[32] = { 0 };
    CHECK_EQ(proto_verify_challenge(ch, sizeof ch, zero_sig, zero_pk), PROTO_E_BAD_SIGNATURE);
    CHECK_EQ(proto_sign_challenge(ch, 0, sk, sig), PROTO_OK);
    CHECK_EQ(proto_verify_challenge(ch, 0, sig, pk), PROTO_OK);
}

/* -------------------------------------------------------------- handshake */

struct hs { int fd; const char *allowed; char *got; };

static void *server_thread(void *arg) {
    struct hs *h = arg;
    h->got = proto_auth_server(h->fd, h->allowed);
    if (h->got) proto_send_line(h->fd, "OK");
    return NULL;
}

static void handshake(void) {
    proto_keys_t k;
    make_keys(&k);
    char allowed[65], other[65];
    sodium_bin2hex(allowed, sizeof allowed, k.auth_pk, 32);
    memset(other, 'a', 64);
    other[64] = '\0';
    CHECK_EQ(proto_init(), PROTO_OK);

    int sv[2];
    pair(sv);
    struct hs h = { sv[1], allowed, NULL };
    pthread_t t;
    if (pthread_create(&t, NULL, server_thread, &h) != 0) FAILF("pthread_create");
    CHECK_EQ(proto_auth_client(sv[0], &k), PROTO_OK);
    pthread_join(t, NULL);
    CHECK(h.got && !strcmp(h.got, allowed));
    free(h.got);
    close(sv[0]); close(sv[1]);

    pair(sv);                                                /* not on the allowlist */
    h = (struct hs){ sv[1], other, NULL };
    if (pthread_create(&t, NULL, server_thread, &h) != 0) FAILF("pthread_create");
    CHECK_EQ(proto_auth_client(sv[0], &k), PROTO_E_REJECTED);
    pthread_join(t, NULL);
    CHECK(h.got == NULL);
    close(sv[0]); close(sv[1]);
}

/* ------------------------------------------------------------------ serve */

static void on_term(int sig) { (void)sig; proto_serve_stop(); }

static void serve_handler(int fd, const char *id, void *ctx) {
    (void)id; (void)ctx;
    proto_send_line(fd, "OK");
    for (;;) {
        char *line = proto_recv_line_dyn(fd);
        if (!line) return;
        if (!strcmp(line, "QUIT")) { proto_send_line(fd, "BYE"); free(line); return; }
        proto_send_line(fd, !strcmp(line, "PING") ? "PONG" : "ERR");
        free(line);
    }
}

static void serve(void) {
    proto_keys_t k;
    make_keys(&k);
    char allowed[65];
    sodium_bin2hex(allowed, sizeof allowed, k.auth_pk, 32);

    int probe = socket(AF_INET, SOCK_STREAM, 0);                 /* a free port */
    struct sockaddr_in a;
    socklen_t al = sizeof a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(probe, (struct sockaddr *)&a, sizeof a) != 0 || getsockname(probe, (struct sockaddr *)&a, &al) != 0)
        FAILF("free port");
    int port = ntohs(a.sin_port);
    close(probe);

    pid_t pid = fork();
    if (pid < 0) FAILF("fork");
    if (pid == 0) {
        struct sigaction sa;
        memset(&sa, 0, sizeof sa);
        sa.sa_handler = on_term;
        sigemptyset(&sa.sa_mask);
        sigaction(SIGTERM, &sa, NULL);
        proto_serve_opts_t opts = { .bind_addr = "127.0.0.1", .drain_ms = 2000 };
        /* exit() and not _exit(): a coverage build writes its counters at exit */
        exit(proto_serve(port, allowed, serve_handler, NULL, &opts) == PROTO_OK ? 0 : 1);
    }

    proto_conn_t c;
    memset(&c, 0, sizeof c);
    c.fd = -1;
    c.keys = k;
    int rc = PROTO_E_CONNECT;
    for (int i = 0; i < 200 && rc == PROTO_E_CONNECT; i++) {
        rc = proto_connect(&c, "127.0.0.1", port);
        if (rc == PROTO_E_CONNECT) nanosleep(&(struct timespec){ 0, 50 * 1000000 }, NULL);
    }
    CHECK_EQ(rc, PROTO_OK);
    char buf[64];
    CHECK_EQ(proto_send_line(c.fd, "PING"), PROTO_OK);
    CHECK_EQ(proto_recv_line(c.fd, buf, sizeof buf), 4);
    CHECK(!strcmp(buf, "PONG"));
    proto_close(&c);
    CHECK_EQ(c.fd, -1);

    kill(pid, SIGTERM);
    int status = 0;
    CHECK_EQ(waitpid(pid, &status, 0), pid);
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

/* ------------------------------------------------------------------- main */

static const struct { const char *name; void (*fn)(void); } scenarios[] = {
    { "wire", wire }, { "keys", keys }, { "seal", seal }, { "seal_bounds", seal_bounds },
    { "sign", sign }, { "handshake", handshake }, { "serve", serve },
};

int main(int argc, char **argv) {
    CHECK(sodium_init() >= 0);
    size_t n = sizeof scenarios / sizeof scenarios[0];
    for (size_t i = 0; i < n; i++) {
        int run = argc < 2;
        for (int j = 1; j < argc; j++) if (!strcmp(argv[j], scenarios[i].name)) run = 1;
        if (!run) continue;
        scenarios[i].fn();
        printf("ok %s\n", scenarios[i].name);
        fflush(stdout);
    }
    for (int j = 1; j < argc; j++) {
        int known = 0;
        for (size_t i = 0; i < n; i++) known |= !strcmp(argv[j], scenarios[i].name);
        if (!known) FAILF("unknown scenario %s", argv[j]);
    }
    return 0;
}
