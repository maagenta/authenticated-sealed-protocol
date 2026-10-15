/* seam_crypto.c -- crypto.c with its libc and libsodium calls replaced.
 *
 * crypto.c is compiled with
 *     -Dread=seam_read -Dopen=seam_open -Dmalloc=seam_malloc -Dfree=seam_free
 *     -Dsodium_memzero=spy_memzero
 *
 *   seam_crypto read_eio PATH           T-151  read() fails with EIO
 *   seam_crypto read_eintr PATH         T-152  read() fails with EINTR once
 *   seam_crypto read_onebyte PATH       T-153  read() delivers one byte a call
 *   seam_crypto open_flags PATH         T-155  how the file is opened
 *   seam_crypto memzero KIND PATH       T-156  what is wiped on every way out
 *   seam_crypto malloc_fail             T-189  a failed allocation
 *   seam_crypto unseal_alloc            T-201  what opening allocates
 *   seam_crypto unseal_failures         T-202  failed opens leak nothing
 */
#include <fcntl.h>
#include <stdarg.h>
#include <unistd.h>

#include "crypto.h"
#include "probe.h"

/* ------------------------------------------------------------------ seams */

static int read_mode;                     /* 1 EIO, 2 EINTR once, 3 one byte a call */
static int read_calls;
static int last_open_flags = -1;

ssize_t seam_read(int fd, void *buf, size_t n) {
    read_calls++;
    if (read_mode == 1) { errno = EIO; return -1; }
    if (read_mode == 2 && read_calls == 1) { errno = EINTR; return -1; }
    if (read_mode == 3 && n > 1) n = 1;
    return read(fd, buf, n);
}

int seam_open(const char *path, int flags, ...) {
    last_open_flags = flags;
    return open(path, flags);
}

struct wipe { size_t len; };
static struct wipe wipes[64];
static int nwipes;

void spy_memzero(void *p, size_t n) {
    if (nwipes < 64) wipes[nwipes++].len = n;
    sodium_memzero(p, n);
}

static unsigned long malloc_calls, free_calls;
static unsigned long fail_nth_malloc;     /* 0: never */
static size_t alloc_sizes[16];

void *seam_malloc(size_t n) {
    malloc_calls++;
    if (malloc_calls <= 16) alloc_sizes[malloc_calls - 1] = n;
    if (fail_nth_malloc && malloc_calls == fail_nth_malloc) return NULL;
    return malloc(n);
}

void seam_free(void *p) {
    if (p) free_calls++;
    free(p);
}

static void reset_counts(void) {
    malloc_calls = free_calls = 0;
    fail_nth_malloc = 0;
    memset(alloc_sizes, 0, sizeof alloc_sizes);
}

/* -------------------------------------------------------------- scenarios */

static int load_hex(const char *path) {
    char hex[65];
    return proto_load_pubkey_hex(path, hex, sizeof hex);
}

static int count_wipes(size_t len) {
    int n = 0;
    for (int i = 0; i < nwipes; i++) if (wipes[i].len == len) n++;
    return n;
}

static void memzero_scenario(const char *kind, const char *path) {
    int want, decodes = 1;
    if (!strcmp(kind, "ok")) want = PROTO_OK;
    else if (!strcmp(kind, "empty")) { want = PROTO_E_KEY_EMPTY; decodes = 0; }
    else if (!strcmp(kind, "stray")) { want = PROTO_E_KEY_STRAY; decodes = 0; }
    else if (!strcmp(kind, "format")) want = PROTO_E_KEY_FORMAT;
    else if (!strcmp(kind, "size")) want = PROTO_E_KEY_SIZE;
    else if (!strcmp(kind, "readfail")) { want = PROTO_E_KEY_READ; decodes = 0; read_mode = 1; }
    else FAILF("unknown kind %s", kind);
    nwipes = 0;
    CHECK_EQ(load_hex(path), want);
    CHECK_EQ(count_wipes(512), 1);                 /* the line buffer */
    CHECK_EQ(count_wipes(384), decodes);           /* the decoding buffer */
}

static void seal_to(const unsigned char *pk, const char *msg, size_t n, char **out) {
    *out = proto_seal_new((const unsigned char *)msg, n, pk);
    CHECK(*out != NULL);
}

int main(int argc, char **argv) {
    if (argc < 2) FAILF("usage: seam_crypto SCENARIO ...");
    const char *sc = argv[1];
    CHECK_EQ(proto_init(), PROTO_OK);

    if (!strcmp(sc, "read_eio")) {
        CHECK(argc > 2);
        read_mode = 1;
        CHECK_EQ(load_hex(argv[2]), PROTO_E_KEY_READ);
    } else if (!strcmp(sc, "read_eintr")) {
        CHECK(argc > 2);
        read_mode = 2;
        CHECK_EQ(load_hex(argv[2]), PROTO_OK);
        CHECK(read_calls >= 2);
    } else if (!strcmp(sc, "read_onebyte")) {
        CHECK(argc > 2);
        read_mode = 3;
        CHECK_EQ(load_hex(argv[2]), PROTO_OK);
        CHECK(read_calls >= 40);
    } else if (!strcmp(sc, "open_flags")) {
        CHECK(argc > 2);
        CHECK_EQ(load_hex(argv[2]), PROTO_OK);
        CHECK_EQ(last_open_flags, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
    } else if (!strcmp(sc, "memzero")) {
        CHECK(argc > 3);
        memzero_scenario(argv[2], argv[3]);
    } else if (!strcmp(sc, "malloc_fail")) {
        unsigned char pk[crypto_box_PUBLICKEYBYTES], sk[crypto_box_SECRETKEYBYTES];
        crypto_box_keypair(pk, sk);
        char out[256];
        for (unsigned long nth = 1; nth <= 1; nth++) {
            reset_counts();
            fail_nth_malloc = nth;
            CHECK_EQ(proto_seal((const unsigned char *)"hello", 5, pk, out, sizeof out), PROTO_E_NOMEM);
            CHECK_EQ(malloc_calls, free_calls + 1);          /* the one that failed was never allocated */
        }
        for (unsigned long nth = 1; nth <= 2; nth++) {
            reset_counts();
            fail_nth_malloc = nth;
            CHECK(proto_seal_new((const unsigned char *)"hello", 5, pk) == NULL);
            CHECK_EQ(malloc_calls - 1, free_calls);          /* nothing leaked */
        }
    } else if (!strcmp(sc, "unseal_alloc")) {
        unsigned char pk[crypto_box_PUBLICKEYBYTES], sk[crypto_box_SECRETKEYBYTES];
        crypto_box_keypair(pk, sk);
        size_t n = 1024 * 1024;
        char *msg = malloc(n);
        memset(msg, 'm', n);
        char *b64;
        seal_to(pk, msg, n, &b64);
        size_t len = strlen(b64);
        reset_counts();
        size_t out_len = 0;
        unsigned char *plain = proto_unseal_new(b64, pk, sk, &out_len);
        CHECK(plain != NULL);
        CHECK_EQ(out_len, n);
        CHECK_EQ(malloc_calls, 2);
        CHECK_EQ(alloc_sizes[0], len);                         /* the decoded box: about L */
        CHECK(alloc_sizes[1] >= n && alloc_sizes[1] <= n + 8); /* the plaintext: about 0.75 L */
        /* 0.75 L, less the 48 bytes of the seal and the padding */
        CHECK(alloc_sizes[1] * 4 >= len * 3 - 256 && alloc_sizes[1] * 4 <= len * 3 + 32);
        free(plain);
    } else if (!strcmp(sc, "unseal_failures")) {
        unsigned char pk[crypto_box_PUBLICKEYBYTES], sk[crypto_box_SECRETKEYBYTES];
        unsigned char pk2[crypto_box_PUBLICKEYBYTES], sk2[crypto_box_SECRETKEYBYTES];
        crypto_box_keypair(pk, sk);
        crypto_box_keypair(pk2, sk2);
        char *good;
        seal_to(pk, "a message", 9, &good);
        size_t glen = strlen(good);
        char *bad = strdup(good);
        bad[glen / 2] = (bad[glen / 2] == 'A') ? 'B' : 'A';
        char *trunc = strdup(good);
        trunc[glen - 4] = '\0';
        char *extra = malloc(glen + 8);
        strcpy(extra, good);
        strcat(extra, "AAAA");
        const char *inputs[] = { "", "A", "AAAA", "not base64 at all!", bad, trunc, extra };
        reset_counts();
        for (size_t i = 0; i < sizeof inputs / sizeof inputs[0]; i++) {
            size_t out_len = 77;
            CHECK(proto_unseal_new(inputs[i], pk, sk, &out_len) == NULL);
            CHECK_EQ(out_len, 77);
        }
        CHECK(proto_unseal_new(good, pk2, sk2, NULL) == NULL);          /* wrong recipient */
        CHECK_EQ(malloc_calls, free_calls);
    } else {
        FAILF("unknown scenario %s", sc);
    }
    puts("ok");
    return 0;
}
