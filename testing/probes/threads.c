/* threads.c -- the library called from several threads at once.
 *
 *   threads strerror            8 threads, 100000 calls each
 *   threads init                8 threads call proto_init at once
 *   threads load AUTH ENC       8 threads load the same key pair
 *   threads stop PORT           proto_serve_stop() from another thread
 *
 * Built with and without ThreadSanitizer; the test reads the report.
 */
#include <pthread.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "crypto.h"
#include "probe.h"
#include "serve.h"
#include "status.h"

#define NTHREADS 8

static const char *g_auth, *g_enc;
static proto_keys_t g_want;

static const int codes[] = { 0, 1, 2, -101, -202, -305, -402, -510, -605, -704, -999 };

static void *strerror_worker(void *arg) {
    (void)arg;
    size_t n = sizeof codes / sizeof codes[0];
    for (int i = 0; i < 100000; i++) {
        int c = codes[i % n];
        const char *s = proto_strerror(c);
        if (!s || !*s) return (void *)1;
        if (c == 0 && strcmp(s, "success") != 0) return (void *)1;
    }
    return NULL;
}

static void *init_worker(void *arg) {
    (void)arg;
    return proto_init() == PROTO_OK ? NULL : (void *)1;
}

static void *load_worker(void *arg) {
    (void)arg;
    for (int i = 0; i < 50; i++) {
        proto_keys_t k;
        if (proto_load_keys(g_auth, g_enc, &k) != PROTO_OK) return (void *)1;
        if (memcmp(&k, &g_want, sizeof k) != 0) return (void *)1;
    }
    return NULL;
}

static void run_threads(void *(*fn)(void *), const char *what) {
    pthread_t t[NTHREADS];
    for (int i = 0; i < NTHREADS; i++)
        if (pthread_create(&t[i], NULL, fn, NULL) != 0) FAILF("pthread_create");
    for (int i = 0; i < NTHREADS; i++) {
        void *r;
        pthread_join(t[i], &r);
        if (r) FAILF("a %s thread saw a wrong result", what);
    }
}

static void *stopper(void *arg) {
    (void)arg;
    nanosleep(&(struct timespec){ 0, 200 * 1000000 }, NULL);
    proto_serve_stop();
    return NULL;
}

static void never(int fd, const char *id, void *ctx) { (void)fd; (void)id; (void)ctx; }

int main(int argc, char **argv) {
    if (argc < 2) FAILF("usage: threads SCENARIO");
    const char *sc = argv[1];
    if (strcmp(sc, "strerror") == 0) {
        run_threads(strerror_worker, "proto_strerror");
    } else if (strcmp(sc, "init") == 0) {
        for (int i = 0; i < 3; i++) CHECK_EQ(proto_init(), PROTO_OK);
        run_threads(init_worker, "proto_init");
    } else if (strcmp(sc, "load") == 0) {
        if (argc < 4) FAILF("usage: threads load AUTH ENC");
        g_auth = argv[2];
        g_enc = argv[3];
        CHECK_EQ(proto_init(), PROTO_OK);
        CHECK_EQ(proto_load_keys(g_auth, g_enc, &g_want), PROTO_OK);
        run_threads(load_worker, "proto_load_keys");
    } else if (strcmp(sc, "stop") == 0) {
        if (argc < 3) FAILF("usage: threads stop PORT");
        char allowed[65];
        memset(allowed, 'a', 64);
        allowed[64] = '\0';
        pthread_t t;
        if (pthread_create(&t, NULL, stopper, NULL) != 0) FAILF("pthread_create");
        int rc = proto_serve(atoi(argv[2]), allowed, never, NULL, NULL);
        pthread_join(t, NULL);
        CHECK_EQ(rc, PROTO_OK);
    } else {
        FAILF("unknown scenario %s", sc);
    }
    puts("ok");
    return 0;
}
