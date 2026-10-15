/* probe.h -- the little a probe program needs.
 *
 * A probe is a small C program built from the library sources (see lib.py,
 * build_exe). It runs one scenario named on its command line and reports with
 * its exit status: 0 for success, 1 with a message on stderr for a failure.
 */
#ifndef PROBE_H
#define PROBE_H

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FAILF(...) do {                                                        \
    fprintf(stderr, "FAIL %s:%d: ", __FILE__, __LINE__);                       \
    fprintf(stderr, __VA_ARGS__);                                              \
    fputc('\n', stderr);                                                       \
    exit(1);                                                                   \
} while (0)

#define CHECK(cond) do { if (!(cond)) FAILF("%s", #cond); } while (0)

#define CHECK_EQ(got, want) do {                                               \
    long long g_ = (long long)(got), w_ = (long long)(want);                   \
    if (g_ != w_) FAILF("%s: got %lld, want %lld", #got, g_, w_);              \
} while (0)

#define DIE_IF_FAILED(rc) do {                                                 \
    if ((rc) < 0) FAILF("%s returned %d (%s)", #rc, (int)(rc),                 \
                        proto_strerror((int)(rc)));                            \
} while (0)

#endif /* PROBE_H */
