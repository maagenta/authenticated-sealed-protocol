# Tests for `proto`

This directory holds the test suite of the library and the harness that runs it,
on a developer's machine and in CI. Every test has an entry in this file, in the
order of the library: build, status codes, wire, key files, cryptography,
handshake, connecting, serving, the `keygen` tool, end to end, sanitizers and
fuzzing, documentation, load. The entry says what the test does and what it
expects; the `Code:` line says where it is.

The suite checks what the code and the documents (`docs.md`, `architecture.md`,
`RELEASE_NOTES.md`) promise, not what the code happens to do. Where the two
disagree, the test says so and fails, marked as expected to fail, until one of
them changes.

## Running the tests

```
python3 testing/run.py                      everything that applies to this host, but the slow tests
python3 testing/run.py -v                   one line per test
python3 testing/run.py --section VII        one section (a roman or an arabic numeral)
python3 testing/run.py --id T-057           one test; ranges and lists too: T-052..T-079, 57,60
python3 testing/run.py --tag seam           every test with a tag
python3 testing/run.py --slow               also the slow tests (nightly in CI)
python3 testing/run.py --fuzz               also the fuzz targets (--fuzz-seconds N for each)
python3 testing/run.py --list               what there is, and what this host skips
python3 testing/run.py --check              README.md against the registered tests
python3 testing/run.py --record-baselines   rewrite the warning and analyzer baselines
python3 testing/run.py --clean              remove testing/.build first
```

The exit status is 0 when every guard and pin passed, every finding failed as
expected and no finding passed; it is 1 otherwise. In GitHub Actions the totals
and the problems also go to the job summary.

| Result | Meaning |
|---|---|
| `PASS` | A guard or a pin held. |
| `FAIL` | A guard or a pin did not hold: a regression, or a difference between platforms to look into. |
| `XFAIL` | A finding failed, as it does today. The run stays green. |
| `XPASS` | A finding passed: the defect is fixed. The run fails until the test is made a guard (`FINDING` to `GUARD` in its `@case`, and the **Fails today.** line out of its entry here). |
| `SKIP` | The test does not apply here: another platform, no privilege, a tool this host lacks, or a slow test run without `--slow`. |

The verdicts are the catalogue's:

- A **guard** protects behaviour that is documented or plainly intended, and
  passes today.
- A **finding** (**Fails today.** in its entry) states what the documents
  promise and the code does not do, or the other way round. The code or the
  documents must change before it can pass.
- A **pin** (**Pin.**) records behaviour nobody documented, so that changing it is
  a decision and not an accident. A pin that says **Decide** carries an open
  question.

A finding that only shows on some platforms is a guard on the others, and the
tags at the end of an entry say where a test applies: `(Linux)` and `(macOS)`
only run there, `(root)` needs privileges, `(not as root)` must not have them,
`(seam)` uses fault injection, `(slow)` runs nightly, `(IPv6)` needs `::1`,
`(fuzz)` is a fuzz target.

## Requirements

- Python 3.8 or newer, standard library only.
- A C compiler (`cc`, or the one `CC` names), `make`, and libsodium with its
  headers. The library is found with `pkg-config`, else under `/usr/local`,
  `/opt/homebrew`, `/opt/local` and `/usr/pkg`; `SODIUM_CFLAGS` and
  `SODIUM_LIBS` override that.
- Optional, and the tests that need them skip without them: `nm`, a C++
  compiler, `valgrind`, `cppcheck`, `nft` or `iptables` with `ip`, a
  32-bit toolchain, a cross compiler for AArch64.

| Variable | Effect |
|---|---|
| `CC` | The compiler of every build. With it set, the build tests use only that one. |
| `SODIUM_CFLAGS`, `SODIUM_LIBS` | Where libsodium is, when `pkg-config` does not know. |
| `PROTO_TEST_SLACK` | Multiplies the slack of every timing window. Slow hosts and emulators set 3 or 4. |
| `PROTO_TEST_TIMEOUT` | Seconds a test may run before it is killed (default 60). |
| `PROTO_FUZZ_SECONDS` | Time budget of each fuzz target (default 20; CI uses 60). |

## How a test runs

**Isolation.** Every test runs in a forked child with its own process group, its
own temporary directory, its standard streams captured and a hard deadline. A
crash, a hang or a leftover process fails that test and nothing else, and a call
that is expected to crash (a `NULL` argument, say) shows as `killed by SIGSEGV`.
Whatever the child writes to standard output or error is a failure too: the
library must stay silent (T-405).

**Calling the library.** The five sources are compiled into a shared library per
build variant and called through `ctypes` (`lib.py`). The variants exist because
the timeouts and framing options are compile-time:

| Variant | Flags | Used for |
|---|---|---|
| `default` | none | the defaults themselves |
| `fast` | `HANDSHAKE_TIMEOUT_MS=300`, `QUIT_TIMEOUT_MS=200`, `CONNECT_TIMEOUT_MS=500` | almost every test, so that timing tests take under a second |
| `chunk1`, `chunk3` | `fast` and `READ_CHUNK=1` or `3` | T-011: the `wire` tests must pass unchanged |
| `pay64` | `fast` and `MAX_PAYLOAD=64` | the boundaries of the payload cap, cheap to reach |
| `pay64c1`, `pay64c3` | `pay64` with `READ_CHUNK` 1 and 3 | the cap however the bytes arrive (T-101) |
| `min` | `HANDSHAKE_TIMEOUT_MS=1`, `QUIT_TIMEOUT_MS=0` | the smallest values the options take |

Builds are cached under `testing/.build/`, keyed on the sources and the flags.

**Probes.** What a call through `ctypes` cannot do is done by small C programs in
`probes/`, built from the library sources and run as processes. The test judges
them by their exit status and their log:

- `seam_wire.c` and `seam_crypto.c` take over the libc calls of one source
  (`-Dsend=seam_send`, `-Dread=seam_read`, and so on) to count them, shorten
  them or make them fail. A seam object is built with `-U_FORTIFY_SOURCE`, and is
  never shared with an unseamed binary. `LD_PRELOAD` is not used: macOS has none.
- `threads.c` calls the library from several threads, with and without
  ThreadSanitizer.
- `serve_probe.c` is a server on `proto_serve`, steered from the command line:
  the handler a connection gets, the signals it routes to `proto_serve_stop`,
  the drain, the number of serve cycles. It reports in a log file, one line per
  event.

**Peers.** Tests that need the other end of a connection play it from Python
(`peers.py`, `net.py`): a scripted server or client over a `socketpair` (it
supports `MSG_PEEK`, but has no TCP options and, on macOS, an 8 KiB buffer) or
TCP on 127.0.0.1 (resets: closing with `SO_LINGER {1, 0}`), or a `pipe` for the
fallback that reads a byte at a time. Silence, for a connect timeout, comes from
a listener with a full accept queue (Linux) or from the `getaddrinfo` and
`connect` seams. A port is found by binding port 0 and reading it back.

**Timing.** Windows, never exact values: `[ms, ms + 250]`, measured on the
monotonic clock, scaled by `PROTO_TEST_SLACK`. No test asserts a duration that
is not its own deadline.

## Files

| File | What it holds |
|---|---|
| `run.py` | The command line. |
| `harness.py` | The registry, the isolated runs, the verdicts and the report. |
| `lib.py` | Compilers, libsodium, the build variants, the probes, and the `ctypes` binding. |
| `runprobe.py`, `servers.py` | Running probes; starting and steering `serve_probe`. |
| `net.py`, `peers.py` | Sockets, threads, descriptors; the protocol spoken from Python. |
| `libsodium.py`, `keyfiles.py`, `statuses.py` | The libsodium oracle; key-file fixtures; the 44 status codes. |
| `docsx.py`, `baselines.py`, `readme_check.py` | Reading `docs.md`; baselines of the analyzers; this file against the registry. |
| `sNN_*.py` | The tests, one module per section (a few sections share one). |
| `probes/` | The C programs above. |
| `baselines/` | What the warning and analyzer runs found when they were accepted. |

## Continuous integration

`.github/workflows/ci.yml` runs the suite on every push and pull request, and
the slow tests, the fuzz targets and the privileged tests every night.

| Host | x86-64 | arm64 |
|---|---|---|
| Linux | `ubuntu-24.04` | `ubuntu-24.04-arm` |
| macOS | `macos-15-intel` | `macos-15` |
| FreeBSD 15.1 | VM on `ubuntu-24.04` | VM on `ubuntu-24.04` |
| OpenBSD 7.9, NetBSD 11.0 | VM on `ubuntu-24.04` (allowed to fail) | VM on `ubuntu-24.04` (allowed to fail) |

The BSD machines run under QEMU through `cross-platform-actions/action`; the
arm64 ones are emulated and slow, so they run with `PROTO_TEST_SLACK=4`. Nightly
there is also a job in an Alpine container (musl), one for the 32-bit build,
and a privileged one on Ubuntu for the `(root)` tests.

What was measured where: the expectations marked `(observed)` in the entries
were measured on macOS 14 (x86-64, Apple clang 16, libsodium 1.0.20). What was
worked out from the code or the kernel is marked `(reasoned)`, and the first run
on that platform settles it. A pin that records a platform's behaviour skips on
a platform it has no baseline for, and says so.

## Adding a test

Pick the next free `T-` number (v1.x ends at `T-500`), write the entry in this
file in the same format, and register the function in the module of its
section:

```python
@case("T-424", PIN, tags=("seam",))
def t424():
    """Title of the entry."""
    P = lib.proto()
    ...
```

`python3 testing/run.py --check` fails if a test and an entry disagree on the
id, the verdict or the tags. A test that can crash runs under its own child
anyway; one that expects a crash of a call wraps it in `harness.in_child`.

---

## I. Build, configuration and headers

**T-001 — Headers compile in isolation.**
Each public header (`protocol.h`, `status.h`, `wire.h`, `crypto.h`,
`auth.h`, `serve.h`) compiles as the first and only include of an empty
file, and again when it is included twice. Catches a header that leans
on an include it does not make, or a missing include guard.

Code: `s01_build.py::t001`.

**T-002 — The constants and compile-time options have their documented defaults.**
In a test built with no `-D`, `static_assert`s check
`CHALLENGE_LEN == 32`, `MAX_LINE == 16384`,
`CONNECT_TIMEOUT_MS == 10000`, `HANDSHAKE_TIMEOUT_MS == 10000`,
`QUIT_TIMEOUT_MS == 2000`, `READ_CHUNK == 65536`,
`MAX_PAYLOAD == 16 MiB`, `AUTH_PK_LEN == 32`, `AUTH_SK_LEN == 64`,
`AUTH_SIG_LEN == 64`, `ENC_PK_LEN == 32` and `ENC_SK_LEN == 32`: the
constants table of `docs.md`. A build that sets no option still works,
because every default exists.

Code: `s01_build.py::t002`.

**T-003 — Overrides reach the code.**
A test file built with `-DCONNECT_TIMEOUT_MS=2000`,
`-DHANDSHAKE_TIMEOUT_MS=3000`, `-DQUIT_TIMEOUT_MS=500`,
`-DREAD_CHUNK=131072` and `-DMAX_PAYLOAD=4194304` sees each value
(`#if X != v` then `#error`), with no "redefined" warning. At run time
the fast build proves the same for the library objects (T-222 times out
at 300 ms), and a build at the minimum, `HANDSHAKE_TIMEOUT_MS=1` and
`QUIT_TIMEOUT_MS=0`, runs T-222 to `PROTO_E_TIMEOUT` within 100 ms and
T-288 without a wait. Catches a `#define` that lost its `#ifndef` guard.

Code: `s01_build.py::t003`.

**T-004 — `CONNECT_TIMEOUT_MS=0` fails the build.**
`-DCONNECT_TIMEOUT_MS=0` must not compile; `-DCONNECT_TIMEOUT_MS=1`
compiles. (observed) Catches a dropped `#error` in `protocol.h`.

Code: `s01_build.py::t004`.

**T-005 — `HANDSHAKE_TIMEOUT_MS` below 1 fails the build.**
`-DHANDSHAKE_TIMEOUT_MS=0` and `-DHANDSHAKE_TIMEOUT_MS=-1` must not
compile; 1 compiles. (observed)

Code: `s01_build.py::t005`.

**T-006 — A negative `QUIT_TIMEOUT_MS` fails the build; 0 is allowed.**
`-DQUIT_TIMEOUT_MS=-1` must not compile; 0 compiles, and means "do not
wait". (observed)

Code: `s01_build.py::t006`.

**T-007 — A timeout above `INT_MAX` fails the build.**
**Fails today.** It compiles with only a `-Wconstant-conversion`
warning, and wraps negative where it is passed as `int ms`. With
`-DHANDSHAKE_TIMEOUT_MS=3000000000`, `proto_auth_client` against a
silent peer was still blocked after 2 s (observed): no deadline, the
defect the `< 1` check exists to prevent. With
`-DCONNECT_TIMEOUT_MS=3000000000`, `proto_connect` to a listening local
server returned `PROTO_E_CONNECT_TIMEOUT` (observed), and the same value
for `QUIT_TIMEOUT_MS` would make `proto_close` wait forever (reasoned).
Fix: add `> 2147483647` to the three checks.

Code: `s01_build.py::t007`.

**T-008 — `READ_CHUNK` below 1 fails the build.**
`-DREAD_CHUNK=0` and `-DREAD_CHUNK=-5` must not compile, with
"READ_CHUNK must be at least 1". (observed)

Code: `s01_build.py::t008`.

**T-009 — `MAX_PAYLOAD` outside 64 bytes to 1 GiB fails the build.**
`-DMAX_PAYLOAD=63` and `-DMAX_PAYLOAD=1073741825` must not compile, with
"MAX_PAYLOAD must be between 64 and 1 GiB"; 64 and 1073741824 compile.
(observed)

Code: `s01_build.py::t009`.

**T-010 — An empty option fails at the `#if`.**
An empty definition, which is what an unset Makefile variable produces
(`-DMAX_PAYLOAD=`, `-DREAD_CHUNK=`, `-DHANDSHAKE_TIMEOUT_MS=`), stops
the build instead of compiling to something. (observed)

Code: `s01_build.py::t010`.

**T-011 — The framing options change nothing observable.**
The `wire` tests pass unchanged in builds with `-DREAD_CHUNK=1`,
`-DREAD_CHUNK=3` and `-DMAX_PAYLOAD=64` (observed for the limit cases
T-057 to T-061 and T-098 to T-102). In the `READ_CHUNK=1` build a 1 MiB
line also reads back intact: correctness does not depend on the chunk
size.

Code: `s01_build.py::t011`.

**T-012 — The five library sources build with `-Wall -Wextra -Werror`.**
Each of `status.c`, `wire.c`, `crypto.c`, `auth.c` and `serve.c`
compiles alone with `-Wall -Wextra -Werror` in the compiler's default
dialect, on ubuntu with gcc and clang and on macOS with clang; on macOS
also with `-std=c11 -pedantic` (observed clean). The strict dialects on
Linux are T-014.

Code: `s01_build.py::t012`.

**T-013 — An extended warning set stays quiet.**
`-Wconversion`, `-Wsign-conversion`, `-Wshadow`, `-Wstrict-prototypes`,
`-Wmissing-prototypes`, `-Wcast-qual`, `-Wformat=2`,
`-Wnull-dereference` and `-Wpedantic` give no warning (observed with
clang 16); gcc adds `-Wformat-truncation=2` and `-Wstringop-overflow=4`.
Keep a baseline per compiler and fail on any new warning.

Code: `s01_build.py::t013`.

**T-014 — The sources build under a strict ISO dialect on glibc and musl.**
**Fails today.** (reasoned) Under `-std=c11` or `-std=c99`, glibc and
musl declare only ISO C unless a feature-test macro asks for more, and
no source defines one: `wire.c` loses `clock_gettime` and
`CLOCK_MONOTONIC`, `crypto.c` loses `O_CLOEXEC`, `auth.c` loses
`getaddrinfo`, `strdup` and `strtok_r`, and `serve.c` loses `sigaction`,
`SA_RESTART` and `nanosleep`; even `-D_POSIX_C_SOURCE=200809L` leaves
out `SA_RESTART`, an XSI extension. macOS is clean (observed), since its
headers hide nothing unless asked to; T-015 is the same problem the
other way round. The code uses nothing newer than C99. Expect the five
sources to compile under `-std=c99`, `-std=c11`,
`-D_POSIX_C_SOURCE=200809L` and `-D_XOPEN_SOURCE=700`, on glibc, musl
and macOS: feature-test macros at the top of each source, or a sentence
in `docs.md` naming the dialect a consuming project must use. Decided
together with T-015.

Code: `s01_build.py::t014`.

**T-015 — `wire.c` compiles under `-D_POSIX_C_SOURCE=200809L` on macOS.**
**Fails today.** A consuming project that builds with that flag cannot
compile `wire.c`: `TCP_KEEPALIVE` is hidden by the feature macro, and
`TCP_KEEPIDLE` does not exist there (observed). `auth.c` and `serve.c`
compile under the same flag (observed). Fix: `_DARWIN_C_SOURCE`, or skip
the idle knob when neither constant is visible; record glibc and musl as
well. Decided together with T-014. (macOS)

Code: `s01_build.py::t015`.

**T-016 — A client links without `serve.c`.**
A client program links from `status.c wire.c crypto.c auth.c` alone,
with no undefined symbol: `serve.c` is server-only, as `README.md` says.

Code: `s01_build.py::t016`.

**T-017 — `wire.c` and `status.c` need no libsodium.**
Both compile and link with no libsodium include path and no `-lsodium`:
the "libc alone" promise of `wire.h`. Catches a `sodium_*` call added to
the wrong module.

Code: `s01_build.py::t017`.

**T-018 — Only `proto_*` symbols are exported.**
`nm -g` on the five objects shows none of the helpers (`write_all`,
`read_line_part`, `strip_cr`, `now_ms`, `wait_readable`,
`recv_line_until`, `read_b64_key`, `is_b64_char`, `connect_timeout`,
`is_socket`, `is_identity_hex`, `reap_children`, `drain`) and none of
the globals (`stop_asked`, `stop_fd`, `in_child`, `wake`). The library
is compiled into the application, so an exported helper is a link
collision waiting to happen.

Code: `s01_build.py::t018`.

**T-019 — A 32-bit build passes the suite.**
A `-m32` build, with libsodium for i386, passes the whole suite. It is
the only place where `SEAL_MSG_MAX` is about 3.2 GB (T-186). (Linux)

Code: `s01_build.py::t019`.

**T-020 — An Alpine (musl) build passes the suite.**
A second libc for `getaddrinfo` and `inet_pton` (T-264, T-296). (Linux)

Code: `s01_build.py::t020`.

**T-021 — The headers have no `extern "C"`.**
**Pin.** A C++ file that includes `auth.h` fails to link against the C
objects. Decide whether C++ consumers are supported; if they are, add
the guards and a test that links from C++.

Code: `s01_build.py::t021`.

**T-022 — The Makefile in `docs.md` builds the worked examples.**
The Makefile under "Building a consuming project" builds `vault-client`
and `vault-server` from the worked examples (T-374).

Code: `s01_build.py::t022`.

**T-023 — `keygen` builds with `-Werror`, and its Makefile targets work.**
`make -C keygen CFLAGS="-Wall -Wextra -O2 -Werror"` builds (observed
clean without `-Werror`); `make -C keygen BUILD=$TMP` puts the binary in
`$TMP`; `make -C keygen clean` removes it.

Code: `s01_build.py::t023`.

**T-024 — `keygen/Makefile` hard-codes `gcc` and replaces `CFLAGS`.**
**Pin.** `CC = gcc`, and `CFLAGS` and `LDFLAGS` are assigned outright,
so a libsodium outside the default search path (Homebrew on Apple
Silicon, `/opt/homebrew`) means overriding the whole `CFLAGS` on the
command line and losing `-Wall -Wextra` (reasoned). Decide: `CC ?= cc`,
`CFLAGS +=`, and `pkg-config --cflags --libs libsodium`.

Code: `s01_build.py::t024`.

**T-025 — `keygen` cross-compiles for AArch64.**
`make -C keygen arm64` in a Debian container with
`gcc-aarch64-linux-gnu` and `libsodium-dev:arm64` produces an AArch64
executable, as `file` reports. An optional job. (Linux)

Code: `s01_build.py::t025`.

---

## II. `proto_strerror` and the status codes

**T-026 — Every status code has a message of its own.**
For a list of all 44 members of `proto_status_t`, kept in sync with
`status.h` by T-407, `proto_strerror(v)` is non-NULL, non-empty and not
"unknown status code". Catches a missing `case` after a code is added.

Code: `s02_status.py::t026`.

**T-027 — The 44 messages match a golden table.**
**Pin.** The table is copied from `status.c`, family by family: the 3
successes, 7 caller mistakes, 2 resources, 11 key files, 2 cryptography,
10 sockets, 5 line codes and 4 handshake codes. `docs.md` documents what
the codes mean, not their texts, so a change is allowed; the pin makes
it deliberate, and the table changes with it. Decide whether the texts
are part of the contract.

Code: `s02_status.py::t027`.

**T-028 — No two codes share a message.**
The 44 messages compared pairwise. Catches a copied `case` that was
never edited.

Code: `s02_status.py::t028`.

**T-029 — An unknown value yields "unknown status code".**
3, -1 (the failure value before v1.1), -100, -108, -199, -312, -800,
`INT_MIN` and `INT_MAX` each give "unknown status code", without a
crash. -311 left this list when it became `PROTO_E_KEY_PUBLIC`.

Code: `s02_status.py::t029`.

**T-030 — `proto_strerror` never returns `NULL`.**
For every `int` in [-100000, 100000], and at both extremes.

Code: `s02_status.py::t030`.

**T-031 — `rc < 0` partitions the values.**
Every failure member is negative, `PROTO_OK == 0`,
`PROTO_REGISTER_REQUESTED == 1` and `PROTO_KEEPALIVE_DEFAULTED == 2`,
and each failure's hundreds digit is its family: 1 caller, 2 resources,
3 key files, 4 cryptography, 5 sockets, 6 lines, 7 handshake. Catches a
sign flip when a code is renamed or moved.

Code: `s02_status.py::t031`.

**T-032 — The values are frozen.**
`docs.md` says they are "stable from this release on": one assertion per
member against the numbers in its tables.

Code: `s02_status.py::t032`.

**T-033 — Every message is one line of ASCII.**
No newline inside or at the end, so a message can go straight into a log
line.

Code: `s02_status.py::t033`.

**T-034 — `proto_strerror` is safe from many threads.**
8 threads call it at once, 10^5 calls each, under TSan: no report.

Code: `s02_status.py::t034`.

---

## III. `proto_init`

**T-035 — `proto_init` returns `PROTO_OK`, and is idempotent.**
Three calls in a row return `PROTO_OK` each; so do 8 threads calling it
at once. The header says it is safe to call more than once.

Code: `s02_status.py::t035`.

**T-036 — The turnkey calls need no `proto_init` from the application.**
`proto_connect` and `proto_serve` work in a process that never called
`proto_init`.

Code: `s02_status.py::t036`.

---

## IV. `proto_send_line`, `proto_send_prefixed`

**T-037 — `proto_send_line` writes the line and a newline, nothing else.**
`proto_send_line(fd, "OK")` returns `PROTO_OK`, and the peer reads
exactly the three bytes `OK\n`.

Code: `s04_send.py::t037`.

**T-038 — An empty line writes just a newline.**
`proto_send_line(fd, "")` writes exactly `\n` and returns `PROTO_OK`.

Code: `s04_send.py::t038`.

**T-039 — `proto_send_prefixed` writes the prefix, exactly `body_len` bytes, and a newline.**
`proto_send_prefixed(fd, "PUT ", body, n)`
writes exactly `PUT `, the first `n` bytes of `body`, and `\n`: an `n`
smaller than `strlen(body)` sends only `n` bytes, and NUL bytes inside
`body` go out as they are. A 1 MiB body arrives whole, as one line. The
prefix goes out as given: `PUT` and `abc` make `PUTabc`, with no space
added.

Code: `s04_send.py::t039`.

**T-040 — A zero-length body never touches the pointer.**
`proto_send_prefixed` with `body == NULL` and `body_len == 0` writes the
prefix and `\n`, and returns `PROTO_OK`.

Code: `s04_send.py::t040`.

**T-041 — An empty prefix writes the body and a newline.**
`proto_send_prefixed` with the prefix `""` writes the body and `\n`.

Code: `s04_send.py::t041`.

**T-042 — Short writes are resumed.**
A `send` seam on `wire.c` that moves at most 7 bytes per call, and a
single byte on every third call: `PROTO_OK`, and the reader gets the
line byte-exact, for both `proto_send_line` and `proto_send_prefixed`. A
blocking socket seldom writes short on its own, so the seam is the
deterministic form; T-043 is the real-socket one. (seam)

Code: `s04_send.py::t042`.

**T-043 — A signal during a large write neither fails it nor repeats bytes.**
An 8 MiB line over a socketpair whose `SO_SNDBUF` is shrunk to
4 KiB, with a reader draining it as fast as it can, while `setitimer`
fires `SIGALRM` every millisecond into a handler installed without
`SA_RESTART`: `PROTO_OK`, byte-exact, nothing sent twice. This covers
`EINTR` and the partial counts a signal leaves.

Code: `s04_send.py::t043`.

**T-044 — Writing to a closed peer returns `PROTO_E_WRITE`, not `SIGPIPE`.**
With `SIGPIPE` at its default, sending to a socket whose peer has closed
returns `PROTO_E_WRITE` and the process lives (observed), for both
`proto_send_line` and `proto_send_prefixed`. The descriptor stays open
after the failure: the library never closes on error.

Code: `s04_send.py::t044`.

**T-045 — A peer that closes in the middle of a send is a failure.**
The peer closes during an 8 MiB send: `PROTO_E_WRITE`, never `PROTO_OK`,
and no `SIGPIPE`.

Code: `s04_send.py::t045`.

**T-046 — The client's signal dispositions are untouched.**
After T-044, `SIGPIPE` is still at its default: the library protects
each call and installs nothing.

Code: `s04_send.py::t046`.

**T-047 — A bad descriptor returns `PROTO_E_WRITE`.**
fd -1 and a closed fd return `PROTO_E_WRITE`, without a crash.

Code: `s04_send.py::t047`.

**T-048 — A non-blocking socket with a full send buffer returns `PROTO_E_WRITE`.**
**Pin.** `EAGAIN` counts as failure. Non-blocking
sockets are outside the contract; the test pins that the call fails
cleanly rather than spinning.

Code: `s04_send.py::t048`.

**T-049 — A line that contains `\n` goes out as it is.**
**Pin.** The peer reads two lines. `docs.md` says the line "must not
contain \n", but nothing checks it. Decide: refuse it with
`PROTO_E_PARAM`. That would stop an application that puts client input
into a `FAIL` reason from letting the client inject a line.

Code: `s04_send.py::t049`.

**T-050 — A pipe can be written as well as read.**
**Fails today.** `proto_send_line` on a pipe returns `PROTO_E_WRITE`
(observed; `send()` fails with `ENOTSOCK`), while the readers accept
pipes and `architecture.md` and `docs.md` give "a protocol tunnelled
through another program's stdin and stdout" as the reason the pipe
fallback exists. Decide: fall back to `write()` on `ENOTSOCK` (where
`MSG_NOSIGNAL` cannot help), or say that pipes are for reading in test
harnesses only. See T-381.

Code: `s04_send.py::t050`.

**T-051 — A `NULL` line is refused, not dereferenced.**
**Fails today.** `proto_send_line(fd, NULL)` dies of `SIGSEGV`
(observed), and so would `proto_send_prefixed` with a `NULL` prefix
(reasoned). Decide, for this one and T-174, T-198, T-290, T-063, T-229
and T-280 together: `PROTO_E_PARAM`, in the spirit of "Validate
parameters at entry instead of crashing on them" (`69769e8`), or a
precondition the documents state.

Code: `s04_send.py::t051`.

---

## V. `proto_recv_line`

**T-052 — A line is returned without its newline.**
`hello\n` returns 5 and `"hello"`.

Code: `s05_recv.py::t052`. Also run in every framing build by T-011.

**T-053 — An empty line is a valid message.**
`\n` returns 0 and `""`; three empty lines in a row are three calls
returning 0.

Code: `s05_recv.py::t053`. Also run in every framing build by T-011.

**T-054 — A `\r` before the newline is dropped.**
`abc\r\n` returns 3 and `"abc"`.

Code: `s05_recv.py::t054`. Also run in every framing build by T-011.

**T-055 — Every `\r` is dropped, not only the one before the newline.**
**Pin.** `a\rb\r\n` returns 2 and `"ab"` (observed). `wire.h` says "'\r'
is ignored on read"; the wire appendix of `docs.md` says "a lone \r
before it is tolerated". Decide the wording (T-414).

Code: `s05_recv.py::t055`. Also run in every framing build by T-011.

**T-056 — A NUL inside a line is kept.**
**Pin.** `ab\0cd\n` returns 5, but `strlen(buf) == 2` (observed), so
every `strcmp` in the handshake sees `"ab"` (T-237). Decide: refuse NUL
inside a line.

Code: `s05_recv.py::t056`. Also run in every framing build by T-011.

**T-057 — A line that exactly fills the buffer fits.**
`abcd\n` into `char[5]` returns 4, and the next line reads intact.
(observed) The v1.1 fix for the line that exactly filled the buffer and
was refused.

Code: `s05_recv.py::t057`. Also run in every framing build by T-011.

**T-058 — A `\r` at the limit is not a character.**
`abcd\r\n` into `char[5]` returns 4. (observed)

Code: `s05_recv.py::t058`. Also run in every framing build by T-011.

**T-059 — One character over is `PROTO_E_LINE_TOO_LONG`, and the rest stays unread.**
`abcde\n` into `char[5]` returns `PROTO_E_LINE_TOO_LONG`
with `buf == "abcd"`, and exactly one more character is consumed, so the
next read returns the empty rest `""`. (observed) The partial line comes
back NUL-terminated by design; the stream is past saving, and the caller
closes.

Code: `s05_recv.py::t059`. Also run in every framing build by T-011.

**T-060 — An exact fit followed by end of stream is `PROTO_E_PEER_CLOSED`.**
`abcd` and a close, into `char[5]`: `PROTO_E_PEER_CLOSED` with
`buf == "abcd"`. (observed)

Code: `s05_recv.py::t060`. Also run in every framing build by T-011.

**T-061 — A one-byte buffer holds only empty lines.**
With `bufsz == 1`: `\n` returns 0; `a\n` returns `PROTO_E_LINE_TOO_LONG`
with `buf == ""`; `\r\r\r\n` returns 0. (observed)

Code: `s05_recv.py::t061`. Also run in every framing build by T-011.

**T-062 — `bufsz == 0` returns `PROTO_E_PARAM` and writes nothing.**
`buf` is untouched, even when it is `NULL`. (observed) The v1.1 fix for
the out-of-bounds write.

Code: `s05_recv.py::t062`. Also run in every framing build by T-011.

**T-063 — `buf == NULL` with `bufsz > 0` crashes.**
**Pin.** Nothing checks it. Decided together with T-051.

Code: `s05_recv.py::t063`.

**T-064 — End of stream before any byte is `PROTO_E_PEER_CLOSED`.**
`buf == ""`: end of stream is told apart from an error, as v1.1
promised.

Code: `s05_recv.py::t064`. Also run in every framing build by T-011.

**T-065 — End of stream in the middle of a line is `PROTO_E_PEER_CLOSED`, with the partial line.**
`abc`, then a close:
`PROTO_E_PEER_CLOSED` and `buf == "abc"`.

Code: `s05_recv.py::t065`. Also run in every framing build by T-011.

**T-066 — A reset is `PROTO_E_READ`.**
TCP on loopback, the peer closes with `SO_LINGER {1, 0}`:
`PROTO_E_READ`. Closing a pipe's writer is not a read error but end of
stream (T-064).

Code: `s05_recv.py::t066`. Also run in every framing build by T-011.

**T-067 — A bad descriptor is `PROTO_E_READ`.**
fd -1 or a closed fd: `PROTO_E_READ`, with `buf` NUL-terminated.

Code: `s05_recv.py::t067`. Also run in every framing build by T-011.

**T-068 — Nothing of the next line is taken, on a socket.**
The peer sends `one\ntwo\nthree`; after `proto_recv_line` returns `one`,
a raw `recv(fd, ..., MSG_DONTWAIT)` returns exactly `two\nthree`. This
is the property the `MSG_PEEK` design exists for, and what lets an
application mix its own reads with the library's.

Code: `s05_recv.py::t068`. Also run in every framing build by T-011.

**T-069 — Nothing of the next line is taken, on a pipe.**
The same through the byte-at-a-time fallback. (observed: two lines read
back correctly)

Code: `s05_recv.py::t069`. Also run in every framing build by T-011.

**T-070 — A line that trickles in is assembled.**
One byte every 5 ms: the line is exact, and the call returns only once
the newline has arrived.

Code: `s05_recv.py::t070`. Also run in every framing build by T-011.

**T-071 — Three lines in one segment are read separately.**
`a\nb\nc\n` in a single `send`: three calls return `a`, `b` and `c`.

Code: `s05_recv.py::t071`. Also run in every framing build by T-011.

**T-072 — On a pipe, the peek is tried once per line.**
Counting calls with `-Drecv=count_recv -Dread=count_read` on `wire.c`: a
1000-byte line costs exactly one `recv`, the failed peek, and 1001
`read`s. The verdict lasts one line, so every line read from a pipe
starts with one failed peek. (seam)

Code: `s05_recv.py::t072`.

**T-073 — On a socket, a large line costs a few calls, not one per byte.**
A 1 MiB line costs one `recv` and one `read` per piece the socket holds:
34 calls over TCP loopback, and 258 on a macOS socketpair, whose buffer
is 8 KiB (both observed, the line intact). Gate at fewer than 1000
calls, against 1048577 one byte at a time. Counting calls is
deterministic where timing is not, so this protects the v1.1 speed-up
(1.2 s to 3 ms) without a clock. The line is 16 times `READ_CHUNK`, so
it also checks, byte for byte, a line assembled across chunks. (seam)

Code: `s05_recv.py::t073`.

**T-074 — A signal does not fail a blocked read.**
`SIGALRM` without `SA_RESTART` fires during the wait, and the line
arrives later: the call returns the line, not `PROTO_E_READ`.

Code: `s05_recv.py::t074`. Also run in every framing build by T-011.

**T-075 — A non-blocking socket with nothing to read is `PROTO_E_READ`.**
**Pin.** `EAGAIN` is a failure. Non-blocking sockets are outside the
contract.

Code: `s05_recv.py::t075`. Also run in every framing build by T-011.

**T-076 — An application's `SO_RCVTIMEO` becomes `PROTO_E_READ`.**
**Pin.** On a socket where the application set `SO_RCVTIMEO`, a silent
peer yields `PROTO_E_READ` when the kernel's timeout fires, not
`PROTO_E_TIMEOUT`. Decide whether `EAGAIN` on a blocking read maps to
`PROTO_E_TIMEOUT`.

Code: `s05_recv.py::t076`. Also run in every framing build by T-011.

**T-077 — Every byte value except `\n` and `\r` passes unchanged.**
A 254-byte line of `0x00` to `0xFF` without those two reads back intact.
A line of one space reads back as one space, length 1: whitespace is
content.

Code: `s05_recv.py::t077`. Also run in every framing build by T-011.

**T-078 — The handshake's own buffer holds 16383 characters.**
With `char[MAX_LINE]`, a line of 16383 characters fits, and one of 16384
is `PROTO_E_LINE_TOO_LONG`.

Code: `s05_recv.py::t078`. Also run in every framing build by T-011.

**T-079 — `buf` is NUL-terminated on every way out.**
With `buf` filled with `'Z'` beforehand, after `PROTO_E_LINE_TOO_LONG`,
`PROTO_E_PEER_CLOSED`, `PROTO_E_READ` and `PROTO_E_TIMEOUT` the string
ends where the received text ends, not at `buf[bufsz-1]`.

Code: `s05_recv.py::t079`. Also run in every framing build by T-011.

---

## VI. `proto_recv_line_timeout`

**T-080 — A line already waiting is returned at once.**
With `ms = 1000` and the line in the socket, the call returns it without
waiting.

Code: `s06_timeout.py::t080`. Also run in every framing build by T-011.

**T-081 — A silent peer is `PROTO_E_TIMEOUT` at the deadline.**
`ms = 300`: `PROTO_E_TIMEOUT` within [300, 400] ms, with `buf == ""`.

Code: `s06_timeout.py::t081`. Also run in every framing build by T-011.

**T-082 — The deadline covers the line, not each byte.**
A trickle of one byte every 50 ms with `ms = 300`: `PROTO_E_TIMEOUT` at
about 300 ms, although bytes keep arriving. `buf` holds the bytes
received so far, which are consumed; the bytes still to come stay in the
socket, so the stream is no longer at a line boundary and the
application should close.

Code: `s06_timeout.py::t082`. Also run in every framing build by T-011.

**T-083 — Signals do not stretch the deadline.**
`SIGALRM` every 10 ms without `SA_RESTART`, a silent peer, `ms = 300`:
`PROTO_E_TIMEOUT` at about 300 ms, not later. The time left is
recomputed after every interruption.

Code: `s06_timeout.py::t083`. Also run in every framing build by T-011.

**T-084 — Nor do signals cut the deadline short.**
The same, with the line arriving at 150 ms: the line.

Code: `s06_timeout.py::t084`. Also run in every framing build by T-011.

**T-085 — `ms < 0` means no deadline.**
With -1 and with `INT_MIN`, the call behaves as `proto_recv_line`: a
writer that sends after 1.5 s is waited for.

Code: `s06_timeout.py::t085`. Also run in every framing build by T-011.

**T-086 — `ms == 0` is `PROTO_E_TIMEOUT` even when a whole line is waiting.**
**Pin.** It consumes nothing; `ms == 1` then reads the line
(observed). `docs.md` defines only `ms < 0`, and `proto_close` relies on
0 meaning "do not wait" (`QUIT_TIMEOUT_MS=0`). Decide, and document
either "0 gives up at once" or "0 takes a line only if it is already
complete".

Code: `s06_timeout.py::t086`. Also run in every framing build by T-011.

**T-087 — `ms = INT_MAX` does not overflow the deadline.**
With a line waiting, the call returns the line.

Code: `s06_timeout.py::t087`. Also run in every framing build by T-011.

**T-088 — The deadline wins over a full buffer.**
`bufsz` 5, the peer sends `abcd` and goes quiet, `ms = 200`:
`PROTO_E_TIMEOUT`, not `PROTO_E_LINE_TOO_LONG`, with `buf == "abcd"`.

Code: `s06_timeout.py::t088`. Also run in every framing build by T-011.

**T-089 — A close during the wait is reported at once.**
`PROTO_E_PEER_CLOSED` when the peer closes, not at the deadline.

Code: `s06_timeout.py::t089`. Also run in every framing build by T-011.

**T-090 — An oversized line under a deadline is refused at once.**
`PROTO_E_LINE_TOO_LONG` as soon as the buffer overflows, not at the
deadline.

Code: `s06_timeout.py::t090`. Also run in every framing build by T-011.

**T-091 — Pipes honour the deadline.**
A silent pipe with `ms = 200` gives `PROTO_E_TIMEOUT`; a pipe holding a
line gives the line.

Code: `s06_timeout.py::t091`. Also run in every framing build by T-011.

**T-092 — Under a deadline a closed descriptor fails at once, but fd -1 waits.**
**Pin.** A closed descriptor is `PROTO_E_READ` at once
(observed: 0 ms; `poll` reports `POLLNVAL`). But fd -1 waits out the
whole deadline and returns `PROTO_E_TIMEOUT` (observed: 302 ms for 300),
because `poll` ignores negative descriptors, while without a deadline
the same call gives `PROTO_E_READ` (T-067). Decide: refuse `fd < 0` at
entry.

Code: `s06_timeout.py::t092`. Also run in every framing build by T-011.

**T-093 — The deadline runs on the monotonic clock.**
Setting the wall clock back an hour during a 500 ms wait changes
nothing. (root)

Code: `s06_timeout.py::t093`.

---

## VII. `proto_recv_line_dyn`, `proto_recv_line_dyn_status`

**T-094 — A short line comes back as a heap string, with `PROTO_OK`.**
`*status`, set to 999 beforehand to see it written, is `PROTO_OK`
(observed); the string is NUL-terminated and freed with no LSan report.

Code: `s07_dyn.py::t094`. Also run in every framing build by T-011.

**T-095 — An empty line is an empty string, not `NULL`.**
`\n` returns `""` with `PROTO_OK`. (observed)

Code: `s07_dyn.py::t095`. Also run in every framing build by T-011.

**T-096 — End of stream first is `NULL` with `PROTO_E_PEER_CLOSED`.**
The peer closes before sending anything. (observed)

Code: `s07_dyn.py::t096`. Also run in every framing build by T-011.

**T-097 — End of stream in the middle of a line discards the partial line.**
`NULL` and `PROTO_E_PEER_CLOSED`; the bytes received are freed, not
returned. (observed)

Code: `s07_dyn.py::t097`. Also run in every framing build by T-011.

**T-098 — Exactly `MAX_PAYLOAD` characters are accepted.**
Observed at `MAX_PAYLOAD=64`, where lines of 63 and 64 characters pass;
also run at the default 16 MiB.

Code: `s07_dyn.py::t098`. Also run in every framing build by T-011.

**T-099 — `MAX_PAYLOAD + 1` characters are refused, and only those are consumed.**
`NULL`, `PROTO_E_LINE_TOO_LONG`, and only `MAX_PAYLOAD + 1`
characters consumed: the next read returns what followed (observed: the
empty rest). At `MAX_PAYLOAD=64`, 65 characters are refused. The reader
does not drain the line; the caller answers and closes.

Code: `s07_dyn.py::t099`. Also run in every framing build by T-011.

**T-100 — `\r`s do not count toward the cap.**
At `MAX_PAYLOAD=64`, 64 characters with 16 `\r`s among them are
accepted. (observed)

Code: `s07_dyn.py::t100`. Also run in every framing build by T-011.

**T-101 — The cap is exact however the bytes arrive.**
The 64/65 boundary holds when the peer writes pieces of 1, 3 and 1000
bytes, and in builds with `READ_CHUNK` 1 and 3 (observed for the
`READ_CHUNK` builds).

Code: `s07_dyn.py::t101`.

**T-102 — Pipes work through the fallback, limits included.**
The tests above pass on a pipe as on a socket. (observed)

Code: `s07_dyn.py::t102`.

**T-103 — `proto_recv_line_dyn` is `proto_recv_line_dyn_status` without a status.**
On the same inputs, `proto_recv_line_dyn(fd)` returns
exactly what `proto_recv_line_dyn_status(fd, NULL)` returns, and a
`NULL` status pointer never crashes.

Code: `s07_dyn.py::t103`.

**T-104 — The buffer starts at 4096 bytes and doubles.**
A 1 MiB line costs at most nine `realloc` calls; a 3 KiB line costs one
`malloc` and no `realloc`. (seam)

Code: `s07_dyn.py::t104`.

**T-105 — Memory is bounded by the cap.**
A peer that streams `a` and never sends a newline, at the default cap:
`PROTO_E_LINE_TOO_LONG` after 16 MiB + 1 characters, and no allocation
ever exceeds `MAX_PAYLOAD + 2` bytes. The v1.1 fix for a line that could
be made to allocate without end. (seam)

Code: `s07_dyn.py::t105`.

**T-106 — A failed first `malloc` is `PROTO_E_NOMEM`, and nothing is read.**
`NULL`, `PROTO_E_NOMEM`, and the line is still in the socket. (seam)

Code: `s07_dyn.py::t106`.

**T-107 — A failed `realloc` is `PROTO_E_NOMEM`, and the buffer is freed.**
`NULL`, `PROTO_E_NOMEM`, and LSan sees the old buffer freed. (seam)

Code: `s07_dyn.py::t107`.

**T-108 — A reset is `NULL` with `PROTO_E_READ`.**
The peer closes with `SO_LINGER {1, 0}` in the middle of a line.

Code: `s07_dyn.py::t108`. Also run in every framing build by T-011.

**T-109 — A NUL inside a line ends it, for the caller.**
**Pin.** The returned buffer holds the NUL and what follows, but the
function returns no length, so the caller sees the line end at the NUL.
Harmless for base64 payloads. Decided together with T-056.

Code: `s07_dyn.py::t109`. Also run in every framing build by T-011.

**T-110 — Many lines of random lengths on one stream come back exact.**
1000 lines of 0 to 10000 characters: each returned exactly, none merged
or split.

Code: `s07_dyn.py::t110`.

**T-111 — The fixed and the heap readers mix on one stream.**
As in the "Read a list response" recipe: the header with
`proto_recv_line`, the rows with `proto_recv_line_dyn`; every line
exact.

Code: `s07_dyn.py::t111`. Also run in every framing build by T-011.

---

## VIII. `proto_keepalive`

**T-112 — On a TCP socket, the three knobs are set and read back.**
`proto_keepalive(fd, 10, 5, 3)` returns `PROTO_OK` (observed);
`getsockopt` reads back `SO_KEEPALIVE == 1` and 10, 5 and 3 through the
idle knob of the platform (`TCP_KEEPIDLE` on Linux, `TCP_KEEPALIVE` on
macOS), `TCP_KEEPINTVL` and `TCP_KEEPCNT`. `SO_RCVTIMEO` and
`SO_SNDTIMEO` stay zero: keepalive is not a read timeout.

Code: `s08_keepalive.py::t112`.

**T-113 — Zero or negative values mean "system default".**
`(0, 0, 0)` and `(-1, -1, -1)` return `PROTO_OK` with
`SO_KEEPALIVE == 1`, and the three knobs equal to those of a fresh
socket.

Code: `s08_keepalive.py::t113`.

**T-114 — One positive value changes one knob.**
`(0, 5, 0)` changes the interval only.

Code: `s08_keepalive.py::t114`.

**T-115 — Not a socket is `PROTO_E_KEEPALIVE`.**
A pipe (observed), fd -1 (observed) and a regular file. Here, as in
T-112 and T-116, the descriptor stays open on return.

Code: `s08_keepalive.py::t115`.

**T-116 — An `AF_UNIX` socket gets `PROTO_KEEPALIVE_DEFAULTED` on macOS.**
**Pin.** `SO_KEEPALIVE` is accepted and the TCP knobs refused
(observed), so a socketpair is no place to test keepalive. Record Linux.

Code: `s08_keepalive.py::t116`.

**T-117 — Out-of-range knobs: one expectation per platform.**
**Pin.** macOS accepts an idle time of 40000 s and a count of 1000
(observed `PROTO_OK`) and refuses `INT_MAX` (observed
`PROTO_KEEPALIVE_DEFAULTED`); Linux caps idle time and interval at 32767
and the count at 127 (reasoned from the kernel), so
`PROTO_KEEPALIVE_DEFAULTED` there. (Linux, macOS)

Code: `s08_keepalive.py::t117`.

**T-118 — `PROTO_KEEPALIVE_DEFAULTED` leaves probing on.**
After a refused knob, `SO_KEEPALIVE == 1`, and the knobs that were
accepted hold their values.

Code: `s08_keepalive.py::t118`.

**T-119 — A second call replaces the first.**
Called again on the same fd with other values, it returns `PROTO_OK` and
the new values hold.

Code: `s08_keepalive.py::t119`.

**T-120 — A peer that vanishes is detected.**
`(1, 1, 2)` on an established connection inside a network namespace,
then its packets dropped with `nft`: a blocked `proto_recv_line` returns
`PROTO_E_READ` within about 4 s. Killing the peer process is not this
test: its socket closes, and the read sees end of stream at once.
(Linux, root, slow)

Code: `s08_keepalive.py::t120`.

**T-121 — Where `docs.md` says to call it, it works.**
On `conn.fd` after `proto_connect` and on the handler's fd, it returns
`PROTO_OK` and the session carries on.

Code: `s08_keepalive.py::t121`.

**T-122 — No keepalive unless asked.**
`SO_KEEPALIVE == 0` on `conn.fd` after `proto_connect`, and on the
handler's fd under `proto_serve`.

Code: `s08_keepalive.py::t122`.

---

## IX. Key files

**T-123 — A valid key with a trailing newline loads.**
`PROTO_OK` from both loaders.

Code: `s09_keyfiles.py::t123`.

**T-124 — A valid key without a trailing newline loads.**
`PROTO_OK`: the end of the file ends the line.

Code: `s09_keyfiles.py::t124`.

**T-125 — A key with CRLF, or with several CRs, loads.**
`KEY\r\n` and `KEY\r\r\n` give `PROTO_OK`.

Code: `s09_keyfiles.py::t125`.

**T-126 — Only the first line is read.**
The key on line 1 and anything on the lines after it: `PROTO_OK`. That
includes the label line `TODO.md` designs for v2.0, the kind of key and
the SHA-256 of `auth_pk` (`# enc.key 3f9a...`), in all three files
(observed): v1.x must keep loading the files v2.0's `keygen` will write.

Code: `s09_keyfiles.py::t126`.

**T-127 — An empty file is `PROTO_E_KEY_EMPTY`.**
A file of zero bytes.

Code: `s09_keyfiles.py::t127`.

**T-128 — A blank first line is `PROTO_E_KEY_EMPTY`.**
`\n`, `\r\n`, or only spaces and tabs (`"   \n"`, `"\t\t\n"`). Catches a
regression that decodes whitespace as base64.

Code: `s09_keyfiles.py::t128`.

**T-129 — A blank first line with the key on the second is `PROTO_E_KEY_EMPTY`.**
Only the first line counts (T-126).

Code: `s09_keyfiles.py::t129`.

**T-130 — A space or a tab around the key is `PROTO_E_KEY_STRAY`.**
Four files: a space before the key, a space after it, a tab before, a
tab after.

Code: `s09_keyfiles.py::t130`.

**T-131 — A UTF-8 byte order mark is `PROTO_E_KEY_STRAY`.**
`EF BB BF` before the key, invisible in an editor.

Code: `s09_keyfiles.py::t131`.

**T-132 — A non-breaking space is `PROTO_E_KEY_STRAY`.**
`C2 A0` after the key, and before it.

Code: `s09_keyfiles.py::t132`.

**T-133 — A quoted key is `PROTO_E_KEY_STRAY`.**
In double quotes and in single quotes.

Code: `s09_keyfiles.py::t133`.

**T-134 — A space inside the key is `PROTO_E_KEY_FORMAT`.**
Both edges are base64 characters, so the inside decides.

Code: `s09_keyfiles.py::t134`.

**T-135 — A character outside the alphabet, inside the key, is `PROTO_E_KEY_FORMAT`.**
`*`, `.`, `-` and `_` in the middle of the line.
URL-safe base64 is not accepted.

Code: `s09_keyfiles.py::t135`.

**T-136 — URL-safe base64 is `PROTO_E_KEY_FORMAT` wherever its `-` or `_` falls.**
**Fails today.** (minor) A key that begins or ends with `-`
or `_` is `PROTO_E_KEY_STRAY`, "stray characters around the key (a
space, a tab or an invisible mark)" (observed), while `docs.md` puts the
URL-safe variant under `PROTO_E_KEY_FORMAT`. Decide: check the alphabet
before the edges, or change the wording.

Code: `s09_keyfiles.py::t136`.

**T-137 — Missing padding is `PROTO_E_KEY_FORMAT`.**
A 32-byte key in 43 characters, without its `=`.

Code: `s09_keyfiles.py::t137`.

**T-138 — One `=` too many is `PROTO_E_KEY_FORMAT`.**
A 32-byte key ending in `==`.

Code: `s09_keyfiles.py::t138`.

**T-139 — A non-canonical spelling is `PROTO_E_KEY_FORMAT`.**
The unused bits of the last character set (observed): a key has one
spelling.

Code: `s09_keyfiles.py::t139`.

**T-140 — Valid base64 of the wrong size is `PROTO_E_KEY_SIZE`.**
31, 33 and 64 bytes where 32 belong, and 32 where 64 belong.

Code: `s09_keyfiles.py::t140`.

**T-141 — A first line longer than the 511-byte window is refused safely.**
600 `A`s give `PROTO_E_KEY_FORMAT`; 508 `A`s, valid base64 of 381 bytes,
give `PROTO_E_KEY_SIZE` (both observed); clean under ASan.

Code: `s09_keyfiles.py::t141`.

**T-142 — A huge file is refused quickly.**
A 100 MB file with no newline is refused in well under a second: the
reader stops at 511 bytes.

Code: `s09_keyfiles.py::t142`.

**T-143 — A NUL byte after the key is refused.**
**Fails today.** `KEY\0junk\n` loads as `PROTO_OK` (observed): `strcspn`
stops at the NUL, so nothing after it is looked at. The format is "the
key alone on its line". Expect `PROTO_E_KEY_STRAY`.

Code: `s09_keyfiles.py::t143`.

**T-144 — A UTF-16 file gets one diagnosis, whatever its byte order.**
**Fails today.** (minor) Big-endian without a byte order mark is
`PROTO_E_KEY_EMPTY`, "first line is blank" (observed), which sends the
user to a file that looks fine; little-endian with a mark is
`PROTO_E_KEY_STRAY` (observed). Expect one code for both, through the
same NUL check as T-143.

Code: `s09_keyfiles.py::t144`.

**T-145 — A path that leads nowhere is `PROTO_E_KEY_NOT_FOUND`.**
A missing file; a component that is a file (`auth.key/x`, `ENOTDIR`); a
dangling symlink; a symlink loop (`ELOOP`); a component longer than
`NAME_MAX` (`ENAMETOOLONG`); a whole path longer than `PATH_MAX`. Before
v1.2 all of these were `PROTO_E_KEY_OPEN`, the code that moved.

Code: `s09_keyfiles.py::t145`.

**T-146 — A symlink to a valid key loads.**
`PROTO_OK`: the loader follows links.

Code: `s09_keyfiles.py::t146`.

**T-147 — No permission is `PROTO_E_KEY_DENIED`.**
Mode 000, and a parent directory without search permission. (not as
root)

Code: `s09_keyfiles.py::t147`.

**T-148 — A path that is not a regular file is `PROTO_E_KEY_NOT_FILE`.**
A directory and `/dev/null` (both observed), `/dev/zero`, a FIFO with no
writer (observed; it must return at once, so run it under `alarm(2)`),
and a FIFO a writer holds open. The `O_NONBLOCK` open keeps a FIFO from
hanging, and `fstat` refuses it before a byte is read.

Code: `s09_keyfiles.py::t148`.

**T-149 — A Unix-domain socket at the path is `PROTO_E_KEY_NOT_FILE`.**
**Fails today.** It is `PROTO_E_KEY_OPEN` (observed on macOS, where
`open()` fails with `EOPNOTSUPP`; Linux fails with `ENXIO`, which lands
on the same code, reasoned). `PROTO_E_KEY_OPEN` now means "out of
descriptors or memory", the wrong place to look. Fix: map those two
errors, or `stat()` the path when `open()` fails.

Code: `s09_keyfiles.py::t149`.

**T-150 — Out of descriptors is `PROTO_E_KEY_OPEN`.**
`RLIMIT_NOFILE` lowered to what is already open: the cause that code
still covers.

Code: `s09_keyfiles.py::t150`.

**T-151 — A failing `read()` is `PROTO_E_KEY_READ`.**
`-Dread=fault_read` on `crypto.c` makes the first `read` fail with
`EIO`; a key file is read in one call, so the first is the one that
matters. On Linux, `/proc/self/mem` is also a regular file whose first
read fails. (seam)

Code: `s09_keyfiles.py::t151`.

**T-152 — `EINTR` during the read is retried.**
`read()` fails with `EINTR` once and then delivers the data: `PROTO_OK`.
(seam)

Code: `s09_keyfiles.py::t152`.

**T-153 — A key delivered one byte per `read()` loads.**
The loop assembles the line and stops at the newline: `PROTO_OK`. (seam)

Code: `s09_keyfiles.py::t153`.

**T-154 — No descriptor leaks.**
The count of open fds is the same before and after every outcome in this
section.

Code: `s09_keyfiles.py::t154`.

**T-155 — The file is opened read-only, non-blocking and close-on-exec.**
An `open` seam sees `O_RDONLY | O_NONBLOCK | O_CLOEXEC`. (seam)

Code: `s09_keyfiles.py::t155`.

**T-156 — The key's text is wiped on every way out.**
With `-Dsodium_memzero=spy_memzero` on `crypto.c`, the 512-byte line
buffer, on the stack, is wiped on every way out once it held data (OK,
EMPTY, STRAY, FORMAT, SIZE, a failing `read`), and the decoding buffer
on the decoding paths (OK, FORMAT, SIZE). The check `RELEASE_NOTES.md`
describes for v1.2, made permanent. (seam)

Code: `s09_keyfiles.py::t156`.

**T-157 — A failed load leaves the caller's buffer alone.**
`hex_out`, filled with `'Z'` beforehand, is unchanged after every
failure code of `proto_load_pubkey_hex`.

Code: `s09_keyfiles.py::t157`.

**T-158 — A relative path resolves against the working directory.**
As the FAQ on `PROTO_E_KEY_NOT_FOUND` explains. It runs in a child of
its own, since it changes directory.

Code: `s09_keyfiles.py::t158`.

---

## X. `proto_load_keys`

**T-159 — The files `keygen` writes load, and the public keys are derived.**
`PROTO_OK`; `auth_pk` equals the last 32 bytes of `auth_sk`; `enc_pk`
equals `crypto_scalarmult_base(enc_sk)`; `hex(auth_pk)` equals what
`proto_load_pubkey_hex` reads from `auth.pub`.

Code: `s10_loadkeys.py::t159`.

**T-160 — Keys made with plain libsodium load.**
`crypto_sign_keypair` and `crypto_box_keypair`, each written in base64:
"any other tool works", as `docs.md` says.

Code: `s10_loadkeys.py::t160`.

**T-161 — A damaged public half of `auth.key` is `PROTO_E_KEY_MISMATCH`.**
One base64 character changed in the public half: `PROTO_E_KEY_MISMATCH`,
and `out` all zero. A damaged key file says so where it is loaded, as
v1.1 promised.

Code: `s10_loadkeys.py::t161`.

**T-162 — Swapped paths are `PROTO_E_KEY_SIZE`.**
The two paths swapped, and the same path given twice:
`PROTO_E_KEY_SIZE`, `out` all zero (observed for the same path).

Code: `s10_loadkeys.py::t162`.

**T-163 — A failed load leaves nothing in `out`.**
A good `auth.key` and a bad `enc.key` (missing, empty, wrong size,
damaged): `out`, filled with `0xAA` beforehand, is all zero afterwards,
so the secret key that loaded first is not left behind. Likewise a bad
`auth.key` with a good `enc.key`. The v1.2 fix.

Code: `s10_loadkeys.py::t163`.

**T-164 — `NULL` arguments are `PROTO_E_PARAM`.**
A `NULL` auth path or a `NULL` enc path: `PROTO_E_PARAM`, `out` all
zero. A `NULL` `out`: `PROTO_E_PARAM`, no crash.

Code: `s10_loadkeys.py::t164`.

**T-165 — All-zero keys load.**
**Pin.** An `enc.key` of 32 zero bytes loads (observed), and so does an
`auth.key` derived from a zero seed. A key of zeros is what a broken
generator writes. Decide: refuse it (a new code), or leave the matter to
`keygen`.

Code: `s10_loadkeys.py::t165`.

**T-166 — The code does not say which file failed.**
As documented: an equally bad `auth.key` and `enc.key` give the same
code, so a caller that needs to know loads the files one at a time.

Code: `s10_loadkeys.py::t166`.

**T-167 — The loader keeps no state.**
8 threads loading at once all succeed, TSan clean. Single-threaded too:
two identities loaded one after the other come back different, and the
same files loaded twice give the same bytes.

Code: `s10_loadkeys.py::t167`.

**T-168 — `auth.pub` given as `enc.key` is refused with `PROTO_E_KEY_PUBLIC`.**
`out`, filled with `0xAA` beforehand, is all
zero afterwards. The same for a copy of `auth.pub` under another name,
with CRLF, or without a newline (all observed): the key is compared, not
the file. Until `2ae04f5` it loaded as `PROTO_OK`, and anyone who knows
the identity, starting with the server that allowlists it, could open
every message the client sealed (observed: a probe derived the key from
`auth.pub` alone and read the plaintext).

Code: `s10_loadkeys.py::t168`.

**T-169 — No good key pair is refused as `PROTO_E_KEY_PUBLIC`.**
2000 fresh identities, made with `keygen`'s calls, all load (observed on
macOS), and each seals and opens a message. A comparison over too few
bytes would refuse some of them; 2000 is the count `RELEASE_NOTES.md`
reports.

Code: `s10_loadkeys.py::t169`.

**T-170 — Another identity's `auth.pub` given as `enc.key` still loads.**
(observed) Only the identity's own `auth.pub` can be told, as
`RELEASE_NOTES.md` says. Expected today; flip it when the labelled key
files of v2.0 land (`TODO.md`).

Code: `s10_loadkeys.py::t170`.

---

## XI. `proto_load_pubkey_hex`

**T-171 — `auth.pub` loads as 64 lowercase hex characters.**
The output is 64 lowercase hex characters and a NUL, equal to
`sodium_bin2hex` of the decoded key.

Code: `s10_loadkeys.py::t171`.

**T-172 — A buffer too small is `PROTO_E_BUFFER_TOO_SMALL`, without an abort.**
`hex_sz` 65 gives `PROTO_OK`; 64 and 0 give
`PROTO_E_BUFFER_TOO_SMALL`. The v1.1 fix: `sodium_bin2hex` used to
abort.

Code: `s10_loadkeys.py::t172`.

**T-173 — The size is checked before the path.**
**Pin.** A `NULL` path with `hex_sz` 10 gives
`PROTO_E_BUFFER_TOO_SMALL`; with 65, `PROTO_E_PARAM`.

Code: `s10_loadkeys.py::t173`.

**T-174 — A `NULL` `hex_out` is refused.**
**Fails today.** `hex_out == NULL` with `hex_sz >= 65` dies of `SIGSEGV`
inside `sodium_bin2hex` (observed). Expect `PROTO_E_PARAM`. Decided
together with T-051.

Code: `s10_loadkeys.py::t174`.

**T-175 — `auth.key` given as `auth.pub` is `PROTO_E_KEY_SIZE`.**
The client's secret copied to the server is refused: 64 bytes where 32
belong.

Code: `s10_loadkeys.py::t175`.

**T-176 — `enc.key` given as `auth.pub` loads.**
`PROTO_OK`: 32 bytes either way, and `docs.md` says this swap cannot be
caught. T-378 checks that the mistake then surfaces as
`PROTO_E_REJECTED` at connect. Expected today; flip it when the labelled
key files of v2.0 land (`TODO.md`).

Code: `s10_loadkeys.py::t176`.

**T-177 — `proto_serve` accepts the output as an allowlist.**
No `PROTO_E_BAD_ALLOWLIST`.

Code: `s10_loadkeys.py::t177`.

**T-178 — A larger buffer gets exactly 65 bytes.**
`hex_sz` 100, filled beforehand: exactly 65 bytes written, the rest
untouched.

Code: `s10_loadkeys.py::t178`.

---

## XII. `proto_seal`, `proto_seal_new`, `proto_unseal_new`

**T-179 — A sealed message opens to the same bytes.**
A round trip at lengths 0, 1, 2, 3, 4, 47, 48, 49, 255, 256, 4096, 65535
and 1 MiB: identical bytes, the exact `out_len`, and
`plain[out_len] == '\0'`.

Code: `s11_seal.py::t179`.

**T-180 — 16 MiB seals and opens.**
Identical, as `RELEASE_NOTES.md` claims. No wall-time bound: shared
runners and valgrind make one meaningless; T-420 reports times. (slow)

Code: `s11_seal.py::t180`.

**T-181 — Sealing is binary-safe, and the output is one clean line.**
Plaintext with NUL, `\n`, `\r` and `0xFF` bytes round-trips, and the
base64 never contains `\n`, `\r`, NUL or a space.

Code: `s11_seal.py::t181`.

**T-182 — The output is standard base64 of the documented length.**
Only `A-Z a-z 0-9 + / =`, and `strlen(out) == ceil((L + 48) / 3) * 4`,
the formula in `architecture.md`. An empty message gives the 64
characters of a 48-byte box.

Code: `s11_seal.py::t182`.

**T-183 — The same message sealed twice gives two different ciphertexts.**
A fresh ephemeral key each time; both open.

Code: `s11_seal.py::t183`.

**T-184 — `proto_seal` refuses a buffer one byte short, without an abort.**
Exactly
`sodium_base64_ENCODED_LEN(L + 48, sodium_base64_VARIANT_ORIGINAL)`
gives `PROTO_OK`; one byte less, and 0, give `PROTO_E_BUFFER_TOO_SMALL`,
with `out_b64` untouched. The v1.1 fix: two aborts became return values.

Code: `s11_seal.py::t184`.

**T-185 — A length no message can have is `PROTO_E_PARAM`, without an abort.**
With `msg == NULL`: `SIZE_MAX`, `SIZE_MAX - 47` (where the
sealed size wraps to 0) and `SEAL_MSG_MAX + 1` give `PROTO_E_PARAM`;
`SEAL_MSG_MAX` itself gives `PROTO_E_BUFFER_TOO_SMALL`, no abort (all
observed on 64 bits). The test recomputes `SEAL_MSG_MAX` from its
definition. The v1.2 fix: the size used to wrap and make libsodium
abort.

Code: `s11_seal.py::t185`.

**T-186 — The same boundaries hold in the 32-bit build.**
Where `SEAL_MSG_MAX` is about 3.2 GB: no `SIGABRT`. (Linux)

Code: `s11_seal.py::t186`.

**T-187 — `proto_seal_new` returns `NULL` for those lengths.**
No abort, no leak.

Code: `s11_seal.py::t187`.

**T-188 — A low-order public key is `PROTO_E_CRYPTO`.**
All zeros, or another small-order point: `proto_seal` returns
`PROTO_E_CRYPTO` and `proto_seal_new` returns `NULL` (observed for all
zeros). The one way to reach `PROTO_E_CRYPTO` from outside.

Code: `s11_seal.py::t188`.

**T-189 — A failed allocation is `PROTO_E_NOMEM`.**
`malloc` failing inside `proto_seal` gives `PROTO_E_NOMEM`; inside
`proto_seal_new`, `NULL`; no leak. (seam)

Code: `s11_seal.py::t189`.

**T-190 — The wrong secret key opens nothing.**
`NULL`, and `*out_len` keeps the value it had (observed: untouched on
failure). Sealed to one recipient, a message does not open for another.

Code: `s11_seal.py::t190`.

**T-191 — The right secret key with another public key opens nothing.**
`NULL`.

Code: `s11_seal.py::t191`.

**T-192 — Any flipped bit makes the open fail.**
One bit flipped in the ephemeral key, the MAC or the body: `NULL` every
time (positions sampled across the box).

Code: `s11_seal.py::t192`.

**T-193 — A truncated box opens nothing.**
Four characters off the end, a box shorter than 48 bytes, and `""`:
`NULL` (observed for `""`).

Code: `s11_seal.py::t193`.

**T-194 — Extra bytes make the open fail.**
`AAAA` appended: `NULL`.

Code: `s11_seal.py::t194`.

**T-195 — Bad encoding makes the open fail.**
Missing padding, the URL-safe alphabet, a space or a `\n` inside, a
trailing `\r`: `NULL`.

Code: `s11_seal.py::t195`.

**T-196 — The box of an empty message opens to `""`.**
48 bytes, opening to `""` with `out_len == 0`. (observed)

Code: `s11_seal.py::t196`.

**T-197 — `out_len == NULL` is accepted.**
The plaintext comes back NUL-terminated; a caller that needs the length
passes `out_len`.

Code: `s11_seal.py::t197`.

**T-198 — `proto_unseal_new(NULL, ...)` returns `NULL`.**
**Fails today.** It dies of `SIGSEGV` in `strlen` (observed), and `NULL`
keys would die inside libsodium (reasoned), while the header promises
"Returns NULL on error". Decided together with T-051.

Code: `s11_seal.py::t198`.

**T-199 — The output interoperates with plain libsodium.**
`proto_seal`'s output opens with raw `crypto_box_seal_open`, and raw
`crypto_box_seal` output in base64 opens with `proto_unseal_new`.

Code: `s11_seal.py::t199`.

**T-200 — `proto_seal` and `proto_seal_new` are interchangeable.**
Either output opens with `proto_unseal_new`; the heap string of
`proto_seal_new` is NUL-terminated and the caller's to free.

Code: `s11_seal.py::t200`.

**T-201 — Opening allocates what the documents say.**
Opening a line of `L` characters allocates about `L` for the decoded box
and `0.75 L` for the plaintext: the figures behind the "2.75 x
`MAX_PAYLOAD`" guidance. (seam)

Code: `s11_seal.py::t201`.

**T-202 — A failed open returns nothing and leaks nothing.**
LSan reports no leak after every failure in this section.

Code: `s11_seal.py::t202`.

---

## XIII. `proto_sign_challenge`, `proto_verify_challenge`

**T-203 — A signature verifies with the matching public key.**
Sign a 32-byte challenge, verify with the derived public key:
`PROTO_OK`.

Code: `s11_seal.py::t203`.

**T-204 — Signing is deterministic.**
The same key and challenge give the same signature, and another
challenge gives another one: Ed25519 has no random nonce.

Code: `s11_seal.py::t204`.

**T-205 — Signatures interoperate with plain libsodium.**
The signature equals the output of `crypto_sign_detached`, and verifies
with `crypto_sign_verify_detached`.

Code: `s11_seal.py::t205`.

**T-206 — Any flipped bit fails verification.**
One bit flipped in the signature, the challenge or the public key:
`PROTO_E_BAD_SIGNATURE`. A signature made for one challenge does not
verify for another.

Code: `s11_seal.py::t206`.

**T-207 — The length of the message is part of it.**
`clen` 31 or 33 against a signature of 32 bytes:
`PROTO_E_BAD_SIGNATURE`.

Code: `s11_seal.py::t207`.

**T-208 — Empty and large messages sign and verify.**
`clen == 0` signs and verifies, and so does a 1 MiB message.

Code: `s11_seal.py::t208`.

**T-209 — An all-zero signature with an all-zero key does not verify.**
`PROTO_E_BAD_SIGNATURE` (observed), and likewise with the other
small-order public keys.

Code: `s11_seal.py::t209`.

**T-210 — A non-canonical signature does not verify.**
`S + L` in place of `S`: `PROTO_E_BAD_SIGNATURE`. No malleability.

Code: `s11_seal.py::t210`.

**T-211 — Verification returns one of two codes.**
`PROTO_OK` or `PROTO_E_BAD_SIGNATURE` and nothing else, over 10^4 random
inputs.

Code: `s11_seal.py::t211`.

---

## XIV. `proto_auth_client`

**T-212 — The client speaks first, with exactly `HELLO\n`.**
The first bytes the scripted server reads are `HELLO\n`, and nothing
else is sent before the challenge.

Code: `s12_auth_client.py::t212`.

**T-213 — The `AUTH` line has the documented shape.**
`AUTH `, 44 characters, a space and 88 characters: 138 in all. The key
decodes to `keys->auth_pk`, and the signature verifies over the 32
decoded challenge bytes, not over their base64.

Code: `s12_auth_client.py::t213`.

**T-214 — `OK` is `PROTO_OK`.**
`OK` and `OK\r`. (observed)

Code: `s12_auth_client.py::t214`.

**T-215 — `REGISTER` is `PROTO_REGISTER_REQUESTED`.**
`REGISTER` and `REGISTER\r` (observed). The client does not take it for
`OK`.

Code: `s12_auth_client.py::t215`.

**T-216 — Anything else after `AUTH` is `PROTO_E_REJECTED`.**
`FAIL access denied`, `OK ` with a trailing space, `BYE` (all observed),
and an empty line.

Code: `s12_auth_client.py::t216`.

**T-217 — A `FAIL` in place of the challenge is `PROTO_E_REJECTED`.**
`FAIL server busy`, `FAIL internal error`, and `FAIL ` (observed for
`FAIL `).

Code: `s12_auth_client.py::t217`.

**T-218 — A bare `FAIL` in place of the challenge is `PROTO_E_UNEXPECTED_REPLY`.**
**Pin.** (observed) After `AUTH`, the same
line is `PROTO_E_REJECTED`. Decide whether `FAIL` without a reason is a
refusal.

Code: `s12_auth_client.py::t218`.

**T-219 — A reply that is neither `CHALLENGE` nor `FAIL` is `PROTO_E_UNEXPECTED_REPLY`.**
`CHALLENGE` without its space, a lowercase
`challenge x`, an empty line (observed), and `HI`.

Code: `s12_auth_client.py::t219`.

**T-220 — A malformed challenge is `PROTO_E_BAD_CHALLENGE`.**
Two spaces after `CHALLENGE` (observed), text that is not base64, 31
bytes, 33 bytes, a trailing space, missing padding, URL-safe characters.
A challenge shorter than 32 bytes, such as `CHALLENGE AA==`, is never
signed.

Code: `s12_auth_client.py::t220`.

**T-221 — The client signs any well-formed 32 bytes.**
**Pin.** An all-zero challenge included (observed: it answered with
`AUTH`). This is the behaviour behind the relay attack in `TODO.md`; the
test flips when v2.0 binds the signature to a context.

Code: `s12_auth_client.py::t221`.

**T-222 — Silence after `HELLO` is `PROTO_E_TIMEOUT`.**
After `HANDSHAKE_TIMEOUT_MS`, 300 ms in the fast build.

Code: `s12_auth_client.py::t222`.

**T-223 — Silence after `AUTH` is `PROTO_E_TIMEOUT`.**
The same deadline bounds every handshake read.

Code: `s12_auth_client.py::t223`.

**T-224 — A server that closes mid-handshake is `PROTO_E_PEER_CLOSED`.**
After `HELLO`, or after `AUTH`.

Code: `s12_auth_client.py::t224`.

**T-225 — A challenge line of 16384 characters or more is `PROTO_E_LINE_TOO_LONG`.**
The handshake reads into `char[MAX_LINE]`.

Code: `s12_auth_client.py::t225`.

**T-226 — The reason for a refusal can be read.**
**Fails today.** After `PROTO_E_REJECTED`, the `FAIL` line has been
consumed, and the next read times out (observed). `auth.c` says the
caller "can read [it] off the wire if it wants it", and the FAQ suggests
looking at which `FAIL` the server sends. Expect the reason to be
reachable (an out-parameter, a field in `proto_conn_t`), or the comment
corrected.

Code: `s12_auth_client.py::t226`.

**T-227 — A server that trickles bytes cannot hold the client past the deadline.**
One byte every 50 ms: `PROTO_E_TIMEOUT` at the deadline of
the line.

Code: `s12_auth_client.py::t227`.

**T-228 — A `FAIL` sent before `HELLO` is read gives one code or the other.**
**Pin.** A server that writes its `FAIL` and closes before
reading `HELLO`, as `proto_auth_server` does with an unusable allowlist
in a custom accept loop: the client reported `PROTO_E_REJECTED` in 18
runs out of 20 and `PROTO_E_WRITE` in 2 (observed), because `HELLO`
could not be sent and the `FAIL` already in the socket was never read.
Until this is decided the test accepts either code and records which;
afterwards it requires the decided one in 100 runs out of 100. Decide:
when `HELLO` cannot be sent, try to read a pending line.

Code: `s12_auth_client.py::t228`.

**T-229 — `keys == NULL` crashes after `HELLO` has gone out.**
**Pin.** Nothing checks it. Decided together with T-051.

Code: `s12_auth_client.py::t229`.

**T-230 — No secret crosses the wire.**
Capture every byte a client sends in a session with registration.
Neither `auth_sk`, its 32-byte seed, nor `enc_sk` appears, raw, in
base64 (standard or URL-safe) or in hex of either case. `enc_pk` appears
once, in the `REGISTER` line, and never when no registration was asked
for; `auth_pk` only in `AUTH`.

Code: `s12_auth_client.py::t230`.

---

## XV. `proto_auth_server`

**T-231 — A valid handshake returns the identity, on the heap.**
A string equal to `allowed_hex`, at another address, which the caller
frees with no LSan report.

Code: `s13_auth_server.py::t231`.

**T-232 — On success the server writes nothing after `CHALLENGE`.**
The `OK` or `REGISTER` verdict belongs to the handler, as in the
recipes. A handler that never writes leaves `proto_connect` to fail with
`PROTO_E_TIMEOUT`; test that, so the contract is written down somewhere.

Code: `s13_auth_server.py::t232`.

**T-233 — Every session gets a fresh challenge.**
`CHALLENGE ` and 44 characters that decode to 32 bytes: a line of 54
characters (observed). 100 sessions through `proto_serve`, each in a
fresh fork, give 100 different challenges: the random generator survives
`fork()`.

Code: `s13_auth_server.py::t233`.

**T-234 — A captured `AUTH` line cannot be replayed.**
An `AUTH` line captured in one session and replayed in another gets
`FAIL signature verification failed`. (observed) The property the
challenge exists to provide.

Code: `s13_auth_server.py::t234`.

**T-235 — A valid signature by a key that is not allowlisted is refused.**
`FAIL access denied`, and `NULL`.

Code: `s13_auth_server.py::t235`.

**T-236 — Anything but exactly `HELLO` is refused.**
`hello`, `HELLO `, `HELLO x` and an empty line get
`FAIL expected HELLO`: the check is `strcmp`, not a prefix.

Code: `s13_auth_server.py::t236`.

**T-237 — `HELLO\0junk` is taken for `HELLO`.**
**Pin.** (observed: the challenge follows) Decided together with T-056.

Code: `s13_auth_server.py::t237`.

**T-238 — A line that does not begin with `AUTH ` is refused.**
`FAIL expected AUTH` (observed for `auth ...`), a second `HELLO`
included.

Code: `s13_auth_server.py::t238`.

**T-239 — An `AUTH` line without its two fields is refused.**
One field only, or the two fields separated by a tab:
`FAIL invalid AUTH format` (observed for the tab).

Code: `s13_auth_server.py::t239`.

**T-240 — The spacing of `AUTH` is lenient.**
**Pin.** Extra spaces before, between and after the fields, and a third
field, are all accepted (observed: `OK` for `AUTH pk sig extra junk`,
`AUTH   pk    sig`, `AUTH pk sig ` and `AUTH  pk sig`). The appendix
says "fields separated by single spaces", and the key-file reader
refuses the same looseness. Decide: strict, or documented as lenient.

Code: `s13_auth_server.py::t240`.

**T-241 — A bad public key is refused.**
Not base64, URL-safe characters (`-`, `_`), or 31 or 33 bytes:
`FAIL invalid public key`.

Code: `s13_auth_server.py::t241`.

**T-242 — A bad signature is refused.**
Not base64, or 63 or 65 bytes: `FAIL invalid signature`.

Code: `s13_auth_server.py::t242`.

**T-243 — A signature over anything but this challenge is refused.**
Over another challenge, or over the challenge's base64 text:
`FAIL signature verification failed`.

Code: `s13_auth_server.py::t243`.

**T-244 — An all-zero key with an all-zero signature is refused.**
`FAIL signature verification failed`.

Code: `s13_auth_server.py::t244`.

**T-245 — An unusable allowlist is refused before anything is read.**
`NULL`, 63 and 65 characters, uppercase, a `g`, a NUL at position 32:
`FAIL internal error`, then `NULL`. The v1.1 fix for the segfault on an
unusable allowlist.

Code: `s13_auth_server.py::t245`.

**T-246 — A client that says nothing is sent a `FAIL`.**
**Fails today.** After `HANDSHAKE_TIMEOUT_MS` the child returns `NULL`
and the client sees end of stream, with no `FAIL` (observed); the same
after `CHALLENGE`. `docs.md` says "On every failure path a descriptive
`FAIL <reason>` line has already been sent", and `auth.h` says the same.
Decide: send `FAIL timeout`, or narrow the promise to protocol errors.

Code: `s13_auth_server.py::t246`.

**T-247 — An oversized `HELLO` or `AUTH` is answered with a `FAIL`.**
**Fails today.** A line of 16384 characters or more gives `NULL` and no
`FAIL`; and since the rest of the line is unread when the child closes,
the client gets a reset (observed `PROTO_E_READ`). The server allocates
nothing for it: the bound is `MAX_LINE`. Same decision as T-246; reading
on, within a bound, before closing is how the busy path avoids the same
reset.

Code: `s13_auth_server.py::t247`.

**T-248 — A client that leaves mid-handshake ends the child at once.**
A client that closes after `HELLO`: `NULL` at once.

Code: `s13_auth_server.py::t248`.

**T-249 — Nothing echoes the client, and every `FAIL` is the last line.**
Every line the server sends during the handshake is `CHALLENGE` with 44
characters, or `FAIL ` with one of the documented reasons, a property
also checked over the fuzz corpus (T-396). End of stream follows every
`FAIL`.

Code: `s13_auth_server.py::t249`.

**T-250 — A client that trickles bytes cannot keep the child past the deadline.**
`HANDSHAKE_TIMEOUT_MS` bounds each line, however slowly it
arrives.

Code: `s13_auth_server.py::t250`.

**T-251 — The identity is compared exactly.**
A key whose hex differs from the allowlist in its last digit gets
`FAIL access denied`.

Code: `s13_auth_server.py::t251`.

**T-252 — An allocation failure is answered with `FAIL internal error`.**
`strdup` or `malloc` failing: `FAIL internal error`, `NULL`, no leak.
(seam)

Code: `s13_auth_server.py::t252`.

**T-253 — The two halves of the library agree.**
`proto_auth_client` on one end of a socketpair and `proto_auth_server`
on the other, in two threads, with the server side then sending `OK` as
a handler would: the server returns the client's identity and the client
returns `PROTO_OK`. No network and no fork: the fastest check that a
change to one side did not break the other. It runs in the TSan job too
(T-392).

Code: `s13_auth_server.py::t253`.

---

## XVI. `proto_connect`

**T-254 — A full connection is `PROTO_OK` and fills the conn.**
Against `proto_serve` on `127.0.0.1` with a handler that sends `OK`:
`PROTO_OK`, `fd >= 0`, `identity_hex == hex(keys.auth_pk)`, and the
socket blocking again (observed: `O_NONBLOCK` clear).

Code: `s14_connect.py::t254`.

**T-255 — Registration is answered automatically.**
The handler sends `REGISTER`, reads `REGISTER <b64>` and answers `OK`:
`PROTO_OK`, not `PROTO_REGISTER_REQUESTED`. The line is exactly
`REGISTER ` and 44 characters, decoding to `keys.enc_pk`. The
application never sends it itself.

Code: `s14_connect.py::t255`.

**T-256 — A refused registration is `PROTO_E_REGISTER_REJECTED`.**
`FAIL no` after `REGISTER`: `PROTO_E_REGISTER_REJECTED`, `fd == -1`, and
the server sees the connection close.

Code: `s14_connect.py::t256`.

**T-257 — Only `OK` completes a registration.**
`OK\r` gives `PROTO_OK`; `OK extra` gives `PROTO_E_REGISTER_REJECTED`.

Code: `s14_connect.py::t257`.

**T-258 — Silence after `REGISTER` is `PROTO_E_TIMEOUT`.**
With `fd == -1`.

Code: `s14_connect.py::t258`.

**T-259 — An identity that is not allowlisted is `PROTO_E_REJECTED`.**
With `fd == -1` (observed): "access denied", told apart from "network
down".

Code: `s14_connect.py::t259`.

**T-260 — `identity_hex` is filled even when the handshake fails.**
**Pin.** (observed) `docs.md` lists it as the step after the handshake.

Code: `s14_connect.py::t260`.

**T-261 — An out-of-range port is `PROTO_E_BAD_PORT`, before any resolution.**
Ports 0, -1, 65536, 70000, `INT_MIN` and `INT_MAX`:
`PROTO_E_BAD_PORT`, and a `getaddrinfo` seam records no call. 70000 is
not folded to 4464. (seam)

Code: `s14_connect.py::t261`.

**T-262 — `PROTO_E_BAD_PORT` on a connected conn closes the old connection.**
**Fails today.** On a conn that holds a live connection,
the bad port leaves the connection open and `conn->fd` unchanged
(observed: still usable), while `docs.md` says "On failure `conn->fd` is
left at `-1` and the socket is closed". A later failure does close it
first (`PROTO_E_RESOLVE`, observed). Decide which behaviour the
documents describe.

Code: `s14_connect.py::t262`.

**T-263 — A name that does not resolve is `PROTO_E_RESOLVE`.**
`nonexistent.invalid`.

Code: `s14_connect.py::t263`.

**T-264 — `host == NULL` connects to the loopback.**
**Pin.** `proto_connect(&c, NULL, port)` reaches a local server and
returns `PROTO_OK` (observed): `getaddrinfo(NULL, ...)` without
`AI_PASSIVE` means the loopback. On macOS `host == ""` does the same
(observed); glibc likely answers `""` with `EAI_NONAME` (reasoned).
Decide: `PROTO_E_PARAM` for both.

Code: `s14_connect.py::t264`.

**T-265 — A closed port is `PROTO_E_CONNECT`, at once.**
On 127.0.0.1 (observed: 0 ms). No `TIME_WAIT` is needed: a closed port
refuses.

Code: `s14_connect.py::t265`.

**T-266 — Every address of a host is tried.**
`localhost` reaches a server that listens only on 127.0.0.1, even where
`::1` is listed first (observed `PROTO_OK`). The v1.1 fix: only the
first address used to be tried.

Code: `s14_connect.py::t266`.

**T-267 — Silence is `PROTO_E_CONNECT_TIMEOUT` after `CONNECT_TIMEOUT_MS`.**
500 ms in the fast build, for an address whose SYNs are dropped (see
*Silence* in the conventions). A full accept queue does not do it on
macOS: the connection completes and the handshake times out instead
(observed `PROTO_E_TIMEOUT`). The v1.1 fix: connecting had no deadline.
(Linux)

Code: `s14_connect.py::t267`.

**T-268 — The address walk ranks the outcomes.**
With a `getaddrinfo` seam that returns a crafted list: [refusing, good]
gives `PROTO_OK`; [silent, good] gives `PROTO_OK` after about
`CONNECT_TIMEOUT_MS`; [silent, refusing] gives `PROTO_E_CONNECT`, since
a refusal outweighs silence; [silent, silent] gives
`PROTO_E_CONNECT_TIMEOUT` after about twice `CONNECT_TIMEOUT_MS`, since
the deadline is per address; [a family this host lacks, refusing] gives
`PROTO_E_CONNECT`; [a family this host lacks] alone gives
`PROTO_E_SOCKET`. A `socket` seam that fails for every family gives
`PROTO_E_SOCKET` as well. (seam)

Code: `s14_connect.py::t268`.

**T-269 — An interrupted `connect()` is waited for.**
`EINTR` from `connect()` is treated as `EINPROGRESS`: `PROTO_OK`. (seam)

Code: `s14_connect.py::t269`.

**T-270 — The kernel giving up first counts as silence.**
`SO_ERROR` equal to `ETIMEDOUT`: `PROTO_E_CONNECT_TIMEOUT`, not
`PROTO_E_CONNECT`. (seam)

Code: `s14_connect.py::t270`.

**T-271 — No descriptor leaks on failure.**
The count of open fds is unchanged after `PROTO_E_RESOLVE`,
`PROTO_E_CONNECT`, `PROTO_E_CONNECT_TIMEOUT`, `PROTO_E_SOCKET`,
`PROTO_E_REJECTED`, `PROTO_E_TIMEOUT` and `PROTO_E_REGISTER_REJECTED`,
and `conn->fd == -1` after each.

Code: `s14_connect.py::t271`.

**T-272 — Reconnecting on a live conn closes the old connection.**
The old socket receives `QUIT` and is closed, so its server child sees
`QUIT` and then end of stream, and the new socket works. 100 reconnects
leave the client's fd count and the server's child count flat: the v1.1
leak stays fixed.

Code: `s14_connect.py::t272`.

**T-273 — Reconnecting after the old connection died works.**
After a read returned `PROTO_E_PEER_CLOSED`, `proto_connect` again:
`PROTO_OK`, no `SIGPIPE`, and no `proto_close` needed first.

Code: `s14_connect.py::t273`.

**T-274 — A descriptor that is not a socket is left alone.**
A `{0}` conn with an ordinary stdin (a terminal, a file, a pipe):
`PROTO_OK`, and stdin is still open and unchanged. Any descriptor that
is not a socket is treated the same way: a pipe at fd 5 in `conn->fd`
stays open and is replaced.

Code: `s14_connect.py::t274`.

**T-275 — A `{0}` conn closes stdin when stdin is a socket.**
**Pin.** That socket receives `QUIT` and is closed, and the new
connection takes fd 0 (observed). The documented blind spot; the test
makes any change to it deliberate.

Code: `s14_connect.py::t275`.

**T-276 — A stale `conn->fd` that now holds an application's socket is closed.**
**Pin.** `QUIT` is written into it, and it is closed: the
documented precondition, "`-1` or a socket this library opened", in
executable form.

Code: `s14_connect.py::t276`.

**T-277 — The connection is close-on-exec.**
**Fails today.** `FD_CLOEXEC` is clear (observed), so a client that runs
another program (an editor, a helper, `system()`) hands it an
authenticated session. Fix: `SOCK_CLOEXEC`, or `fcntl` right after
`socket()`.

Code: `s14_connect.py::t277`.

**T-278 — Keys that were never loaded are not checked.**
**Pin.** An all-zero `conn.keys` gives `PROTO_E_REJECTED` after a whole
handshake (observed), not `PROTO_E_PARAM`. A server that asked for
registration would be sent an all-zero, low-order `enc_pk` that nobody
can seal to (T-188). Decide whether `proto_connect` checks.

Code: `s14_connect.py::t278`.

**T-279 — The client's signal dispositions are unchanged.**
`SIGPIPE` and `SIGCHLD` are as before after connecting, failing and
closing.

Code: `s14_connect.py::t279`.

**T-280 — `conn == NULL` crashes for a valid port.**
**Pin.** For an invalid one, `PROTO_E_BAD_PORT` comes first. Decided
together with T-051.

Code: `s14_connect.py::t280`.

**T-281 — The IPv6 path connects.**
Against a test peer that listens on `::1` and runs `proto_auth_server`
and an `OK`, `proto_connect(&c, "::1", port)` returns `PROTO_OK`.
`proto_serve` is IPv4 only, so this is the one place the client's IPv6
code runs to success. (IPv6)

Code: `s14_connect.py::t281`.

---

## XVII. `proto_close`

**T-282 — `proto_close` says `QUIT`, waits for one line, and closes.**
It writes `QUIT\n`, reads one line, closes, and sets `fd = -1`; the
server child sees `QUIT`, then end of stream. With a server that answers
`BYE`, the wire reads `QUIT`, `BYE`, end of stream.

Code: `s15_close.py::t282`.

**T-283 — A server that never answers costs `QUIT_TIMEOUT_MS`, no more.**
The call returns after `QUIT_TIMEOUT_MS` (observed: 201 ms for 200),
with `fd == -1`.

Code: `s15_close.py::t283`.

**T-284 — A dead peer costs no wait.**
The call returns at once and without `SIGPIPE`, whether the `QUIT` fails
or still goes out, as it usually does: the wait then ends on end of
stream or a reset.

Code: `s15_close.py::t284`.

**T-285 — A second call does nothing.**
It writes nothing and closes nothing. (observed)

Code: `s15_close.py::t285`.

**T-286 — `fd == -1` returns without a system call.**
Seams on `send` and `close` record no call. (seam)

Code: `s15_close.py::t286`.

**T-287 — `fd == 0` that is not a socket is left open.**
A `{0}` conn with stdin a terminal or a pipe: nothing written, nothing
closed, and `fd == -1` afterwards. The v1.1 fix.

Code: `s15_close.py::t287`.

**T-288 — `QUIT_TIMEOUT_MS=0` does not wait.**
In a `-DQUIT_TIMEOUT_MS=0` build, `proto_close` on a silent server
returns at once. It relies on T-086.

Code: `s15_close.py::t288`.

**T-289 — A long answer in place of `BYE` does not hold the close.**
An answer longer than 63 characters: the call returns at once, with
`fd == -1`.

Code: `s15_close.py::t289`.

**T-290 — `proto_close(NULL)` is a no-op.**
**Fails today.** It dies of `SIGSEGV` (observed). Cleanup code is where
a `NULL` is most likely. Decided together with T-051.

Code: `s15_close.py::t290`.

**T-291 — An unread reply is taken for the goodbye.**
**Pin.** With an application reply still unread, `proto_close` takes
that line for the goodbye and closes at once, leaving `BYE` unread.
Record whether the server child then sees a reset rather than end of
stream.

Code: `s15_close.py::t291`.

---

## XVIII. `proto_serve`

**T-292 — Arguments are checked in order, before any socket exists.**
The fd count is unchanged and the port still free after each: a `NULL`
allowlist, a `NULL` handler and port 0 give `PROTO_E_NO_ALLOWLIST`
(observed); a bad allowlist and a `NULL` handler,
`PROTO_E_BAD_ALLOWLIST`; a `NULL` handler and port 0,
`PROTO_E_NO_HANDLER`; port 0 and a bad address, `PROTO_E_BAD_PORT`; a
bad address and a negative `drain_ms`, `PROTO_E_BAD_ADDRESS` (observed);
a negative `drain_ms` alone, `PROTO_E_PARAM`.

Code: `s16_serve.py::t292`.

**T-293 — An allowlist that is not 64 lowercase hex characters is refused.**
`PROTO_E_BAD_ALLOWLIST` for uppercase (observed), 63 and 65 characters
(observed for 65), a letter that is not hex (`g`), and a NUL at
position 32.

Code: `s16_serve.py::t293`.

**T-294 — An out-of-range port is refused.**
Ports 0, -1, 65536 and 70000: `PROTO_E_BAD_PORT`. 70000 is not folded to
4464, and 0 does not ask the kernel for a port.

Code: `s16_serve.py::t294`.

**T-295 — `bind_addr` must be an IPv4 literal.**
`127.0.0.1` and `0.0.0.0` start (observed); `127.1`, ` 127.0.0.1`,
`127.0.0.1 `, `::1`, `""` and `localhost` give `PROTO_E_BAD_ADDRESS`
(observed). No name is resolved.

Code: `s16_serve.py::t295`.

**T-296 — Leading zeros in `bind_addr` get one verdict per platform.**
**Pin.** `127.000.000.001` starts on macOS, whose `inet_pton` accepts
leading zeros (observed), while the `inet_pton` of glibc and of musl
refuse them (reasoned from their sources): `PROTO_E_BAD_ADDRESS` on
Linux. One configuration, two verdicts. Decide: take the platform's
answer, or parse strictly in the library.

Code: `s16_serve.py::t296`.

**T-297 — An address this host does not have is `PROTO_E_BIND`.**
`192.0.2.1` gives `PROTO_E_BIND` (observed). Record `255.255.255.255`
per platform: `PROTO_E_BIND` on macOS (observed), while Linux accepts a
broadcast address in a TCP `bind` (reasoned from `inet_bind`), so the
server would start where no client can reach it.

Code: `s16_serve.py::t297`.

**T-298 — A port held by another listener is `PROTO_E_PORT_IN_USE`.**
Both on the wildcard address. (observed)

Code: `s16_serve.py::t298`.

**T-299 — A second server on the same port is refused, whatever the two bind addresses.**
**Fails today.** Wildcard then `127.0.0.1`, and
`127.0.0.1` then wildcard, both leave the second one running (observed).
"A forgotten instance still holding the port" then goes undiagnosed, and
loopback clients reach the newer instance. Linux refuses both
(reasoned). Expect `PROTO_E_PORT_IN_USE` on every platform;
`SO_REUSEADDR` allows more on BSD-derived kernels than on Linux. (macOS)

Code: `s16_serve.py::t299`.

**T-300 — A privileged port without privilege is `PROTO_E_PERM_DENIED`.**
A port below `net.ipv4.ip_unprivileged_port_start`. Not on macOS, where
uid 501 binds port 80 (observed), nor in the many containers that allow
it. (Linux, not as root)

Code: `s16_serve.py::t300`.

**T-301 — A failed `socketpair()` is `PROTO_E_SOCKET`, and the port is free.**
The stop channel cannot be made: `PROTO_E_SOCKET`, and the port
can be bound again at once. (observed) (seam)

Code: `s16_serve.py::t301`.

**T-302 — A failed `socket()` is `PROTO_E_SOCKET`.**
The listener cannot be created. (seam)

Code: `s16_serve.py::t302`.

**T-303 — A failed `listen()` is `PROTO_E_LISTEN`, and the port is released.**
The port can be bound again at once. (seam)

Code: `s16_serve.py::t303`.

**T-304 — A broken listening socket is `PROTO_E_ACCEPT`.**
`accept()` failing with `EBADF` or `EINVAL` (observed for `EBADF`): the
server returns instead of looping forever. (seam)

Code: `s16_serve.py::t304`.

**T-305 — Running out of descriptors pauses `accept`, without a busy loop.**
`accept()` failing with `EMFILE`, `ENFILE`, `ENOBUFS` or `ENOMEM` is
retried about every 100 ms (observed: 10 calls in 1.2 s), and a stop
still ends it (observed). A real descriptor limit is no way to reach
this: with a limit of 4, `socketpair` fails before `accept` is reached,
since stdio, the listener and the pair need six. (seam)

Code: `s16_serve.py::t305`.

**T-306 — `EINTR` and `ECONNABORTED` from `accept` are retried at once.**
The next client is served. (seam)

Code: `s16_serve.py::t306`.

**T-307 — A failed `fork()` is answered with `FAIL server busy`.**
The client's `proto_connect` returns `PROTO_E_REJECTED` (observed, in 1
ms); a client that sends nothing still gets the line within about 100 ms
(observed). The connection is then closed and the server keeps going.
(seam)

Code: `s16_serve.py::t307`.

**T-308 — A real process shortage gets the same answer.**
`RLIMIT_NPROC` set to the current number of processes: the next client
gets `FAIL server busy`. Root ignores the limit, hence the tag. (Linux,
not as root)

Code: `s16_serve.py::t308`.

**T-309 — A failing `poll()` is retried after a pause.**
Any error other than `EINTR`: retried, not in a busy loop. (seam)

Code: `s16_serve.py::t309`.

**T-310 — The handler gets the connection, the identity and `ctx`, in a child.**
It receives the connected fd, an `identity_hex` equal to the
allowlist, and `ctx` unchanged. It runs in another process (`getpid()`
differs from the parent's), and its fd is a connected, blocking socket
(`getpeername` succeeds, `O_NONBLOCK` clear). A listener made
non-blocking later would hand handlers non-blocking sockets on macOS and
the BSDs, where accepted sockets inherit the flag.

Code: `s16_serve.py::t310`.

**T-311 — Nothing runs for a stranger.**
A handler that writes a marker file is never called for a refused or a
silent client.

Code: `s16_serve.py::t311`.

**T-312 — `ctx` points to the child's copy.**
A change made through it in one connection is seen neither by the parent
nor by the next connection.

Code: `s16_serve.py::t312`.

**T-313 — When the handler returns, the child closes, exits 0 and is reaped.**
The client sees end of stream; no zombie after 50 sessions.

Code: `s16_serve.py::t313`.

**T-314 — A handler that crashes costs its own connection only.**
`raise(SIGSEGV)` in the handler: the next client is served.

Code: `s16_serve.py::t314`.

**T-315 — Clients are served in parallel.**
20 clients whose handlers each sleep 200 ms finish in about 200 ms, not
4 s.

Code: `s16_serve.py::t315`.

**T-316 — The parent keeps nothing per connection.**
Its fd count is the same after 200 sessions.

Code: `s16_serve.py::t316`.

**T-317 — A silent stranger costs a child for `HANDSHAKE_TIMEOUT_MS` only.**
After 10 silent connections, and the timeout plus some slack, none of
their children is alive. The v1.1 fix for children held forever by
silent peers.

Code: `s16_serve.py::t317`.

**T-318 — What a handler prints reaches its destination.**
**Fails today.** What a handler writes through stdio and does not flush
is lost, because the child ends with `_exit`, which discards buffers
(observed: a `printf` in the handler, stdout redirected to a file, and
the file stays empty). `_exit` is right, since the child inherits the
parent's unflushed buffers. Expect either the documents to tell handlers
to `fflush`, or the parent to flush before `fork()` and the child to
call `fflush(NULL)` after the handler.

Code: `s16_serve.py::t318`.

**T-319 — A stopped server can start again on the same port at once.**
`SO_REUSEADDR`: a server stopped while its connections linger in
`TIME_WAIT` starts again on the same port without `PROTO_E_PORT_IN_USE`.

Code: `s16_serve.py::t319`.

**T-320 — A burst beyond the backlog is served.**
50 connections against the backlog of 16: every client completes the
handshake, since the kernel retries; none is refused. (slow)

Code: `s16_serve.py::t320`.

**T-321 — A client that resets before `accept` does not wedge the loop.**
An `accept` seam sleeps 300 ms while the client closes with
`SO_LINGER {1, 0}`; a stop asked during the sleep is honoured (observed
on macOS: returned at 361 ms). A guard for kernels that drop aborted
connections from the queue, where a blocking `accept()` would wait for
the next client. (seam)

Code: `s16_serve.py::t321`.

**T-322 — `proto_serve` keeps two descriptors, once.**
After `proto_serve` returns, the process holds two descriptors more than
before its first call, the stop channel, and none more after later
calls.

Code: `s16_serve.py::t322`.

**T-323 — The listening socket and the stop channel are close-on-exec.**
**Fails today.** None of the three sockets had `FD_CLOEXEC` while
serving (observed), so a program the parent runs inherits the port and
the channel. Expect `FD_CLOEXEC` on all three.

Code: `s16_serve.py::t323`.

**T-324 — The server is IPv4 only.**
A client that connects to `::1` on the server's port is refused, as
`bind_addr` documents.

Code: `s16_serve.py::t324`.

**T-325 — The child holds nothing of the parent's.**
Inside the handler, the open descriptors are the ones the process had
before its first `proto_serve`, plus the connection: the listener and
the stop channel are closed. After a stop with `drain_ms` 0 while a
child is still serving, a new `proto_serve` binds the same port at once:
the child does not keep the port, as the stop promises.

Code: `s16_serve.py::t325`.

**T-326 — `bind_addr` restricts who can connect.**
With `127.0.0.1`, a connection to the host's own non-loopback IPv4
address on the server's port is refused, and the listening socket, found
among the process's descriptors, reports `127.0.0.1` through
`getsockname`. Skip where the host has no non-loopback IPv4.

Code: `s16_serve.py::t326`.

**T-327 — Signals do not disturb the accept loop.**
`SIGUSR1` at about 1 kHz into a handler installed without `SA_RESTART`,
while 50 clients connect in turn: every client is served, and after the
stop `proto_serve` returns `PROTO_OK`, never `PROTO_E_ACCEPT`.

Code: `s16_serve.py::t327`.

---

## XIX. `proto_serve_stop` and draining

**T-328 — A stop from a signal handler ends `proto_serve` with `PROTO_OK`.**
`SIGTERM` routed to `proto_serve_stop`: `PROTO_OK`, and a new connection
is refused afterwards (`ECONNREFUSED`), since the port is free.

Code: `s17_stop.py::t328`.

**T-329 — A stop from another thread ends `proto_serve`.**
`PROTO_OK`. (observed)

Code: `s17_stop.py::t329`.

**T-330 — A stop from another thread is free of data races.**
**Fails today.** ThreadSanitizer reports two races (observed):
`stop_asked`, written at `serve.c:67` and read at `serve.c:182`, and
`stop_fd`, read at `serve.c:68` and written at `serve.c:177`. A
`volatile sig_atomic_t` is safe against a signal handler, not against
another thread, and `serve.h` promises "from any thread". Expect a clean
TSan run: lock-free C11 atomics are safe for both.

Code: `s17_stop.py::t330`.

**T-331 — A stop before `proto_serve` is kept, but the setup still runs.**
A bad port is still reported; with a good setup, `proto_serve` returns
`PROTO_OK` without accepting. (observed)

Code: `s17_stop.py::t331`.

**T-332 — A stop outlives a failed call.**
**Pin.** A stop, then `proto_serve` with a `NULL` allowlist gives
`PROTO_E_NO_ALLOWLIST`; a good call after it returns `PROTO_OK` at once.
(observed)

Code: `s17_stop.py::t332`.

**T-333 — A stop after `proto_serve` returned is kept for the next call.**
As documented.

Code: `s17_stop.py::t333`.

**T-334 — Many stops never block.**
10^5 stops in a row all return, and the call after next runs normally:
at most one stray byte is left in the channel.

Code: `s17_stop.py::t334`.

**T-335 — `proto_serve_stop` preserves `errno`.**
On the first call, on later calls, and on a call before any
`proto_serve`.

Code: `s17_stop.py::t335`.

**T-336 — A stop wins over a waiting client.**
With the server held by `SIGSTOP`, a client connects and `SIGTERM` is
sent; on `SIGCONT`, `proto_serve` returns without accepting, the handler
never runs, and the client sees its connection reset or closed.

Code: `s17_stop.py::t336`.

**T-337 — `drain_ms` 0 returns at once and leaves children serving.**
While a child is serving, `proto_serve` returns at once, and that child
goes on serving its client afterwards (`PING` still gets `PONG`).

Code: `s17_stop.py::t337`.

**T-338 — The drain returns when the last child ends.**
`drain_ms` 2000, with the last child ending at 500 ms: returns at about
500 ms.

Code: `s17_stop.py::t338`.

**T-339 — `drain_ms` bounds the wait.**
`drain_ms` 500 with a busy child: returns at about 500 ms, with the
child still alive.

Code: `s17_stop.py::t339`.

**T-340 — The drain counts the application's own children.**
**Pin.** One that sleeps 1 s, forked before `proto_serve`, holds the
return until about 1 s with `drain_ms` 3000 (observed: 1002 ms).
Documented; the test keeps it so.

Code: `s17_stop.py::t340`.

**T-341 — `drain_ms` `INT_MAX` with no children returns at once.**
No child, nothing to wait for.

Code: `s17_stop.py::t341`.

**T-342 — A stop during the drain belongs to the stop in progress.**
The next `proto_serve` runs normally.

Code: `s17_stop.py::t342`.

**T-343 — A child that receives the stop signal itself exits at once.**
Through the handler it inherited, the child exits 0 at once, and the
server keeps accepting.

Code: `s17_stop.py::t343`.

**T-344 — `SIGTERM` to the whole process group ends everything cleanly.**
The parent returns `PROTO_OK` and exits 0, and the children exit 0: the
measurement in `RELEASE_NOTES.md`, on every run.

Code: `s17_stop.py::t344`.

**T-345 — A handler that calls `proto_serve_stop()` ends only its own child.**
With status 0, and the parent goes on serving.

Code: `s17_stop.py::t345`.

**T-346 — Serving and stopping on one port, 50 times over, always works.**
`PROTO_OK` each time, never `PROTO_E_PORT_IN_USE`, and a flat fd count
after the first.

Code: `s17_stop.py::t346`.

**T-347 — A stop on the busy path is honoured right after it.**
While the loop is on the busy path (`fork` failing, a silent client, the
100 ms read), a stop ends the loop as soon as that path is done. (seam)

Code: `s17_stop.py::t347`.

---

## XX. Process-wide effects of `proto_serve`

**T-348 — The child reaper is removed when `proto_serve` returns.**
**Fails today.** It stays installed (observed): in the parent,
`pclose(popen("exit 3"))` returns -1 with `ECHILD`, and `waitpid` on a
child of the application's own fails with `ECHILD` (both observed). The
code after a stop, "close your storage, log, exit 0", is exactly where
an application might run a helper. Expect the previous `SIGCHLD`
disposition back on return, and on every setup failure that happens
after it was changed.

Code: `s18_process.py::t348`.

**T-349 — `SIGPIPE` stays ignored after `proto_serve` returns.**
**Pin.** (observed) The documents say the harness ignores it, not that
it goes on ignoring it. Decide: restore it, or document it.

Code: `s18_process.py::t349`.

**T-350 — An application's `SIGCHLD` handler is replaced without a word.**
**Pin.** A handler installed before `proto_serve` is gone after it, and
nothing says so.

Code: `s18_process.py::t350`.

**T-351 — Setup failures after the dispositions change leave them changed.**
**Pin.** `PROTO_E_SOCKET`, `PROTO_E_PORT_IN_USE`, `PROTO_E_PERM_DENIED`,
`PROTO_E_BIND` and `PROTO_E_LISTEN` leave them changed; the failures
before (`PROTO_E_NO_ALLOWLIST` to `PROTO_E_PARAM`) do not.

Code: `s18_process.py::t351`.

**T-352 — In the child, `SIGCHLD` is at its default and `SIGPIPE` is ignored.**
A handler's `pclose(popen("exit 3"))` returns status 3 (the
v1.1 fix: the reaper used to swallow the application's children), and a
raw `write()` to a closed peer fails with `EPIPE` instead of killing the
child.

Code: `s18_process.py::t352`.

**T-353 — The reaper keeps `errno`.**
A child that exits between an `accept` failing with `EMFILE` and the
check does not turn it into `ECHILD`, so the server never returns
`PROTO_E_ACCEPT` over it. Stress the window with many short-lived
children. (seam)

Code: `s18_process.py::t353`.

**T-354 — The application's own signal handlers reach the children unchanged.**
As documented.

Code: `s18_process.py::t354`.
