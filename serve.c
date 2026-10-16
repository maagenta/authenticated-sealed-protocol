#include "serve.h"
#include "auth.h"
#include "crypto.h"
#include "wire.h"
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* Collect every child that has exited. A handler runs between any two
 * instructions of the code it interrupts, and the loop below ends with
 * waitpid() failing with ECHILD once no children are left. Without
 * restoring errno, a child exiting just after accept() failed would turn
 * EMFILE into ECHILD, and the accept loop — which reads errno to tell a
 * passing shortage from a broken socket — would return PROTO_E_ACCEPT and
 * stop a server that was fine. Running out of descriptors is exactly when
 * children exiting is to be expected. */
static void reap_children(int sig) {
    (void)sig;
    int saved = errno;
    while (waitpid(-1, NULL, WNOHANG) > 0);
    errno = saved;
}

/* 64 lowercase hex characters, the only form an identity takes. A copy of
 * the one in auth.c, which explains why length alone is not enough; this
 * one runs first, so a bad allowlist stops the server before the port is
 * bound instead of refusing every client from inside a child. */
static int is_identity_hex(const char *s) {
    for (size_t i = 0; i < AUTH_PK_LEN * 2; i++)
        if (!((s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'f')))
            return 0;
    return s[AUTH_PK_LEN * 2] == '\0';
}

/* All that proto_serve_stop() touches. It may run in a signal handler or on
 * another thread, so it reads and writes nothing else. stop_asked is the
 * request itself, and it waits for a proto_serve that has not started yet;
 * stop_fd only wakes the loop so that it looks at it. */
static volatile sig_atomic_t stop_asked = 0;
static volatile sig_atomic_t stop_fd    = -1;
static volatile sig_atomic_t in_child   = 0;

/* The channel stop_fd writes into. Created by the first proto_serve and
 * never closed in this process: a proto_serve_stop() on another thread may
 * be about to write to it, and a closed number could by then belong to
 * another file. */
static int wake[2] = { -1, -1 };

void proto_serve_stop(void) {
    /* A child inherits the application's handler, but stopping is the
     * parent's business: end the child as the signal would have without
     * that handler. Ending it gracefully comes with v2.0 (TODO.md). */
    if (in_child) _exit(0);
    /* One byte per stop wakes the loop, so the channel never fills. */
    if (stop_asked) return;
    int saved = errno;
    stop_asked = 1;
    int fd = stop_fd;
    if (fd >= 0) {
        ssize_t n = write(fd, "", 1);
        (void)n;
    }
    errno = saved;
}

/* Milliseconds on a clock that never jumps. A copy of the one in wire.c,
 * which keeps it private. */
static long long now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/* Give the children up to ms to finish, returning as soon as none is left.
 * waitpid() asks the kernel whether any remains, so nothing has to count
 * them, and it collects the ones the reaper has not. A child exiting cuts
 * the sleep short; the 100 ms only bound one that exits just before it.
 * Children the application forked itself count too: the kernel does not
 * tell them apart. */
static void drain(int ms) {
    long long deadline = now_ms() + ms;
    for (;;) {
        pid_t r = waitpid(-1, NULL, WNOHANG);
        if (r < 0) return;                  /* none left */
        if (r > 0) continue;                /* collected one; look again */
        long long left = deadline - now_ms();
        if (left <= 0) return;
        if (left > 100) left = 100;
        nanosleep(&(struct timespec){ 0, (long)left * 1000000 }, NULL);
    }
}

int proto_serve(int port, const char *allowed_hex,
                proto_handler_fn handler, void *ctx,
                const proto_serve_opts_t *opts) {
    /* A server with no allowlist, a malformed one, or no handler can never
     * serve anyone: refuse to start rather than bind a port and fail every
     * connection. */
    if (!allowed_hex) return PROTO_E_NO_ALLOWLIST;
    if (!is_identity_hex(allowed_hex)) return PROTO_E_BAD_ALLOWLIST;
    if (!handler) return PROTO_E_NO_HANDLER;
    /* The cast to uint16_t below would silently fold 70000 to 4464, and
     * 0 asks the kernel for any free port — a server that starts fine and
     * listens where no client will look. Refuse both. */
    if (port < 1 || port > 65535) return PROTO_E_BAD_PORT;

    /* Parse the bind address up front, with the other caller mistakes: a
     * typo in a config file should fail here, not after the port is half
     * set up. NULL opts, or a NULL field, means the default. */
    /* Only digits and dots get as far as inet_pton: NetBSD's stops at the
     * first space and accepts the rest, so "127.0.0.1\n" read from a config
     * file, or "127.0.0.1 junk", would bind there and nowhere else. */
    struct in_addr bind_addr = { .s_addr = htonl(INADDR_ANY) };
    if (opts && opts->bind_addr
        && (opts->bind_addr[strspn(opts->bind_addr, "0123456789.")] != '\0'
            || inet_pton(AF_INET, opts->bind_addr, &bind_addr) != 1))
        return PROTO_E_BAD_ADDRESS;
    /* A negative wait means nothing here. Read as 0 it would hide the
     * mistake, and -1 is not "forever" as it is for poll(): refuse it. */
    int drain_ms = opts ? opts->drain_ms : 0;
    if (drain_ms < 0) return PROTO_E_PARAM;

    int rc = proto_init();
    if (rc != PROTO_OK) return rc;

    signal(SIGPIPE, SIG_IGN);
    struct sigaction sa;
    sa.sa_handler = reap_children;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    sigaction(SIGCHLD, &sa, NULL);

    int srv = socket(AF_INET, SOCK_STREAM, 0);
    if (srv < 0) return PROTO_E_SOCKET;

    int one = 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr   = bind_addr;
    addr.sin_port   = htons((uint16_t)port);

    if (bind(srv, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        /* Capture errno before close(), which may overwrite it. The two
         * common causes get their own code: a forgotten instance still
         * holding the port, and a privileged port without the rights. */
        int e = errno;
        close(srv);
        return e == EADDRINUSE               ? PROTO_E_PORT_IN_USE
             : (e == EACCES || e == EPERM)   ? PROTO_E_PERM_DENIED
             : PROTO_E_BIND;
    }
    if (listen(srv, 16) < 0) { close(srv); return PROTO_E_LISTEN; }

    /* The channel a stop wakes the loop through. A socket pair rather than
     * a pipe, so that failing to create it is honestly PROTO_E_SOCKET. Both
     * ends non-blocking: the loop empties it without waiting, and a stop
     * never blocks in the handler it runs in. */
    if (wake[0] < 0) {
        int p[2];
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, p) < 0) {
            close(srv);
            return PROTO_E_SOCKET;
        }
        fcntl(p[0], F_SETFL, O_NONBLOCK);
        fcntl(p[1], F_SETFL, O_NONBLOCK);
        wake[0] = p[0];
        wake[1] = p[1];
        stop_fd = p[1];
    }

    /* A stop asked before this point is seen here, once the server is set
     * up, so that a setup error is still reported. */
    while (!stop_asked) {
        /* Wait for a client or a stop. A blocking accept() would not do: a
         * signal does not break it out of its wait (the kernel restarts it,
         * or the loop retries it), so a stop would go unseen until the next
         * client arrived. */
        struct pollfd ready[2] = { { .fd = srv,     .events = POLLIN },
                                   { .fd = wake[0], .events = POLLIN } };
        if (poll(ready, 2, -1) < 0) {
            /* A signal: look at the flag again. Anything else is a passing
             * shortage of memory; pause as for accept() below. */
            if (errno != EINTR)
                nanosleep(&(struct timespec){ 0, 100 * 1000000 }, NULL);
            continue;
        }
        if (ready[1].revents) {
            /* Empty the channel: its byte has done its job, and one left by
             * an earlier stop would wake the loop forever. */
            char drop[16];
            while (read(wake[0], drop, sizeof drop) > 0)
                ;
        }
        /* A stop wins over a waiting client. Any event on the listener goes
         * to accept(), not only POLLIN: if the socket has broken, accept()
         * is what reports it, and skipping it would spin. */
        if (stop_asked || !ready[0].revents) continue;

        int cli = accept(srv, NULL, NULL);
        if (cli < 0) {
            /* A signal, or a peer that gave up before we got to it: retry. */
            if (errno == EINTR || errno == ECONNABORTED) continue;
            /* Out of descriptors or memory. On Linux the pending connection
             * stays queued and accept() fails again at once, so retrying
             * without a pause is a busy loop. A child exiting frees what is
             * missing; give it 100 ms. */
            if (errno == EMFILE || errno == ENFILE || errno == ENOBUFS
             || errno == ENOMEM) {
                nanosleep(&(struct timespec){ 0, 100 * 1000000 }, NULL);
                continue;
            }
            /* Anything else means the listening socket itself is unusable
             * and no retry will change that: return so the application can
             * decide, instead of looping forever in silence. */
            close(srv);
            return PROTO_E_ACCEPT;
        }

        pid_t pid = fork();
        if (pid < 0) {
            /* No process to serve this client. Say so before closing: a bare
             * close looks like a network failure; "busy" says try again. Its
             * HELLO is read first — closing with data unread makes the kernel
             * reset the connection, and the reset discards the FAIL. The
             * wait is short: this is the accept loop. */
            char line[MAX_LINE];
            proto_recv_line_timeout(cli, line, sizeof line, 100);
            proto_send_line(cli, "FAIL server busy");
            close(cli);
            continue;
        }
        if (pid == 0) {
            /* From here a stop ends this child (see proto_serve_stop); set
             * first, so that none can write to the channel being closed.
             * The channel and the listener are the parent's. */
            in_child = 1;
            close(wake[0]);
            close(wake[1]);
            close(srv);
            /* The reaper is the parent's: it collects the connections' children.
             * Inherited, it would collect the handler's own — a popen() whose
             * pclose() then fails with ECHILD every time, a waitpid() that never
             * sees its child's status — since it waits for any child the moment
             * one exits. The child has no children of the library's to reap, so
             * it gets the default back. SIGPIPE stays ignored: that one protects
             * the handler's own writes. */
            signal(SIGCHLD, SIG_DFL);
            char *user = proto_auth_server(cli, allowed_hex);
            if (user) {
                handler(cli, user, ctx);
                free(user);
            }
            close(cli);
            _exit(0);
        }
        close(cli);
    }

    /* Stopped. The port is free from here: the children closed their copy
     * of the listener when they were forked. The connections in progress
     * are untouched, each on its own socket, and get drain_ms to finish.
     * The channel stays open for the next proto_serve. */
    close(srv);
    drain(drain_ms);
    /* Consumed. A stop asked while draining was this one; one asked from
     * now on is for the next proto_serve. */
    stop_asked = 0;
    return PROTO_OK;
}
