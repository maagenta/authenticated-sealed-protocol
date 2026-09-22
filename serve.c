#include "serve.h"
#include "auth.h"
#include "crypto.h"
#include "wire.h"
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>

static void reap_children(int sig) {
    (void)sig;
    while (waitpid(-1, NULL, WNOHANG) > 0);
}

int proto_serve(int port, const char *allowed_hex,
                proto_handler_fn handler, void *ctx,
                const proto_serve_opts_t *opts) {
    /* A server with no allowlist, a malformed one, or no handler can never
     * serve anyone: refuse to start rather than bind a port and fail every
     * connection. */
    if (!allowed_hex) return PROTO_E_NO_ALLOWLIST;
    if (strlen(allowed_hex) != AUTH_PK_LEN * 2) return PROTO_E_BAD_ALLOWLIST;
    if (!handler) return PROTO_E_NO_HANDLER;
    /* The cast to uint16_t below would silently fold 70000 to 4464, and
     * 0 asks the kernel for any free port — a server that starts fine and
     * listens where no client will look. Refuse both. */
    if (port < 1 || port > 65535) return PROTO_E_BAD_PORT;

    /* Parse the bind address up front, with the other caller mistakes: a
     * typo in a config file should fail here, not after the port is half
     * set up. NULL opts, or a NULL field, means the default. */
    struct in_addr bind_addr = { .s_addr = htonl(INADDR_ANY) };
    if (opts && opts->bind_addr
        && inet_pton(AF_INET, opts->bind_addr, &bind_addr) != 1)
        return PROTO_E_BAD_ADDRESS;

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

    for (;;) {
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
            close(srv);
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
    /* not reached */
}
