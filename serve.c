#include "serve.h"
#include "auth.h"
#include "crypto.h"
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>

static void reap_children(int sig) {
    (void)sig;
    while (waitpid(-1, NULL, WNOHANG) > 0);
}

int proto_serve(int port, const char *allowed_hex,
                proto_handler_fn handler, void *ctx) {
    if (proto_init() != 0) return -1;

    signal(SIGPIPE, SIG_IGN);
    struct sigaction sa;
    sa.sa_handler = reap_children;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    sigaction(SIGCHLD, &sa, NULL);

    int srv = socket(AF_INET, SOCK_STREAM, 0);
    if (srv < 0) return -1;

    int one = 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port        = htons((uint16_t)port);

    if (bind(srv, (struct sockaddr *)&addr, sizeof(addr)) < 0) { close(srv); return -1; }
    if (listen(srv, 16) < 0) { close(srv); return -1; }

    for (;;) {
        int cli = accept(srv, NULL, NULL);
        if (cli < 0) continue;

        pid_t pid = fork();
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
