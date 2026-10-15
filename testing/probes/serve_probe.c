/* serve_probe.c -- a server built on proto_serve, steered from the command line.
 *
 * The tests start it as a separate process, talk to it over TCP and read what
 * it reports in its log file. Every event is one line, written with a single
 * write(), so the children of proto_serve can share the log.
 *
 *   serve_probe --port N --allow HEX --log PATH [options]
 *
 *   --bind ADDR          bind_addr of proto_serve_opts_t
 *   --drain MS           drain_ms
 *   --handler NAME       what a connection does (below); default "ok"
 *   --ms N               a duration the handler uses
 *   --ctx STR            a string the handler uses (a path)
 *   --sigterm-stop       SIGTERM and SIGINT call proto_serve_stop(), as docs.md shows
 *   --sigusr1-noop       SIGUSR1 does nothing, installed without SA_RESTART
 *   --sigusr2-dump       SIGUSR2 logs every open descriptor
 *   --sleeper-ms N       fork a child of the application that sleeps N ms first
 *   --cycles N --cycle-ms MS   run proto_serve N times, each stopped after MS ms
 *   --after popen|waitpid      what to try once proto_serve has returned
 *
 * Handlers: ok, vault, register, register_once, register_fail, register_okcr,
 * register_okextra, register_silent, silent, ok_silent, long_answer, sleep,
 * crash, marker, ctxmod, printf, fds, info, keepalive, child_signals, stopper.
 * All but the ones that fail on purpose send OK and then answer PING, ECHO,
 * SLEEP, STOP, DIE and QUIT until the client goes.
 */
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "crypto.h"
#include "probe.h"
#include "serve.h"
#include "wire.h"

struct cfg {
    const char *handler;
    const char *ctx_str;
    int ms;
    int counter;
};

static int logfd = -1;
static int baseline[256], nbaseline;

static void logf_(const char *fmt, ...) {
    char buf[2048];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof buf - 1, fmt, ap);
    va_end(ap);
    if (n < 0) return;
    if (n > (int)sizeof buf - 2) n = (int)sizeof buf - 2;
    buf[n++] = '\n';
    ssize_t w = write(logfd, buf, (size_t)n);
    (void)w;
}
#define logf logf_

static void sleep_ms(int ms) {
    nanosleep(&(struct timespec){ ms / 1000, (long)(ms % 1000) * 1000000L }, NULL);
}

/* ------------------------------------------------- async-signal-safe output */

static void put(const char *s) {
    ssize_t w = write(logfd, s, strlen(s));
    (void)w;
}

static void put_num(long v) {
    char b[24];
    int i = sizeof b;
    int neg = v < 0;
    unsigned long u = neg ? -(unsigned long)v : (unsigned long)v;
    b[--i] = '\0';
    do { b[--i] = (char)('0' + u % 10); u /= 10; } while (u);
    if (neg) b[--i] = '-';
    put(b + i);
}

/* One write() for the whole line: the children handle the same signal at the
 * same moment, and three writes each would interleave in the log. */
static void on_term(int sig) {
    (void)sig;
    char line[48] = "term pid=";
    size_t n = strlen(line);
    char digits[24];
    int d = 0;
    unsigned long v = (unsigned long)getpid();
    do { digits[d++] = (char)('0' + v % 10); v /= 10; } while (v);
    while (d) line[n++] = digits[--d];
    line[n++] = '\n';
    ssize_t w = write(logfd, line, n);
    (void)w;
    proto_serve_stop();
}

static void on_noop(int sig) { (void)sig; }

static void dump_fds(int sig) {
    (void)sig;
    for (int fd = 0; fd < 128; fd++) {
        int fl = fcntl(fd, F_GETFD);
        if (fl < 0) continue;
        struct stat st;
        if (fstat(fd, &st) != 0) continue;
        put("fd="); put_num(fd);
        put(" cloexec="); put(fl & FD_CLOEXEC ? "1" : "0");
        put(" sock="); put(S_ISSOCK(st.st_mode) ? "1" : "0");
        if (S_ISSOCK(st.st_mode)) {
            struct sockaddr_in a;
            socklen_t al = sizeof a;
            if (getsockname(fd, (struct sockaddr *)&a, &al) == 0 && a.sin_family == AF_INET) {
                unsigned char *ip = (unsigned char *)&a.sin_addr;
                put(" local=");
                for (int i = 0; i < 4; i++) { put_num(ip[i]); if (i < 3) put("."); }
                put(":"); put_num(ntohs(a.sin_port));
            } else {
                put(" local=other");
            }
        }
        put("\n");
    }
    put("dump end\n");
}

static void on_alarm(int sig) { (void)sig; proto_serve_stop(); }

/* ---------------------------------------------------------------- handlers */

static int list_fds(char *out, size_t max) {
    size_t n = 0;
    out[0] = '\0';
    for (int fd = 0; fd < 256; fd++)
        if (fcntl(fd, F_GETFD) >= 0 && n + 8 < max)
            n += (size_t)snprintf(out + n, max - n, "%s%d", n ? "," : "", fd);
    return (int)n;
}

static void wait_eof(int fd);

static void command_loop(int fd) {
    for (;;) {
        char *line = proto_recv_line_dyn(fd);
        if (!line) { logf("eof"); return; }
        logf("rx %.200s", line);
        if (!strcmp(line, "QUIT")) {
            proto_send_line(fd, "BYE");
            free(line);
            wait_eof(fd);                                /* the client closes after BYE */
            return;
        }
        else if (!strcmp(line, "PING")) proto_send_line(fd, "PONG");
        else if (!strncmp(line, "ECHO ", 5)) proto_send_prefixed(fd, "ECHO ", line + 5, strlen(line + 5));
        else if (!strncmp(line, "SLEEP ", 6)) { sleep_ms(atoi(line + 6)); proto_send_line(fd, "SLEPT"); }
        else if (!strcmp(line, "STOP")) { proto_send_line(fd, "STOPPING"); proto_serve_stop(); }
        else if (!strcmp(line, "DIE")) raise(SIGSEGV);
        else if (!strcmp(line, "FDS")) {
            char l[1024];
            list_fds(l, sizeof l);
            logf("child_fds %s", l);
            proto_send_line(fd, "FDS");
        } else proto_send_line(fd, "ERR");
        free(line);
    }
}

static void wait_eof(int fd) {
    for (;;) {
        char *line = proto_recv_line_dyn(fd);
        if (!line) { logf("eof"); return; }
        logf("rx %.200s", line);
        free(line);
    }
}

/* Ask for the client's encryption key; returns 1 and logs it if it came. */
static int do_register(int fd) {
    proto_send_line(fd, "REGISTER");
    char *line = proto_recv_line_dyn(fd);
    if (!line) { logf("register eof"); return 0; }
    logf("rx %.200s", line);
    free(line);
    return 1;
}

/* Close the way an application that answers an oversized line should: say no,
 * stop writing, and read what is left of the line before closing, so that the
 * close does not reset the connection and take the answer with it. */
static void refuse_and_drain(int fd) {
    shutdown(fd, SHUT_WR);
    char buf[65536];
    for (;;) {
        struct pollfd p = { .fd = fd, .events = POLLIN };
        if (poll(&p, 1, 5000) <= 0) break;
        if (read(fd, buf, sizeof buf) <= 0) break;
    }
}

/* The vault of the worked example in docs.md, kept in memory: PUT stores a line,
 * GET returns them all, a line past MAX_PAYLOAD is answered "FAIL message too
 * large" before the connection closes. */
static void vault(int fd) {
    enum { MAX_ENTRIES = 64 };
    char *entries[MAX_ENTRIES];
    int n = 0;
    proto_send_line(fd, "OK");
    for (;;) {
        int status = PROTO_OK;
        char *line = proto_recv_line_dyn_status(fd, &status);
        if (!line) {
            if (status == PROTO_E_LINE_TOO_LONG) {
                proto_send_line(fd, "FAIL message too large");
                refuse_and_drain(fd);
            }
            logf("vault ended status=%d", status);
            return;
        }
        if (!strncmp(line, "PUT ", 4) && n < MAX_ENTRIES) {
            entries[n++] = strdup(line + 4);
            char ok[32];
            snprintf(ok, sizeof ok, "OK %d", n);
            proto_send_line(fd, ok);
            logf("vault stored %d", n);
        } else if (!strcmp(line, "GET")) {
            char hdr[32];
            snprintf(hdr, sizeof hdr, "ENTRIES %d", n);
            proto_send_line(fd, hdr);
            for (int i = 0; i < n; i++) {
                char id[16];
                snprintf(id, sizeof id, "%d ", i + 1);
                proto_send_prefixed(fd, id, entries[i], strlen(entries[i]));
            }
        } else if (!strcmp(line, "QUIT")) {
            proto_send_line(fd, "BYE");
            free(line);
            wait_eof(fd);
            return;
        } else {
            proto_send_line(fd, "FAIL unknown command");
        }
        free(line);
    }
}

static void handler(int fd, const char *identity, void *ctx) {
    struct cfg *c = ctx;
    const char *h = c->handler;
    logf("handler %s pid=%d", h, (int)getpid());

    if (!strcmp(h, "ok")) { proto_send_line(fd, "OK"); command_loop(fd); }
    else if (!strcmp(h, "vault")) vault(fd);
    else if (!strcmp(h, "register")) {
        if (!do_register(fd)) return;
        proto_send_line(fd, "OK");
        command_loop(fd);
    } else if (!strcmp(h, "register_once")) {
        /* ctx_str: a file holding the registered key. First time asks, then remembers. */
        if (access(c->ctx_str, F_OK) == 0) { proto_send_line(fd, "OK"); command_loop(fd); return; }
        proto_send_line(fd, "REGISTER");
        char *line = proto_recv_line_dyn(fd);
        if (!line) return;
        if (strncmp(line, "REGISTER ", 9) != 0) { proto_send_line(fd, "FAIL expected REGISTER"); free(line); return; }
        FILE *f = fopen(c->ctx_str, "w");
        if (f) { fprintf(f, "%s\n", line + 9); fclose(f); }
        logf("registered %.200s", line + 9);
        free(line);
        proto_send_line(fd, "OK");
        command_loop(fd);
    } else if (!strcmp(h, "register_fail")) {
        if (!do_register(fd)) return;
        proto_send_line(fd, "FAIL no");
        wait_eof(fd);
    } else if (!strcmp(h, "register_okcr")) {
        if (!do_register(fd)) return;
        proto_send_line(fd, "OK\r");
        command_loop(fd);
    } else if (!strcmp(h, "register_okextra")) {
        if (!do_register(fd)) return;
        proto_send_line(fd, "OK extra");
        wait_eof(fd);
    } else if (!strcmp(h, "register_silent")) {
        if (!do_register(fd)) return;
        wait_eof(fd);
    } else if (!strcmp(h, "silent")) {
        wait_eof(fd);                                   /* never sends the verdict */
    } else if (!strcmp(h, "ok_silent")) {
        proto_send_line(fd, "OK");
        wait_eof(fd);                                   /* reads QUIT, never answers */
    } else if (!strcmp(h, "long_answer")) {
        proto_send_line(fd, "OK");
        char *line = proto_recv_line_dyn(fd);
        if (line) { logf("rx %.200s", line); free(line); }
        char big[101];
        memset(big, 'x', 100);
        big[100] = '\0';
        proto_send_line(fd, big);
        wait_eof(fd);
    } else if (!strcmp(h, "sleep")) {
        proto_send_line(fd, "OK");
        sleep_ms(c->ms);
        logf("slept");
    } else if (!strcmp(h, "crash")) {
        proto_send_line(fd, "OK");
        raise(SIGSEGV);
    } else if (!strcmp(h, "marker")) {
        int m = open(c->ctx_str, O_CREAT | O_WRONLY, 0600);
        if (m >= 0) close(m);
        proto_send_line(fd, "OK");
        command_loop(fd);
    } else if (!strcmp(h, "ctxmod")) {
        logf("ctxmod counter=%d", c->counter);
        c->counter += 10;
        proto_send_line(fd, "OK");
        wait_eof(fd);
    } else if (!strcmp(h, "printf")) {
        printf("handler says hi\n");                    /* deliberately not flushed */
        proto_send_line(fd, "OK");
    } else if (!strcmp(h, "fds")) {
        char l[1024];
        list_fds(l, sizeof l);
        logf("child_fds %s conn=%d", l, fd);
        proto_send_line(fd, "OK");
        command_loop(fd);
    } else if (!strcmp(h, "info")) {
        int fl = fcntl(fd, F_GETFL);
        int ka = -1;
        socklen_t kl = sizeof ka;
        getsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &ka, &kl);
        struct sockaddr_storage ss;
        socklen_t sl = sizeof ss;
        int peer = getpeername(fd, (struct sockaddr *)&ss, &sl) == 0;
        logf("info pid=%d ppid=%d identity=%s ctx=%s nonblock=%d keepalive=%d peer=%d",
             (int)getpid(), (int)getppid(), identity, c->ctx_str ? c->ctx_str : "", !!(fl & O_NONBLOCK),
             ka, peer);
        proto_send_line(fd, "OK");
        command_loop(fd);
    } else if (!strcmp(h, "keepalive")) {
        logf("keepalive rc=%d", proto_keepalive(fd, 10, 5, 3));
        proto_send_line(fd, "OK");
        command_loop(fd);
    } else if (!strcmp(h, "child_signals")) {
        void (*prev)(int) = signal(SIGCHLD, SIG_DFL);
        logf("sigchld default=%d", prev == SIG_DFL);
        prev = signal(SIGPIPE, SIG_IGN);
        logf("sigpipe ignored=%d", prev == SIG_IGN);
        FILE *p = popen("exit 3", "r");
        int st = p ? pclose(p) : -99;
        logf("pclose status=%d exited=%d code=%d", st, st >= 0 && WIFEXITED(st),
             st >= 0 && WIFEXITED(st) ? WEXITSTATUS(st) : -1);
        int sv[2];
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0) {
            close(sv[1]);
            errno = 0;
            ssize_t w = write(sv[0], "x", 1);
            logf("raw write returned %d errno_epipe=%d", (int)w, errno == EPIPE);
        }
        proto_send_line(fd, "OK");
        command_loop(fd);
    } else if (!strcmp(h, "stopper")) {
        proto_send_line(fd, "OK");
        logf("stopper calls proto_serve_stop");
        proto_serve_stop();
        logf("stopper survived proto_serve_stop");
    } else {
        logf("unknown handler %s", h);
    }
}

/* ------------------------------------------------------------------- main */

int main(int argc, char **argv) {
    int port = 0, drain = 0, have_drain = 0, cycles = 1, cycle_ms = 0, sleeper_ms = 0;
    int term = 0, usr1 = 0, usr2 = 0;
    const char *allow = NULL, *bind_addr = NULL, *log = NULL, *after = NULL;
    struct cfg cfg = { "ok", "", 0, 0 };

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        const char *v = i + 1 < argc ? argv[i + 1] : NULL;
        if (!strcmp(a, "--port") && v) { port = atoi(v); i++; }
        else if (!strcmp(a, "--allow") && v) { allow = v; i++; }
        else if (!strcmp(a, "--bind") && v) { bind_addr = v; i++; }
        else if (!strcmp(a, "--drain") && v) { drain = atoi(v); have_drain = 1; i++; }
        else if (!strcmp(a, "--handler") && v) { cfg.handler = v; i++; }
        else if (!strcmp(a, "--ms") && v) { cfg.ms = atoi(v); i++; }
        else if (!strcmp(a, "--ctx") && v) { cfg.ctx_str = v; i++; }
        else if (!strcmp(a, "--log") && v) { log = v; i++; }
        else if (!strcmp(a, "--sleeper-ms") && v) { sleeper_ms = atoi(v); i++; }
        else if (!strcmp(a, "--cycles") && v) { cycles = atoi(v); i++; }
        else if (!strcmp(a, "--cycle-ms") && v) { cycle_ms = atoi(v); i++; }
        else if (!strcmp(a, "--after") && v) { after = v; i++; }
        else if (!strcmp(a, "--sigterm-stop")) term = 1;
        else if (!strcmp(a, "--sigusr1-noop")) usr1 = 1;
        else if (!strcmp(a, "--sigusr2-dump")) usr2 = 1;
        else FAILF("bad option %s", a);
    }
    if (!port || !allow || !log) FAILF("usage: serve_probe --port N --allow HEX --log PATH [...]");
    logfd = open(log, O_WRONLY | O_CREAT | O_APPEND, 0600);
    if (logfd < 0) FAILF("cannot open the log");

    if (sleeper_ms) {                                  /* a child of the application's own */
        if (fork() == 0) { sleep_ms(sleeper_ms); _exit(0); }
    }
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sigemptyset(&sa.sa_mask);
    if (term) {
        sa.sa_handler = on_term;
        sigaction(SIGTERM, &sa, NULL);
        sigaction(SIGINT, &sa, NULL);
    }
    if (usr1) { sa.sa_handler = on_noop; sigaction(SIGUSR1, &sa, NULL); }
    if (usr2) { sa.sa_handler = dump_fds; sigaction(SIGUSR2, &sa, NULL); }

    /* libsodium opens its source of randomness the first time it is asked for
     * bytes, and keeps the descriptor: do it now, so that the baseline holds it
     * and a handler that inherits it is not mistaken for one that leaks. */
    proto_init();
    {
        unsigned char warm[8];
        randombytes_buf(warm, sizeof warm);
    }
    char l[1024];
    list_fds(l, sizeof l);
    logf("baseline_fds %s", l);

    proto_serve_opts_t opts = { .bind_addr = bind_addr, .drain_ms = have_drain ? drain : 0 };
    int rc = 0;
    for (int cycle = 1; cycle <= cycles; cycle++) {
        if (cycle_ms) {
            struct sigaction al;
            memset(&al, 0, sizeof al);
            sigemptyset(&al.sa_mask);
            al.sa_handler = on_alarm;
            sigaction(SIGALRM, &al, NULL);
            setitimer(ITIMER_REAL, &(struct itimerval){ { 0, 0 }, { cycle_ms / 1000, (cycle_ms % 1000) * 1000 } }, NULL);
        }
        rc = proto_serve(port, allow, handler, &cfg, &opts);
        list_fds(l, sizeof l);
        int n = 0;
        for (char *p = l; *p; p++) n += *p == ',';
        logf("cycle %d rc=%d open_fds=%d", cycle, rc, l[0] ? n + 1 : 0);
        if (rc != PROTO_OK) break;
    }
    logf("serve rc=%d counter=%d", rc, cfg.counter);
    if (after && rc == PROTO_OK) {
        if (!strcmp(after, "popen")) {
            errno = 0;
            FILE *p = popen("exit 3", "r");
            int st = p ? pclose(p) : -99;
            logf("after popen status=%d errno_echild=%d", st, errno == ECHILD);
        } else if (!strcmp(after, "waitpid")) {
            pid_t pid = fork();
            if (pid == 0) _exit(7);
            sleep_ms(100);
            int st = 0;
            errno = 0;
            pid_t r = waitpid(pid, &st, 0);
            logf("after waitpid returned=%d errno_echild=%d status=%d", (int)r, errno == ECHILD,
                 r > 0 && WIFEXITED(st) ? WEXITSTATUS(st) : -1);
        }
    }
    return rc == PROTO_OK ? 0 : 2;
}
