#include "auth.h"
#include "wire.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netdb.h>
#include <sodium.h>

int proto_auth_client(int fd, const proto_keys_t *keys) {
    char line[MAX_LINE];
    int rc;

    /* Every handshake read is bounded: a server that accepted the connection
     * and then went silent must not hold the client past HANDSHAKE_TIMEOUT_MS. */
    if ((rc = proto_send_line(fd, "HELLO")) < 0) return rc;
    if ((rc = proto_recv_line_timeout(fd, line, sizeof(line), HANDSHAKE_TIMEOUT_MS)) < 0) return rc;
    /* A FAIL here is the server declining before the challenge — busy, or
     * misconfigured — not a protocol violation. */
    if (strncmp(line, "FAIL ", 5) == 0)       return PROTO_E_REJECTED;
    if (strncmp(line, "CHALLENGE ", 10) != 0) return PROTO_E_UNEXPECTED_REPLY;

    unsigned char challenge[CHALLENGE_LEN];
    size_t ch_len = 0;
    if (sodium_base642bin(challenge, sizeof(challenge),
                          line + 10, strlen(line + 10),
                          NULL, &ch_len, NULL,
                          sodium_base64_VARIANT_ORIGINAL) != 0
        || ch_len != CHALLENGE_LEN) return PROTO_E_BAD_CHALLENGE;

    unsigned char sig[AUTH_SIG_LEN];
    if ((rc = proto_sign_challenge(challenge, ch_len, keys->auth_sk, sig)) != PROTO_OK)
        return rc;

    /* sodium_base64_ENCODED_LEN already counts the trailing NUL, so it is the
     * whole buffer size — unlike the hex buffers, where sodium_bin2hex wants
     * len * 2 + 1 and the caller adds the NUL. Do not add 1 here. */
    char pk_b64[sodium_base64_ENCODED_LEN(AUTH_PK_LEN, sodium_base64_VARIANT_ORIGINAL)];
    char sig_b64[sodium_base64_ENCODED_LEN(AUTH_SIG_LEN, sodium_base64_VARIANT_ORIGINAL)];
    sodium_bin2base64(pk_b64,  sizeof(pk_b64),  keys->auth_pk, AUTH_PK_LEN,  sodium_base64_VARIANT_ORIGINAL);
    sodium_bin2base64(sig_b64, sizeof(sig_b64), sig,           AUTH_SIG_LEN, sodium_base64_VARIANT_ORIGINAL);

    char cmd[MAX_LINE];
    snprintf(cmd, sizeof(cmd), "AUTH %s %s", pk_b64, sig_b64);
    if ((rc = proto_send_line(fd, cmd)) < 0) return rc;
    if ((rc = proto_recv_line_timeout(fd, line, sizeof(line), HANDSHAKE_TIMEOUT_MS)) < 0) return rc;

    if (strcmp(line, "REGISTER") == 0) return PROTO_REGISTER_REQUESTED;
    if (strcmp(line, "OK") == 0)       return PROTO_OK;
    /* Anything else is the server declining — usually a FAIL line carrying
     * the reason, which the caller can read off the wire if it wants it. */
    return PROTO_E_REJECTED;
}

/* Whether fd refers to a socket at all. conn->fd holding a number does not
 * mean it is a connection of ours: a struct initialized with {0} has fd 0,
 * which is stdin. Ask the kernel what the number is before touching it. */
static int is_socket(int fd) {
    struct stat st;
    return fstat(fd, &st) == 0 && S_ISSOCK(st.st_mode);
}

/* Milliseconds on a clock that never jumps, for deadlines. (wire.c keeps
 * its own copy: six lines are cheaper than a public function nothing but
 * this file would call.) */
static long long now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/* connect() with a deadline. An address that refuses fails at once, but one
 * that answers nothing — a firewall dropping packets — would otherwise cost
 * the kernel's own limit, 75 s on macOS and about two minutes on Linux, and
 * that once per address the name resolves to.
 *
 * The socket is non-blocking for the attempt only: everything above this
 * layer is documented as blocking, and the handshake that follows depends
 * on it. Returns 0 connected, 1 out of time, -1 refused or failed. */
static int connect_timeout(int fd, const struct sockaddr *addr,
                           socklen_t len, int ms) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) return -1;

    int result = -1;
    if (connect(fd, addr, len) == 0) {
        result = 0;                      /* a local socket can finish at once */
    } else if (errno == EINPROGRESS) {
        long long deadline = now_ms() + ms;
        for (;;) {
            long long left = deadline - now_ms();
            if (left <= 0) { result = 1; break; }
            struct pollfd p = { .fd = fd, .events = POLLOUT };
            int n = poll(&p, 1, (int)left);
            if (n < 0 && errno == EINTR) continue;   /* a signal, not an answer */
            if (n <= 0) { result = n == 0 ? 1 : -1; break; }
            /* Writable means the attempt has finished, one way or the
             * other; SO_ERROR says which. */
            int err = 0;
            socklen_t errlen = sizeof err;
            if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &errlen) < 0) {
                result = -1;
            } else {
                result = err == 0 ? 0 : -1;
            }
            break;
        }
    }
    fcntl(fd, F_SETFL, flags);           /* blocking again, connected or not */
    return result;
}

int proto_connect(proto_conn_t *conn, const char *host, int port) {
    /* getaddrinfo() would reject a port outside the TCP range, but with
     * the code for a name that does not resolve, which sends the caller
     * to check the wrong thing. Say what is wrong. */
    if (port < 1 || port > 65535) return PROTO_E_BAD_PORT;

    /* One conn, one connection. If the caller reconnects without closing,
     * the socket still in conn->fd would be overwritten and leak — no one
     * could close it, and the server child serving it would block until
     * this process exits — so close it first. Only a socket is ours to
     * close: whatever else the number refers to is left alone and merely
     * overwritten below. */
    if (conn->fd >= 0) {
        if (is_socket(conn->fd)) proto_close(conn);
        else conn->fd = -1;
    }

    int rc = proto_init();
    if (rc != PROTO_OK) return rc;

    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    char port_str[8];
    snprintf(port_str, sizeof(port_str), "%d", port);
    if (getaddrinfo(host, port_str, &hints, &res) != 0) return PROTO_E_RESOLVE;

    /* A name may resolve to several addresses — an IPv6 and an IPv4, or
     * several hosts behind one name — and the first is not necessarily
     * reachable from here: the resolver lists IPv6 first, so a server on
     * 127.0.0.1 would be unreachable as "localhost" without ever trying
     * the IPv4. Walk the list in the resolver's order and stop at the
     * first address that connects. */
    int fd = -1, tried = 0, refused = 0;
    for (struct addrinfo *ai = res; ai; ai = ai->ai_next) {
        fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0) continue;            /* family not available here; next */
        tried = 1;
        int c = connect_timeout(fd, ai->ai_addr, ai->ai_addrlen,
                                CONNECT_TIMEOUT_MS);
        if (c == 0) break;
        if (c < 0) refused = 1;          /* a definite answer, unlike silence */
        close(fd); fd = -1;
    }
    freeaddrinfo(res);
    /* Every address failed. socket() failing on all of them means no address
     * family the resolver offered exists on this host. Otherwise, a refusal
     * anywhere is the useful diagnosis — something is there and not
     * listening — and only silence everywhere is reported as a timeout. */
    if (fd < 0) {
        conn->fd = -1;
        if (!tried) return PROTO_E_SOCKET;
        return refused ? PROTO_E_CONNECT : PROTO_E_CONNECT_TIMEOUT;
    }
    conn->fd = fd;

    sodium_bin2hex(conn->identity_hex, sizeof(conn->identity_hex),
                   conn->keys.auth_pk, AUTH_PK_LEN);

    rc = proto_auth_client(conn->fd, &conn->keys);
    if (rc < 0) goto fail;

    if (rc == PROTO_REGISTER_REQUESTED) {  /* send our enc pubkey */
        char epk_b64[sodium_base64_ENCODED_LEN(ENC_PK_LEN, sodium_base64_VARIANT_ORIGINAL)];
        sodium_bin2base64(epk_b64, sizeof(epk_b64),
                          conn->keys.enc_pk, ENC_PK_LEN,
                          sodium_base64_VARIANT_ORIGINAL);
        char reg[MAX_LINE];
        snprintf(reg, sizeof(reg), "REGISTER %s", epk_b64);
        char line[MAX_LINE];
        if ((rc = proto_send_line(conn->fd, reg)) < 0) goto fail;
        if ((rc = proto_recv_line_timeout(conn->fd, line, sizeof(line), HANDSHAKE_TIMEOUT_MS)) < 0) goto fail;
        if (strcmp(line, "OK") != 0) { rc = PROTO_E_REGISTER_REJECTED; goto fail; }
    }
    return PROTO_OK;

fail:
    /* rc carries why: the handshake code, a transport code, or the
     * registration refusal. The socket is closed either way. */
    close(conn->fd); conn->fd = -1; return rc;
}

void proto_close(proto_conn_t *conn) {
    if (conn->fd < 0) return;
    /* Not a socket: the number is not ours — a {0} struct that was never
     * connected has stdin here. Forget it rather than close it. */
    if (!is_socket(conn->fd)) { conn->fd = -1; return; }
    /* The goodbye is a courtesy: wait for BYE only briefly, and not at all if
     * QUIT could not even be sent. The close ends the connection regardless,
     * so a server that never answers cannot hold the client here. */
    if (proto_send_line(conn->fd, "QUIT") == PROTO_OK) {
        char line[64];
        proto_recv_line_timeout(conn->fd, line, sizeof(line), QUIT_TIMEOUT_MS);
    }
    close(conn->fd);
    conn->fd = -1;
}

char *proto_auth_server(int fd, const char *allowed_hex) {
    char line[MAX_LINE];

    /* Without a well-formed allowlist there is nobody to compare against, so
     * no peer could ever authenticate. Say so before spending a handshake. */
    if (!allowed_hex || strlen(allowed_hex) != AUTH_PK_LEN * 2) {
        proto_send_line(fd, "FAIL internal error");
        return NULL;
    }

    /* Every handshake read is bounded. This is what frees a forked child from
     * a peer that connected and never spoke: after HANDSHAKE_TIMEOUT_MS the
     * read fails, the child returns, and proto_serve reaps it. */
    if (proto_recv_line_timeout(fd, line, sizeof(line), HANDSHAKE_TIMEOUT_MS) < 0) return NULL;
    if (strcmp(line, "HELLO") != 0) {
        proto_send_line(fd, "FAIL expected HELLO"); return NULL;
    }

    unsigned char challenge[CHALLENGE_LEN];
    randombytes_buf(challenge, sizeof(challenge));

    char ch_b64[sodium_base64_ENCODED_LEN(CHALLENGE_LEN, sodium_base64_VARIANT_ORIGINAL)];
    sodium_bin2base64(ch_b64, sizeof(ch_b64), challenge, CHALLENGE_LEN,
                      sodium_base64_VARIANT_ORIGINAL);

    char resp[MAX_LINE];
    snprintf(resp, sizeof(resp), "CHALLENGE %s", ch_b64);
    if (proto_send_line(fd, resp) < 0) return NULL;

    if (proto_recv_line_timeout(fd, line, sizeof(line), HANDSHAKE_TIMEOUT_MS) < 0) return NULL;
    if (strncmp(line, "AUTH ", 5) != 0) {
        proto_send_line(fd, "FAIL expected AUTH"); return NULL;
    }

    char *sv = NULL, *tmp = strdup(line + 5);
    if (!tmp) { proto_send_line(fd, "FAIL internal error"); return NULL; }
    char *pk_b64  = strtok_r(tmp, " ", &sv);
    char *sig_b64 = strtok_r(NULL, " ", &sv);
    if (!pk_b64 || !sig_b64) {
        free(tmp); proto_send_line(fd, "FAIL invalid AUTH format"); return NULL;
    }

    unsigned char pk[AUTH_PK_LEN];
    size_t pk_len = 0;
    if (sodium_base642bin(pk, sizeof(pk), pk_b64, strlen(pk_b64),
                          NULL, &pk_len, NULL,
                          sodium_base64_VARIANT_ORIGINAL) != 0
        || pk_len != AUTH_PK_LEN) {
        free(tmp); proto_send_line(fd, "FAIL invalid public key"); return NULL;
    }

    unsigned char sig[AUTH_SIG_LEN];
    size_t sig_len = 0;
    if (sodium_base642bin(sig, sizeof(sig), sig_b64, strlen(sig_b64),
                          NULL, &sig_len, NULL,
                          sodium_base64_VARIANT_ORIGINAL) != 0
        || sig_len != AUTH_SIG_LEN) {
        free(tmp); proto_send_line(fd, "FAIL invalid signature"); return NULL;
    }
    free(tmp);

    if (proto_verify_challenge(challenge, CHALLENGE_LEN, sig, pk) != 0) {
        proto_send_line(fd, "FAIL signature verification failed"); return NULL;
    }

    char *hex = malloc(AUTH_PK_LEN * 2 + 1);
    if (!hex) { proto_send_line(fd, "FAIL internal error"); return NULL; }
    sodium_bin2hex(hex, AUTH_PK_LEN * 2 + 1, pk, AUTH_PK_LEN);

    if (strcmp(hex, allowed_hex) != 0) {
        proto_send_line(fd, "FAIL access denied");
        free(hex); return NULL;
    }
    return hex;
}
