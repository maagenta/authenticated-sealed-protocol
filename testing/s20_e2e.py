"""XXII. End-to-end and integration (T-374 to T-389)."""

import os
import pty
import re
import select
import shutil
import signal
import socket
import subprocess
import threading
import time
import tty

import docsx
import harness
import lib
import libsodium as ls
import net
import peers
import servers
from harness import FINDING, PIN, ROOT, case, check, eq, skip, slack_ms
from keyfiles import make_identity
from net import Peer
from s14_connect import connect_to, new_conn

TIMEOUT, REJECTED = -605, -703


# ----------------------------------------------------------- building the documents' programs

def compile_cmd(out, sources, include_dirs):
    c_flags, ld_flags = lib.sodium()
    cmd = [lib.cc(), "-Wall", "-Wextra", "-O1", "-o", out]
    for d in include_dirs:
        cmd += ["-I", d]
    return cmd + c_flags + sources + ld_flags


def layout():
    """A project directory next to a protocol/ that is this repository."""
    top = harness.tmpdir("proj")
    os.symlink(ROOT, os.path.join(top, "protocol"))
    app = os.path.join(top, "app")
    os.mkdir(app)
    return top, app


def replace_port(text, old, port, expect):
    check(text.count(old) == expect, "expected %d occurrences of %r, found %d" % (expect, old, text.count(old)))
    return text.replace(old, str(port))


def keygen_in(directory):
    p = subprocess.run([lib.build_keygen()], cwd=directory, stdin=subprocess.DEVNULL,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    eq(p.returncode, 0, "keygen")


def listening(port, proc=None, timeout=10.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if proc is not None and proc.poll() is not None:
            raise harness.Fail("the server exited with %s: %s" % (proc.returncode, proc.stderr.read().decode()[-300:]))
        try:
            socket.create_connection(("127.0.0.1", port), timeout=1).close()
            return
        except OSError:
            time.sleep(0.02)
    raise harness.Fail("nothing listening on port %d" % port)


class Vault(object):
    """The worked example of docs.md, built from its text with only the port changed."""

    def __init__(self):
        self.port = net.free_port()
        top, app = layout()
        self.dir = app
        client = docsx.find_block("docs.md", "c", "/* vault-client.c */")
        server = docsx.find_block("docs.md", "c", "/* vault-server.c */")
        for name, text in (("vault-client.c", client), ("vault-server.c", server)):
            check(text.count("#define VAULT_PORT 5000") == 1, "docs.md no longer defines VAULT_PORT once in " + name)
            with open(os.path.join(app, name), "w") as f:     # only the port differs from the document
                f.write(text.replace("#define VAULT_PORT 5000", "#define VAULT_PORT %d" % self.port))
        os.symlink(ROOT, os.path.join(app, "protocol"))
        lib_src = [os.path.join(ROOT, s) for s in ("status.c", "wire.c", "crypto.c", "auth.c")]
        for exe, src, extra in (("vault-client", "vault-client.c", []), ("vault-server", "vault-server.c", ["serve.c"])):
            cmd = compile_cmd(os.path.join(app, exe), [os.path.join(app, src)] + lib_src
                              + [os.path.join(ROOT, e) for e in extra], [app])
            rc, out = lib.run(cmd)
            check(rc == 0, "cannot build %s from docs.md: %s" % (exe, out[-500:]))
        keygen_in(app)
        self.proc = None

    def start(self):
        self.proc = subprocess.Popen([os.path.join(self.dir, "vault-server")], cwd=self.dir,
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.DEVNULL)
        listening(self.port, self.proc)

    def client(self, *args, cwd=None):
        p = subprocess.run([os.path.join(self.dir, "vault-client")] + list(args), cwd=cwd or self.dir,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.DEVNULL, timeout=60)
        return p.returncode, p.stdout.decode(), p.stderr.decode()

    def stop(self):
        if self.proc and self.proc.poll() is None:
            self.proc.send_signal(signal.SIGTERM)
            try:
                self.proc.wait(15)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        return self.proc.returncode if self.proc else None

    def close(self):
        if self.proc and self.proc.poll() is None:
            self.proc.kill()
            self.proc.wait(5)
        for stream in (self.proc.stdout, self.proc.stderr) if self.proc else ():
            try:
                stream.close()
            except OSError:
                pass


@case("T-374")
def t374():
    """The worked example of docs.md runs."""
    v = Vault()
    try:
        v.start()
        eq(v.client("note one"), (0, "OK 1\n", ""), "the first PUT")
        eq(v.client("note two"), (0, "OK 2\n", ""), "the second PUT")
        rc, out, err = v.client()
        eq((rc, out), (0, "[1] note one\n[2] note two\n"), "GET (stderr: %s)" % err[:100])
        db = open(os.path.join(v.dir, "vault.db"), "rb").read()
        check(b"note one" not in db and b"note two" not in db, "the storage file holds a plaintext")
        eq(v.stop(), 0, "the server's exit status")
        out = v.proc.stdout.read().decode()
        check("vault-server stopped" in out, "the server's output: %r" % out[-100:])
    finally:
        v.close()


@case("T-375")
def t375():
    """The quick start of README.md runs."""
    port = net.free_port()
    top, app = layout()
    client = docsx.find_block("README.md", "c", 'proto_connect(&c, "127.0.0.1", 5000)')
    server = docsx.find_block("README.md", "c", "proto_serve(5000")
    with open(os.path.join(app, "client.c"), "w") as f:
        f.write(replace_port(client, "5000", port, 1))
    with open(os.path.join(app, "server.c"), "w") as f:
        f.write(replace_port(server, "5000", port, 1))
    lib_src = [os.path.join(ROOT, s) for s in ("status.c", "wire.c", "crypto.c", "auth.c")]
    for exe, src, extra in (("client", "client.c", []), ("server", "server.c", ["serve.c"])):
        cmd = compile_cmd(os.path.join(app, exe), [os.path.join(app, src)] + lib_src
                          + [os.path.join(ROOT, e) for e in extra], [top])
        rc, out = lib.run(cmd)
        check(rc == 0, "cannot build the README's %s: %s" % (exe, out[-500:]))
    keygen_in(app)
    proc = subprocess.Popen([os.path.join(app, "server")], cwd=app, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, stdin=subprocess.DEVNULL)
    try:
        listening(port, proc)
        p = subprocess.run([os.path.join(app, "client")], cwd=app, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           stdin=subprocess.DEVNULL, timeout=60)
        eq((p.returncode, p.stdout.decode()), (0, "server said: OK\n"), "the client (stderr: %s)" % p.stderr.decode()[:100])
    finally:
        proc.kill()
        proc.wait(5)
        proc.stdout.close()
        proc.stderr.close()


@case("T-376")
def t376():
    """The first connection registers, and later ones go straight to OK."""
    P = lib.proto()
    port = net.free_port()
    top, app = layout()
    recipe = docsx.find_block("docs.md", "c", "static void on_client(int fd, const char *user, void *ctx) {\n    storage_open")
    store = harness.tmpdir("store")
    program = r'''
#include "protocol/serve.h"
#include "protocol/crypto.h"
#include "protocol/wire.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static const char *g_dir;
static int storage_open(const char *path) { g_dir = path; return 0; }
static int storage_user_exists(const char *user) {
    char p[512];
    snprintf(p, sizeof p, "%s/%s", g_dir, user);
    return access(p, F_OK) == 0;
}
static int storage_register_user(const char *user, const char *enc_b64) {
    char p[512];
    snprintf(p, sizeof p, "%s/%s", g_dir, user);
    FILE *f = fopen(p, "w");
    if (!f) return -1;
    fprintf(f, "%s\n", enc_b64);
    fclose(f);
    snprintf(p, sizeof p, "%s/registrations.log", g_dir);
    f = fopen(p, "a");
    if (f) { fprintf(f, "registered %s\n", user); fclose(f); }
    return 0;
}
static void storage_close(void) {}

''' + recipe + r'''
int main(int argc, char **argv) {
    (void)argc;
    char allowed[AUTH_PK_LEN * 2 + 1];
    if (proto_load_pubkey_hex("auth.pub", allowed, sizeof allowed) != 0) return 1;
    return proto_serve(atoi(argv[1]), allowed, on_client, argv[2], NULL) == 0 ? 0 : 1;
}
'''
    with open(os.path.join(app, "registrar.c"), "w") as f:
        f.write(program)
    lib_src = [os.path.join(ROOT, s) for s in ("status.c", "wire.c", "crypto.c", "auth.c", "serve.c")]
    rc, out = lib.run(compile_cmd(os.path.join(app, "registrar"), [os.path.join(app, "registrar.c")] + lib_src, [top]))
    check(rc == 0, "the recipe of docs.md does not build: %s" % out[-600:])
    keygen_in(app)
    ident = make_identity(app, write=False)
    ident.auth_key, ident.auth_pub, ident.enc_key = [os.path.join(app, n) for n in ("auth.key", "auth.pub", "enc.key")]
    proc = subprocess.Popen([os.path.join(app, "registrar"), str(port), store], cwd=app, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, stdin=subprocess.DEVNULL)
    try:
        listening(port, proc)
        rc, conn = connect_to(P, ident, port)
        eq(rc, 0, "the first connection")
        user = bytes(conn.keys.auth_pk).hex()
        P.close(conn)
        stored = open(os.path.join(store, user)).read().strip()
        eq(len(stored), 44, "length of the stored key")
        eq(ls.b64d(stored), bytes(conn.keys.enc_pk), "the stored key against the client's enc_pk")
        for n in (2, 3):
            rc, conn = connect_to(P, ident, port)
            eq(rc, 0, "connection %d" % n)
            P.close(conn)
        eq(open(os.path.join(store, user)).read().strip(), stored, "the stored key after later connections")
        eq(open(os.path.join(store, "registrations.log")).read().splitlines(), ["registered " + user],
           "registrations")
    finally:
        proc.kill()
        proc.wait(5)
        proc.stdout.close()
        proc.stderr.close()


@case("T-377")
def t377():
    """Two copies of one identity are one user."""
    v = Vault()
    try:
        v.start()
        other = harness.tmpdir("other")
        for name in ("auth.key", "enc.key"):
            shutil.copy(os.path.join(v.dir, name), os.path.join(other, name))
        eq(v.client("from the first copy")[:2], (0, "OK 1\n"), "a PUT from the first copy")
        eq(v.client("from the second copy", cwd=other)[:2], (0, "OK 2\n"), "a PUT from the second copy")
        eq(v.client(cwd=other)[:2], (0, "[1] from the first copy\n[2] from the second copy\n"), "GET from the second copy")
        eq(v.client()[:2], (0, "[1] from the first copy\n[2] from the second copy\n"), "GET from the first copy")
    finally:
        v.close()


@case("T-378")
def t378():
    """A wrong allowlist is refused at connect."""
    P = lib.proto()
    mine, other = make_identity(), make_identity()
    wrong = {
        "a wrong allowlist": "ab" * 32,
        "another identity's auth.pub": P.load_pubkey_hex(other.auth_pub)[1][:64].decode(),
        "the client's enc.key loaded as auth.pub": P.load_pubkey_hex(mine.enc_key)[1][:64].decode(),
    }
    for what, allow in wrong.items():
        with servers.Server(allow, "ok") as srv:
            rc, conn = connect_to(P, mine, srv.port)
            eq(rc, REJECTED, what)


@case("T-379")
def t379():
    """A client written from the wire appendix alone interoperates."""
    ident = make_identity()
    with servers.Server(ident.hex, "ok") as srv:
        s = socket.create_connection(("127.0.0.1", srv.port))
        peer = Peer(s)
        eq(peers.client_handshake(peer, ident), b"OK", "the verdict")
        peer.send_line(b"PING")
        eq(peer.recv_line(), b"PONG", "a command")
        peer.send_line(b"QUIT")
        eq(peer.recv_line(), b"BYE", "the goodbye")
        s.close()


@case("T-380")
def t380():
    """A server written from the wire appendix alone interoperates."""
    P = lib.proto()
    ident = make_identity()
    ls_ = net.listener()

    def server():
        conn, _ = ls_.accept()
        peer = Peer(conn)
        info = peers.server_handshake(peer, ident.auth_pk, b"REGISTER")
        line = peer.recv_line(5)
        check(line is not None and line.startswith(b"REGISTER ") and len(line) == 53, "the REGISTER line: %r" % (line,))
        peer.send_line(b"OK")
        while True:
            l = peer.recv_line(10)
            if l is None:
                break
            if l == b"QUIT":
                peer.send_line(b"BYE")
        return ls.b64d(line[9:])
    w = net.Worker(server)
    rc, conn = connect_to(P, ident, ls_.getsockname()[1])
    eq(rc, 0, "proto_connect, registration included")
    P.close(conn)
    eq(w.finish(), ident.enc_pk, "the key the server was sent")


@case("T-381", FINDING)
def t381():
    """The protocol works over a pair of pipes."""
    P = lib.proto()
    ident = make_identity()
    rc, keys = P.load_keys(ident.auth_key, ident.enc_key)
    eq(rc, 0, "proto_load_keys")
    master, slave = pty.openpty()                 # one descriptor that carries both ways and is no socket
    tty.setraw(master)
    tty.setraw(slave)

    def read_line():
        buf = b""
        deadline = time.monotonic() + 5
        while not buf.endswith(b"\n"):
            if not select.select([master], [], [], max(0.0, deadline - time.monotonic()))[0]:
                raise harness.Fail("nothing from the client over the terminal")
            buf += os.read(master, 1)
        return buf[:-1]

    def server():
        check(read_line() == b"HELLO", "the client did not say HELLO")
        challenge = os.urandom(32)
        os.write(master, b"CHALLENGE " + ls.b64(challenge).encode() + b"\n")
        auth = read_line().split(b" ")
        check(ls.verify_detached(ls.b64d(auth[2]), challenge, ls.b64d(auth[1])), "bad signature")
        os.write(master, b"OK\n")
    w = net.Worker(server)
    rc = P.auth_client(slave, keys)
    eq(rc, 0, "proto_auth_client over a descriptor that is not a socket (a program's stdin and stdout)")
    w.finish()


def over_the_wire(P, ident, port, plain, variant_cap=None):
    """PUT plain to a vault, then GET it back: (reply to PUT, plaintext of the entry or None)."""
    rc, conn = connect_to(P, ident, port)
    eq(rc, 0, "proto_connect")
    sealed = P.seal_new(plain, bytes(conn.keys.enc_pk))
    check(sealed is not None, "cannot seal %d bytes" % len(plain))
    eq(P.send_prefixed(conn.fd, "PUT ", sealed), 0, "sending the entry")
    rc, reply = P.recv_line(conn.fd, 128)
    if reply.startswith(b"OK"):
        P.send_line(conn.fd, "GET")
        rc, header = P.recv_line(conn.fd, 128)
        eq(header, b"ENTRIES 1", "the header of GET")
        row, status = P.recv_dyn(conn.fd)
        eid, _, b64 = row.partition(b" ")
        back = P.unseal_full(b64, bytes(conn.keys.enc_pk), bytes(conn.keys.enc_sk))[0]
        P.close(conn)
        return reply, back
    return reply, conn


@case("T-382", tags=("slow",), timeout=300)
def t382():
    """A 10 MiB entry round-trips."""
    P = lib.proto()
    ident = make_identity()
    plain = os.urandom(10 * 1024 * 1024)
    with servers.Server(ident.hex, "vault") as srv:
        reply, back = over_the_wire(P, ident, srv.port, plain)
        eq(reply, b"OK 1", "the reply to PUT")
        check(back == plain, "the 10 MiB entry did not come back identical")


@case("T-383")
def t383():
    """An entry over the limit is refused cleanly."""
    P = lib.proto()
    ident = make_identity()
    plain = os.urandom(13 * 1000 * 1000)
    with servers.Server(ident.hex, "vault") as srv:
        rc, conn = connect_to(P, ident, srv.port)
        eq(rc, 0, "proto_connect")
        sealed = P.seal_new(plain, bytes(conn.keys.enc_pk))
        check(len(sealed) + 4 > 16 * 1024 * 1024, "test data is wrong: the line is not past MAX_PAYLOAD")
        sender = net.Worker(lambda: P.send_prefixed(conn.fd, "PUT ", sealed))
        rc, reply = P.recv_line_timeout(conn.fd, 20000, 128)
        eq((rc, reply), (22, b"FAIL message too large"), "the server's answer")
        eq(P.recv_line_timeout(conn.fd, 20000, 128)[0], -603, "after the FAIL, the end of the stream")
        os.close(conn.fd)
        sender.finish(60)
        srv.wait_log("vault ended status=-604")


class Relay(object):
    """A process in the middle of a connection: forwards both ways and records them."""

    def __init__(self, target_port):
        self.listener = net.listener()
        self.port = self.listener.getsockname()[1]
        self.target = target_port
        self.c2s, self.s2c = bytearray(), bytearray()
        self.worker = net.Worker(self._run)

    def _run(self):
        client, _ = self.listener.accept()
        server = socket.create_connection(("127.0.0.1", self.target))
        a = net.Worker(self._pump, client, server, self.c2s)
        b = net.Worker(self._pump, server, client, self.s2c)
        a.finish(60)
        b.finish(60)

    @staticmethod
    def _pump(src, dst, log):
        try:
            while True:
                data = src.recv(65536)
                if not data:
                    break
                log += data
                dst.sendall(data)
        except OSError:
            pass
        try:
            dst.shutdown(socket.SHUT_WR)
        except OSError:
            pass

    def finish(self):
        self.worker.finish(60)


@case("T-384")
def t384():
    """The relay attack works today."""
    P = lib.proto()
    ident = make_identity()
    with servers.Server(ident.hex, "ok") as srv:
        rl = net.listener()

        def relay():
            client, _ = rl.accept()
            server = socket.create_connection(("127.0.0.1", srv.port))
            cp, sp = Peer(client), Peer(server)
            sp.send_line(cp.recv_line())                   # HELLO
            cp.send_line(sp.recv_line())                   # CHALLENGE
            sp.send_line(cp.recv_line())                   # AUTH, signed by someone else
            verdict = sp.recv_line()
            cp.send_line(verdict)                          # the real client is let through ...
            sp.send_line(b"PING")                          # ... and the relay uses the session itself
            return verdict, sp.recv_line()
        w = net.Worker(relay)
        rc, conn = connect_to(P, ident, rl.getsockname()[1])
        eq(rc, 0, "the client's own connect through the relay")
        verdict, pong = w.finish()
        eq((verdict, pong), (b"OK", b"PONG"), "the session the relay holds, without auth.key")
        os.close(conn.fd)


@case("T-385")
def t385():
    """A forged entry opens as genuine today."""
    P = lib.proto()
    ident = make_identity()
    with servers.Server(ident.hex, "register") as srv:
        rc, conn = connect_to(P, ident, srv.port)
        eq(rc, 0, "proto_connect")
        registered = ls.b64d(srv.wait_log("rx REGISTER ")[0][3 + 9:])
        P.close(conn)
    forged = ls.b64(ls.box_seal(b"written by the server", registered))
    plain = P.unseal_full(forged, ident.enc_pk, ident.enc_sk)[0]
    eq(plain, b"written by the server", "an entry sealed by the server to the registered key")


@case("T-386")
def t386():
    """A peer that ends its lines with \\r\\n works."""
    ident = make_identity()
    with servers.Server(ident.hex, "ok") as srv:
        s = socket.create_connection(("127.0.0.1", srv.port))
        peer = Peer(s)
        peer.send(b"HELLO\r\n")
        line = peer.recv_line()
        check(line.startswith(b"CHALLENGE "), "no challenge: %r" % (line,))
        ch = ls.b64d(line[10:])
        sig = ls.sign_detached(ch, ident.auth_sk)
        peer.send(b"AUTH " + ls.b64(ident.auth_pk).encode() + b" " + ls.b64(sig).encode() + b"\r\n")
        eq(peer.recv_line(), b"OK", "the verdict")
        peer.send(b"PING\r\n")
        eq(peer.recv_line(), b"PONG", "a command")
        s.close()


@case("T-387", tags=("slow",), timeout=120)
def t387():
    """A stop under load lets clients finish."""
    P = lib.proto()
    ident = make_identity()
    with servers.Server(ident.hex, "ok", drain=5000) as srv:
        conns = []
        for _ in range(10):
            rc, conn = connect_to(P, ident, srv.port)
            eq(rc, 0, "proto_connect")
            conns.append(conn)
        t0 = net.now()
        os.kill(srv.pid, signal.SIGTERM)

        def finish(conn):
            time.sleep(1.2)
            eq(servers.command(P, conn, "PING"), (4, b"PONG"), "a command after the stop")
            P.send_line(conn.fd, "QUIT")
            answer = P.recv_line(conn.fd, 64)
            os.close(conn.fd)                         # the client hangs up after BYE
            return answer
        workers = [net.Worker(finish, c) for c in conns]
        results = [w.finish(30) for w in workers]
        eq(results, [(3, b"BYE")] * 10, "the answers to QUIT")
        eq(srv.wait_exit(15), 0, "the server's exit status")
        took = net.ms_since(t0)
        check(1000 <= took <= 4500, "the server returned %.0f ms after the stop, when the last client had quit" % took)


@case("T-388", timeout=600)
def t388():
    """The largest message fits, and one byte more does not."""
    runs = [("pay4096", 4096)]
    if harness.OPTS is not None and harness.OPTS.slow:
        runs.append(("fast", 16 * 1024 * 1024))
    for variant, cap in runs:
        P = lib.proto(variant)
        ident = make_identity()
        biggest = (cap - 4) // 4 * 3 - 48
        with servers.Server(ident.hex, "vault", variant=variant) as srv:
            plain = os.urandom(biggest)
            reply, back = over_the_wire(P, ident, srv.port, plain)
            eq(reply, b"OK 1", "%s: the reply to the largest plaintext (%d bytes)" % (variant, biggest))
            check(back == plain, "%s: the largest plaintext did not come back identical" % variant)
        with servers.Server(ident.hex, "vault", variant=variant) as srv:
            rc, conn = connect_to(P, ident, srv.port)
            eq(rc, 0, "proto_connect")
            sealed = P.seal_new(os.urandom(biggest + 1), bytes(conn.keys.enc_pk))
            eq(len(sealed) + 4, cap + 4, "%s: the line with one byte more" % variant)
            sender = net.Worker(lambda: P.send_prefixed(conn.fd, "PUT ", sealed))
            rc, reply = P.recv_line_timeout(conn.fd, 20000, 128)
            eq((rc, reply), (22, b"FAIL message too large"), "%s: the answer to one byte more" % variant)
            eq(P.recv_line_timeout(conn.fd, 20000, 128)[0], -603, "%s: the end of the stream after the FAIL" % variant)
            os.close(conn.fd)
            sender.finish(60)
            srv.wait_log("vault ended status=-604")


B64_44 = rb"[A-Za-z0-9+/]{43}="
B64_88 = rb"[A-Za-z0-9+/]{86}=="


@case("T-389")
def t389():
    """The transcript matches the grammar."""
    P = lib.proto()
    ident = make_identity()
    with servers.Server(ident.hex, "register") as srv:
        relay = Relay(srv.port)
        rc, conn = connect_to(P, ident, relay.port)
        eq(rc, 0, "proto_connect with registration")
        P.close(conn)
        relay.finish()
    c2s, s2c = bytes(relay.c2s), bytes(relay.s2c)
    for name, stream in (("client", c2s), ("server", s2c)):
        check(stream.endswith(b"\n") and b"\r" not in stream, "%s lines do not end in \\n alone: %r" % (name, stream[-40:]))
    client_ok = [rb"HELLO", rb"AUTH " + B64_44 + rb" " + B64_88, rb"REGISTER " + B64_44, rb"QUIT"]
    server_ok = [rb"CHALLENGE " + B64_44, rb"REGISTER", rb"OK", rb"BYE", rb"FAIL [a-z ]+"]
    for line in c2s.split(b"\n")[:-1]:
        check(any(re.fullmatch(p, line) for p in client_ok), "a client line outside the grammar: %r" % line[:60])
    for line in s2c.split(b"\n")[:-1]:
        check(any(re.fullmatch(p, line) for p in server_ok), "a server line outside the grammar: %r" % line[:60])
    eq([l.split(b" ")[0] for l in c2s.split(b"\n")[:-1]], [b"HELLO", b"AUTH", b"REGISTER", b"QUIT"], "client verbs")
    eq([l.split(b" ")[0] for l in s2c.split(b"\n")[:-1]], [b"CHALLENGE", b"REGISTER", b"OK", b"BYE"], "server verbs")
