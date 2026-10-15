"""Starting and steering the serve_probe server from a test."""

import os
import signal
import socket
import subprocess
import time

import harness
import lib
import net
import runprobe
from harness import Fail, check


def probe_path(variant="fast"):
    return runprobe.build("serve_probe", variant=variant)


class Server(object):
    """serve_probe running as a process of its own, listening on 127.0.0.1."""

    def __init__(self, allow, handler="ok", variant="fast", port=None, bind="127.0.0.1",
                 drain=None, ms=None, ctx=None, flags=(), group=False, stdout=None,
                 wait=True, extra=()):
        self.allow = allow
        self.port = port or net.free_port()
        self.dir = harness.tmpdir("srv")
        self.log_path = os.path.join(self.dir, "log")
        self.out_path = os.path.join(self.dir, "stdout")
        cmd = [probe_path(variant), "--port", str(self.port), "--allow", allow,
               "--log", self.log_path, "--handler", handler]
        if bind:
            cmd += ["--bind", bind]
        if drain is not None:
            cmd += ["--drain", str(drain)]
        if ms is not None:
            cmd += ["--ms", str(ms)]
        if ctx is not None:
            cmd += ["--ctx", str(ctx)]
        cmd += ["--sigterm-stop"] + list(flags) + list(extra)
        out = open(self.out_path, "wb") if stdout is None else stdout
        self.proc = subprocess.Popen(cmd, stdout=out, stderr=subprocess.PIPE, stdin=subprocess.DEVNULL,
                                     start_new_session=group)
        self.group = group
        self.pid = self.proc.pid
        self.exited = None
        if wait:
            self.wait_listening()

    # ------------------------------------------------------------ state

    def wait_listening(self, timeout=15.0):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.proc.poll() is not None:
                raise Fail("the server exited with %s before listening: %s" % (self.proc.returncode, self.stderr()))
            try:
                c = socket.create_connection(("127.0.0.1", self.port), timeout=1)
                c.close()
                return
            except OSError:
                time.sleep(0.01)
        raise Fail("the server did not start listening in %.0f s" % timeout)

    def stderr(self):
        try:
            if self.proc.poll() is not None:
                return self.proc.stderr.read().decode("utf-8", "replace")[-500:]
        except (OSError, ValueError):
            pass
        return ""

    def log(self):
        try:
            with open(self.log_path, "rb") as f:
                return f.read().decode("utf-8", "replace").splitlines()
        except OSError:
            return []

    def stdout_text(self):
        try:
            with open(self.out_path, "rb") as f:
                return f.read().decode("utf-8", "replace")
        except OSError:
            return ""

    def wait_log(self, prefix, timeout=5.0, count=1):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            hits = [l for l in self.log() if l.startswith(prefix)]
            if len(hits) >= count:
                return hits
            time.sleep(0.01)
        raise Fail("the server log never showed %r x%d; it has: %s" % (prefix, count, self.log()[-6:]))

    def grep(self, prefix):
        return [l for l in self.log() if l.startswith(prefix)]

    def field(self, prefix, name):
        """Value of name=VALUE in the last log line that starts with prefix."""
        lines = self.grep(prefix)
        if not lines:
            raise Fail("no log line starts with %r: %s" % (prefix, self.log()[-6:]))
        for part in lines[-1].split():
            if part.startswith(name + "="):
                return part[len(name) + 1:]
        raise Fail("no %s= in %r" % (name, lines[-1]))

    def children(self):
        """Live processes whose parent is the server: [(pid, state)]."""
        return net.child_pids(self.pid)

    # --------------------------------------------------------- control

    def signal(self, sig):
        os.kill(self.pid, sig)

    def signal_group(self, sig):
        os.killpg(self.pid, sig)

    def stop(self, sig=signal.SIGTERM, timeout=15.0):
        """Send sig and wait for the server to exit; returns its exit status."""
        if self.proc.poll() is None:
            os.kill(self.pid, sig)
        try:
            self.proc.wait(timeout)
        except subprocess.TimeoutExpired:
            raise Fail("the server did not exit within %.0f s of the signal" % timeout)
        return self.proc.returncode

    def wait_exit(self, timeout=15.0):
        try:
            self.proc.wait(timeout)
        except subprocess.TimeoutExpired:
            raise Fail("the server is still running after %.0f s" % timeout)
        return self.proc.returncode

    def kill(self):
        try:
            if self.group:
                os.killpg(self.pid, signal.SIGKILL)
            elif self.proc.poll() is None:
                os.kill(self.pid, signal.SIGKILL)
        except OSError:
            pass
        try:
            self.proc.wait(5)
        except subprocess.TimeoutExpired:
            pass

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.kill()
        try:
            self.proc.stderr.close()
        except OSError:
            pass


def connect(P, ident, port, host="127.0.0.1"):
    """proto_connect with the identity's keys: (rc, conn, keys)."""
    rc, keys = P.load_keys(ident.auth_key, ident.enc_key)
    if rc != 0:
        raise Fail("cannot load the identity: %d" % rc)
    conn = lib.Conn.new(keys)
    rc = P.connect(conn, host, port)
    return rc, conn, keys


def command(P, conn, line, bufsz=4096):
    """Send a line on a connection and read the reply line."""
    P.send_line(conn.fd, line)
    rc, text = P.recv_line(conn.fd, bufsz)
    return rc, text
