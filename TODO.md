# TODO

Work this library has decided on and deliberately not done yet, with the
reason for the delay. Anything here has a design; what it lacks is the
right moment.

## Graceful shutdown of `proto_serve`, parent side — v1.2

**What is missing.** `proto_serve` blocks in `accept()` and returns only
when it cannot serve. An application has no way to say "stop": no way to
release the port, let the clients in progress finish, close its storage and
exit with status 0. The only way to stop a server today is to kill the
process, which cuts whoever was mid-command.

The design is settled and in two halves. This one does not depend on
bidirectionality; the child side does, and waits for v2.0 (below).

**Parent side.** `proto_serve_stop()` writes one byte into a pipe the
library creates at startup — a `write()` is one of the few things a signal
handler may safely do — and the accept loop waits on both the listening
socket and that pipe with `poll()`. A byte stays in the pipe until it is
read, so a stop can never be missed in the window between checking a flag
and blocking again, which is what makes a bare flag the wrong mechanism.
On stop the loop closes the listening socket (the port is free at once: the
children closed their copy of it when they were forked) and returns
`PROTO_OK`, since a stop that was asked for is not a failure. Established
connections are untouched by that close: a connection is identified by the
full four-tuple, not by the port, so each child keeps talking to its client
over a socket whose local port is still the server's. A new field in
`proto_serve_opts_t`, `drain_ms`, says how long the parent waits, reaping,
for those children to finish before it returns — a deployment decision,
which is what that struct is for.

The application keeps control of signals, which is the point of putting
the mechanism in a function rather than having the library seize `SIGTERM`:

```c
static void on_term(int sig) { (void)sig; proto_serve_stop(); }
signal(SIGTERM, on_term);
signal(SIGINT,  on_term);

int rc = proto_serve(port, allowed, handler, &ctx, &opts);
if (rc == PROTO_OK) { /* asked to stop: close storage, exit 0 */ }
```

**What the gap costs until then.** A killed server leaves its children
orphaned; one killed mid-command loses that command and leaves its client
without a reply. SQLite rolls the transaction back, so storage is not
corrupted, but the entry is gone and the client cannot tell "not saved"
from "saved, answer lost". The window is small — a command takes
milliseconds against sessions that idle for hours — which is why this is
worth doing well later rather than badly now.

**Workaround meanwhile.** An application that needs a child to stop can do
it without the library: call `shutdown()` on the connection from its own
signal handler, which makes the blocked read fail. `docs.md` documents it
under cancelling a blocked call.

## Graceful shutdown of `proto_serve`, child side — with bidirectionality, v2.0

**What is missing.** Telling the children to wrap up, so that a stop lands
*between* messages and never inside one. The readers already guarantee half
of that — `proto_recv_line*` returns a line only once it has seen the
newline, and `write_all` resumes short writes — so no message is ever cut
unless a process is killed. The other half has three parts.

- **Reaching them.** A signal sent to the whole group (Ctrl-C, systemd's
  default `KillMode`) reaches the children through the handler they
  inherit; one sent to the parent alone (`kill`, `docker stop`) does not,
  and the parent keeps no pids. Rather than keep them — and make sure never
  to signal one the reaper has collected and the system has handed to
  another process — the parent holds the write end of a pipe whose read
  end every child inherits, and closes it on a stop: every child sees
  end-of-file at once, with no pids and no signals. The write end must be
  the parent's alone, closed in each child and close-on-exec.
- **Noticing.** The stop is one more source the child waits on, consulted
  at line boundaries only, where the reader returns a new
  `PROTO_E_STOPPING`. Mid-line, the read finishes the line and delivers it
  as usual; the stop is seen on the next call. A command already executing
  is never interrupted: the handler finishes it and sends its reply before
  it reads again.
- **Leaving.** The handler's loop ends on `PROTO_E_STOPPING` as it ends on
  any failed read, and the library, not the handler, says `BYE` once the
  handler returns — as it says `FAIL` during the handshake — so existing
  handlers need no change. It then closes without leaving client data
  unread: `shutdown` for writing, then read until end-of-file or
  `QUIT_TIMEOUT_MS`. A close with data unread makes the kernel reset the
  connection, and the reset can discard the `BYE`; it is the same reason
  the busy path reads `HELLO` before its `FAIL`.

**What `BYE` says.** Nothing beyond itself: the bare word that already
answers `QUIT`. In a lock-step protocol its position says it all: every
command the server executed was answered before the `BYE`, and a `BYE`
where a reply was expected means that command was not executed.

    C: PUT …    S: OK 42    executed and answered
                (stop)
    C: PUT …    S: BYE      not executed

A `BYE` that named the last thing done would repeat what the client already
has. Where the client really is left in doubt — a server killed, crashed or
cut off mid-command — there is no `BYE` at all; that case is closed by
idempotent commands, which are the application's. On the client,
`proto_recv_reply` recognizes an unprompted `BYE` as the library's word,
like its handshake lines, and reports it as a status — likely the same
`PROTO_E_STOPPING` — instead of handing it over as a reply. A v1.x client
sees an unexpected reply, then end-of-file.

**Why this half waits.** It depends on the shape of the child's read loop,
and bidirectionality changes that shape. A child that can be pushed
messages must wait on two sources at once — its client and whatever
produces the pushes — which means it will poll, as the `proto_wait` loop
documented on the `temp-docs-bidirectional` branch does. Once it polls, the
stop is one more source to wait on: the pipe needs no pids, and the poll
needs no signal to wake it. Telling an unprompted `BYE` from a reply is
likewise the problem bidirectionality solves for pushes. Building the
signal-and-flag machinery now would mean discarding it then.

**Set aside for v1.2.** Keeping pids, signalling each child, and having a
handler the library installs in the child call `shutdown(fd, SHUT_RD)`.
Measured on macOS: a read waiting for the next command returns end-of-file
at once, and the child can still write `BYE`, which the client receives;
a command sent but not yet read is discarded, so the client gets `BYE` in
its place, as the rule above says; a client that sends after the stop
still reads the `BYE`. On Linux the unread command would be read and
answered instead (reasoned, not measured). It works, but it doubles the
v1.2 change, takes `SIGTERM` from the application in every child, makes a
stop look like "client gone" to the handler, and v2.0's poll replaces it.
It is the fallback if v2.0 slips.

**Until then.** With v1.2, a stop frees the port and waits up to
`drain_ms` for the children, but cannot ask one to finish: a child still
serving when `drain_ms` runs out is left running. A child that receives the
signal itself ends at once — `proto_serve_stop()`, called from the
application's handler it inherited, exits — which is what the signal would
have done without that handler, so children behave as they did before v1.2.

## Other pending work

- **Tests.** The structure and `test.h` are agreed; nothing is written.
  Every fix in v1.1 was verified by a one-off program, which is evidence
  but not a suite.
- **CI — v1.2.** No `.github/workflows/ci.yml`. The build has only ever been
  exercised on macOS with clang; the Linux paths (`TCP_KEEPIDLE`, the
  busy-loop `accept` case, the kernel's own connect timeout) are reasoned
  about, not measured.
- **`crypto.c` has never been read line by line — v1.2.** Its absence from
  the fixed list means nobody looked, not that it is clean.
