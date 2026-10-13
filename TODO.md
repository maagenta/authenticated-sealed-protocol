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
unless a process is killed. What is missing is how a child learns that it
should finish: a flag it consults at line boundaries only, and a new
`PROTO_E_STOPPING` for the reader to return there, so the application's
handler can answer `BYE` and return. Mid-line, the read finishes the line
and delivers it as usual; the stop is seen on the next call.

**Why this half waits.** It depends on the shape of the child's read loop,
and bidirectionality changes that shape. A child that can be pushed
messages must wait on two sources at once — its client and whatever
produces the pushes — which means it will poll. Once it polls, a stop is
one more source to wait on, and the signal-and-flag machinery sketched
above becomes the wrong answer to a question that no longer exists.
Building it now would mean discarding it then.

**Until then.** With v1.2, a stop frees the port and waits up to
`drain_ms` for the children, but it cannot ask a child to finish: one
that is still serving when `drain_ms` runs out is left running, as today.

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
