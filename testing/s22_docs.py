"""XXIV. Documentation and source-level invariants (T-407 to T-416)."""

import concurrent.futures
import functools
import glob
import math
import os
import re

import docsx
import harness
import lib
import statuses
from harness import FINDING, ROOT, case, check, eq

HEADERS = ["status.h", "wire.h", "crypto.h", "auth.h", "serve.h"]
SOURCES = lib.LIB_SOURCES


def broken(msg):
    """The analysis itself is wrong: an error, so that not even a finding hides it."""
    raise RuntimeError(msg)


def strip_comments(text):
    """C source without its comments; string and character constants are left alone."""
    out, i, n = [], 0, len(text)
    while i < n:
        two = text[i:i + 2]
        if two == "/*":
            j = text.find("*/", i + 2)
            j = n if j < 0 else j + 2
            out.append(" " + "\n" * text.count("\n", i, j))
            i = j
        elif two == "//":
            j = text.find("\n", i)
            i = n if j < 0 else j
        elif text[i] in "\"'":
            j = i + 1
            while j < n and text[j] != text[i]:
                j += 2 if text[j] == "\\" else 1
            out.append(text[i:j + 1])
            i = j + 1
        else:
            out.append(text[i])
            i += 1
    return "".join(out)


def squash(text):
    return re.sub(r"\s+", " ", text)


def read_c(name):
    return strip_comments(docsx.read(name))


# ------------------------------------------------------------------ T-407

ROW = re.compile(r"^\| `(PROTO_\w+)` \| `(-?\d+)` \| (.*?) \| (.*?) \|\s*$", re.M)
# The success has no table of its own: it is the middle item of the sign rule.
ZERO = re.compile(r"^- \*\*`(-?\d+)`\*\* — `(PROTO_\w+)`", re.M)


def docs_codes():
    text = docsx.read("docs.md")
    codes = {m.group(1): int(m.group(2)) for m in ROW.finditer(text)}
    codes.update({m.group(2): int(m.group(1)) for m in ZERO.finditer(text)})
    return codes


def header_codes():
    text = read_c("status.h")
    body = text[text.index("typedef enum"):text.index("proto_status_t;")]
    return {m.group(1): int(m.group(2)) for m in re.finditer(r"(PROTO_\w+)\s*=\s*(-?\d+)", body)}


@case("T-407")
def t407():
    """The status tables of docs.md match status.h."""
    header, docs, table = header_codes(), docs_codes(), dict(statuses.VALUE)
    eq(len(header), 44, "members of proto_status_t")
    eq(header, table, "status.h against the table of this suite")
    missing = sorted(set(header) - set(docs))
    extra = sorted(set(docs) - set(header))
    check(not missing, "docs.md lacks %s" % missing)
    check(not extra, "docs.md lists codes that do not exist: %s" % extra)
    wrong = ["%s is %d in docs.md, %d in status.h" % (n, docs[n], header[n]) for n in header if docs[n] != header[n]]
    check(not wrong, "; ".join(wrong))


# ------------------------------------------------------------------ T-408

@case("T-408", FINDING)
def t408():
    """The list of FAIL reasons is complete."""
    sent = set()
    for s in SOURCES:
        sent |= set(re.findall(r'"FAIL ([A-Za-z][A-Za-z ]*)"', read_c(s)))
    if len(sent) < 9:
        broken("found only %d FAIL literals in the sources: %s" % (len(sent), sorted(sent)))
    text = squash(docsx.read("docs.md"))
    m = re.search(r"`FAIL` reasons emitted by the library: (.*?)\.", text)
    if not m:
        broken("docs.md no longer lists the FAIL reasons emitted by the library")
    listed = set(re.findall(r"`([^`]+)`", m.group(1)))
    check(sent == listed, "docs.md lists %d reasons, the sources send %d: missing %s, extra %s"
          % (len(listed), len(sent), sorted(sent - listed), sorted(listed - sent)))


# ------------------------------------------------------------------ T-409

def header_functions():
    names = set()
    for h in HEADERS:
        for m in re.finditer(r"^\s*(?:const\s+)?(?:unsigned\s+)?(?:char|int|void|size_t)\s*\**\s*(proto_\w+)\s*\(",
                             read_c(h), re.M):
            names.add(m.group(1))
    return names


def header_types():
    names = set()
    for h in HEADERS:
        text = read_c(h)
        names |= set(re.findall(r"\}\s*(proto_\w+)\s*;", text))
        names |= set(re.findall(r"typedef\s+[^;{]*\(\s*\*\s*(proto_\w+)\s*\)", text))
    return names


def struct_fields(text, name):
    m = re.search(r"typedef struct \{(.*?)\}\s*" + re.escape(name) + r"\s*;", strip_comments(text), re.S)
    check(m, "no definition of %s" % name)
    fields = []
    for decl in m.group(1).split(";"):
        decl = decl.strip()
        if decl:
            ident = re.findall(r"[A-Za-z_]\w*", re.sub(r"\[[^\]]*\]", "", decl))
            fields.append(ident[-1])
    return fields


@case("T-409")
def t409():
    """Every public function and type is documented, and nothing else is."""
    functions, types = header_functions(), header_types()
    eq(len(functions), 22, "public functions declared in the headers")
    eq(types, {"proto_status_t", "proto_keys_t", "proto_conn_t", "proto_handler_fn", "proto_serve_opts_t"},
       "public types declared in the headers")
    docs = docsx.read("docs.md")
    sections = set(re.findall(r"^### `(proto_\w+)`\s*$", docs, re.M))
    toc = set(re.findall(r"^\s*- \[`(proto_\w+)`\]\(#proto_\w+\)", docs, re.M))
    # proto_strerror and proto_status_t are documented under "Status codes", with a signature block
    status_section = docs[docs.index("## Status codes"):docs.index("## Error codes")]
    check("const char *proto_strerror(int code);" in status_section, "proto_strerror has no signature in docs.md")
    check("`proto_status_t`" in status_section, "proto_status_t is not introduced in the Status codes section")
    sections |= {"proto_strerror", "proto_status_t"}
    toc |= {"proto_strerror", "proto_status_t"}
    declared = functions | types
    check(declared <= sections, "declared, with no section: %s" % sorted(declared - sections))
    check(sections <= declared, "sections of things that are not declared: %s" % sorted(sections - declared))
    check(declared <= toc, "declared, absent from the table of contents: %s" % sorted(declared - toc))
    check(toc <= declared, "table of contents entries that are not declared: %s" % sorted(toc - declared))
    for typ, header in (("proto_keys_t", "crypto.h"), ("proto_conn_t", "auth.h"), ("proto_serve_opts_t", "serve.h")):
        block = docsx.find_block("docs.md", "c", "} %s;" % typ)
        eq(struct_fields(block, typ), struct_fields(docsx.read(header), typ),
           "the fields of %s in docs.md and in %s" % (typ, header))
    # the options table of proto_serve_opts_t names the same fields
    opts = docs[docs.index("### `proto_serve_opts_t`"):docs.index("## Module `wire`")]
    eq(re.findall(r"^\| `(\w+)` \| ", opts, re.M), struct_fields(docsx.read("serve.h"), "proto_serve_opts_t"),
       "the fields the options table of proto_serve_opts_t describes")


# ------------------------------------------------------------------ T-410

def c_functions():
    """{name: (return type, body)} for the function definitions at column 0 of the library's sources."""
    funcs = {}
    for path in SOURCES:
        text = read_c(path)
        for m in re.finditer(r"^(?P<ret>(?:static\s+)?[A-Za-z_][\w\s\*]*?)\b(?P<name>[A-Za-z_]\w*)\s*\([^;{}]*\)\s*\{",
                             text, re.M):
            i, depth = m.end(), 1
            while i < len(text) and depth:
                c = text[i]
                if c in "\"'":
                    q = c
                    i += 1
                    while i < len(text) and text[i] != q:
                        i += 2 if text[i] == "\\" else 1
                elif c == "{":
                    depth += 1
                elif c == "}":
                    depth -= 1
                i += 1
            funcs[m.group("name")] = (m.group("ret").strip(), text[m.end():i])
    return funcs


CODE = re.compile(r"\bPROTO_(?:E_\w+|REGISTER_REQUESTED|KEEPALIVE_DEFAULTED)\b")
LENGTH = "(a length)"

# What the call graph reaches and the arguments rule out.
NEVER = {
    ("PROTO_E_TIMEOUT", "proto_recv_line"): "it passes no deadline, so the wait is never entered",
}


def returned_codes():
    """{code: public functions that can return it}, by following the calls through the sources.

    Codes travel up a call that hands its result on: `return f(...)`, `rc = f(...)` and
    the `*status = ...` of the allocating reader. A positive value stops at a public call, which
    consumes it (proto_connect answers REGISTER itself), and so does a caller mistake: the
    argument check of the callee is not one of its caller's, which passes what it built itself.
    """
    funcs = c_functions()
    public = header_functions()
    values = header_codes()
    reports = {n for n, (ret, body) in funcs.items() if "int" in ret.split() or "*status =" in body}
    own, calls = {}, {}
    for name in reports:
        body = funcs[name][1]
        codes = set()
        for stmt in re.findall(r"\breturn\b([^;]*);", body):
            codes |= set(CODE.findall(stmt))
        for stmt in re.findall(r"(?:\brc|\*status)\s*=(?!=)\s*([^;]*);", body):
            codes |= set(CODE.findall(stmt))
        if re.search(r"\breturn\s+\(int\)\s*\w+\s*;", body):
            codes.add(LENGTH)
        own[name] = codes
        calls[name] = {c for c in re.findall(r"\brc\s*=(?!=)\s*(\w+)\s*\(", body)
                       + re.findall(r"\breturn\s+(\w+)\s*\(", body) if c in reports}

    def reach(name, seen):
        codes = set(own[name])
        for callee in calls[name] - seen:
            sub = reach(callee, seen | {name})
            if callee in public:
                sub = {c for c in sub if c in values and values[c] < 0 and not -199 <= values[c] <= -100}
            codes |= sub
        return codes

    result = {}
    for name in sorted(public & reports):
        for code in reach(name, frozenset()):
            if (code, name) not in NEVER:
                result.setdefault(code, set()).add(name)
    return result


def docs_returned_by():
    """{code: set of functions} from the Returned-by column of docs.md ('idem' repeats the row above)."""
    res, last = {}, set()
    for m in ROW.finditer(docsx.read("docs.md")):
        cell = m.group(4)
        res[m.group(1)] = last if cell.strip().startswith("idem") else set(re.findall(r"`(proto_\w+)`", cell))
        last = res[m.group(1)]
    return res


NUMBERS = {"one": 1, "two": 2, "three": 3, "four": 4, "five": 5, "six": 6}


@case("T-410", FINDING)
def t410():
    """"Returned by" names every function that returns the code."""
    computed, documented = returned_codes(), docs_returned_by()
    lengths = computed.pop(LENGTH, set())
    pairs = sum(len(v) for v in computed.values())
    if pairs < 30 or lengths != {"proto_recv_line", "proto_recv_line_timeout"}:
        broken("the analysis of the sources found %d (code, function) pairs and the readers %s" % (pairs, sorted(lengths)))
    gaps, extras = [], []
    for code in sorted(set(computed) | set(documented)):
        want, have = computed.get(code, set()), documented.get(code, set())
        if want - have:
            gaps.append("%s: %s" % (code, ", ".join(sorted(want - have))))
        if have - want:
            extras.append("%s: %s" % (code, ", ".join(sorted(have - want))))
    # the functions said to return a positive value: the named ones, and the length of the readers
    positive = {f for c in ("PROTO_REGISTER_REQUESTED", "PROTO_KEEPALIVE_DEFAULTED") for f in computed.get(c, ())} | lengths
    docs = docsx.read("docs.md")
    section = docs[docs.index("## Status codes"):docs.index("## Error codes")]
    unnamed = sorted(f for f in positive if "`%s`" % f not in section)
    m = re.search(r"never return a positive — (\w+) do\b", squash(section))
    if m and NUMBERS.get(m.group(1)) != len(positive):
        unnamed.append("(the count says %s, there are %d)" % (m.group(1), len(positive)))
    problems = []
    if gaps:
        problems.append("%d codes miss functions in their Returned-by column: %s" % (len(gaps), "; ".join(gaps)))
    if extras:
        problems.append("%d name functions that do not return them: %s" % (len(extras), "; ".join(extras)))
    if unnamed:
        problems.append("the Status codes section leaves out what returns a positive value: %s" % ", ".join(unnamed))
    check(not problems, " | ".join(problems))


# ------------------------------------------------------------------ T-411

def lines_of(name):
    with open(os.path.join(ROOT, name), encoding="utf-8") as f:
        return len(f.read().splitlines())


@case("T-411", FINDING)
def t411():
    """No text predates the code it describes."""
    problems = []
    for doc in ("docs.md", "architecture.md", "README.md"):
        text = squash(docsx.read(doc))
        for m in re.finditer(r"`proto_\w+(?:\(\))?`\s+returns?\s+`?-1\b|\b-1 on (?:failure|error)", text):
            problems.append("%s: '%s' predates the status codes" % (doc, m.group(0)))
    # the FAQ on a failed signature: a corrupt auth.key no longer reaches the handshake
    faq = squash(docsx.read("docs.md"))
    m = re.search(r"\*\*`FAIL signature verification failed`\.\*\*(.*?)(?=\*\*[A-Z`]|\Z)", faq)
    if not m:
        broken("docs.md has no FAQ entry on FAIL signature verification failed")
    if re.search(r"corrupt|damaged", m.group(1)) and not ("PROTO_E_KEY_MISMATCH" in m.group(1) and "PROTO_E_KEY_SIZE" in m.group(1)):
        problems.append("the FAQ on FAIL signature verification failed blames a damaged auth.key, which "
                        "PROTO_E_KEY_MISMATCH and PROTO_E_KEY_SIZE stop at load time")
    # sizes quoted for the sources
    claims = 0
    for doc in ("architecture.md", "docs.md", "README.md"):
        for m in re.finditer(r"`(\w+\.[ch])`[^.]{0,60}?~(\d+) lines", squash(docsx.read(doc))):
            claims += 1
            claimed, actual = int(m.group(2)), lines_of(m.group(1))
            if not claimed * 0.8 <= actual <= claimed * 1.25:
                problems.append("%s says %s is ~%d lines, and it has %d" % (doc, m.group(1), claimed, actual))
    if not claims:
        broken("no document quotes the size of a source any more: drop this part of the lint")
    check(not problems, "; ".join(problems))


# ------------------------------------------------------------------ T-412

def macro_values(name):
    return {m.group(1): m.group(2) for m in re.finditer(r"^#define\s+(\w+)\s+(.+?)\s*$", read_c(name), re.M)}


def number(expr):
    """A product of integers, such as (16 * 1024 * 1024)."""
    return math.prod(int(x) for x in expr.strip("() ").split("*"))


def include_closure(name, seen=None):
    """Every header a source reaches: local ones by name, system ones in angle brackets."""
    seen = set() if seen is None else seen
    if name not in seen:
        seen.add(name)
        for m in re.finditer(r'^\s*#\s*include\s+([<"])([^>"]+)[>"]', read_c(name), re.M):
            if m.group(1) == '"':
                include_closure(m.group(2), seen)
            else:
                seen.add("<%s>" % m.group(2))
    return seen


@case("T-412")
def t412():
    """The constants table matches the headers, and each option lives in one header."""
    protocol, wire = macro_values("protocol.h"), macro_values("wire.h")
    expected = {name: number(protocol[name]) for name in
                ("CHALLENGE_LEN", "MAX_LINE", "CONNECT_TIMEOUT_MS", "HANDSHAKE_TIMEOUT_MS", "QUIT_TIMEOUT_MS")}
    expected.update({name: number(wire[name]) for name in ("READ_CHUNK", "MAX_PAYLOAD")})
    expected.update({"AUTH_PK_LEN": 32, "AUTH_SK_LEN": 64, "AUTH_SIG_LEN": 64, "ENC_PK_LEN": 32, "ENC_SK_LEN": 32})
    docs = docsx.read("docs.md")
    for name, want in expected.items():
        m = re.search(r"^\| `" + name + r"`[^|]*\| ([^|]+) \|", docs, re.M)
        check(m, "docs.md has no row for %s" % name)
        got = int(re.search(r"\d+", m.group(1)).group(0))
        if "MB" in m.group(1):
            got *= 1024 * 1024
        eq(got, want, "the value of %s in docs.md" % name)
    # each option is defined in one header
    for name, home in (("CONNECT_TIMEOUT_MS", "protocol.h"), ("HANDSHAKE_TIMEOUT_MS", "protocol.h"),
                       ("QUIT_TIMEOUT_MS", "protocol.h"), ("READ_CHUNK", "wire.h"), ("MAX_PAYLOAD", "wire.h")):
        homes = [os.path.basename(p) for p in glob.glob(os.path.join(ROOT, "*.h")) + glob.glob(os.path.join(ROOT, "*.c"))
                 if re.search(r"^\s*#\s*define\s+" + name + r"\b", read_c(os.path.basename(p)), re.M)]
        eq(homes, [home], "the files that define %s" % name)
    # wire depends on libc alone: nothing it includes reaches libsodium or protocol.h
    for source in ("wire.h", "wire.c"):
        closure = include_closure(source)
        check(not closure & {"protocol.h", "crypto.h", "<sodium.h>"},
              "%s reaches %s" % (source, sorted(closure & {"protocol.h", "crypto.h", "<sodium.h>"})))


# ------------------------------------------------------------------ T-413

# What the fragments of the documents take for granted, declared where they are compiled.
PRELUDE = r'''
#include <ctype.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <syslog.h>
#include <unistd.h>
#include "status.h"
#include "wire.h"
#include "crypto.h"
#include "auth.h"
#include "serve.h"

static proto_conn_t conn, c;
static proto_keys_t k;
static const char *host, *text, *allowed, *allowed_hex, *b64_field;
static int fd, port, n, srv;
static char *b64, *line;
static char reply[MAX_LINE], hdr[MAX_LINE];
static unsigned char *buf, *data;
static size_t len, data_len, plen;
static FILE *f, *out;
static char db[64];
static void *ctx;
static volatile sig_atomic_t stop;
static void on_client(int fd_, const char *user, void *ctx_);
static void handle(int cli, const char *user);
void dispatch(char *line);
void my_log(int level, const char *fmt, ...);
void close_storage(void *db_);
int storage_open(const char *path);
int storage_user_exists(const char *user);
int storage_register_user(const char *user, const char *enc_b64);
void storage_close(void);
'''

FLAGS = ["-Wall", "-Wno-unused", "-Werror=implicit-function-declaration"]
LABELS = "disconnected: server_said_no: peer_too_slow: ;"
HEADER_PRELUDES = ("", '#include "protocol.h"\n', '#include "crypto.h"\n')


def split_fragment(text):
    """A fragment's definitions (static functions and variables, #defines) and its statements."""
    top, stmts, lines, i = [], [], strip_comments(text).split("\n"), 0
    while i < len(lines):
        if lines[i].startswith(("static ", "typedef ", "#")):
            chunk, depth = [], 0
            while i < len(lines):
                chunk.append(lines[i])
                depth += lines[i].count("{") - lines[i].count("}")
                if depth <= 0 and (lines[i].rstrip().endswith((";", "}")) or lines[i].startswith("#")):
                    break
                i += 1
            top.append("\n".join(chunk))
        else:
            stmts.append(lines[i])
        i += 1
    return "\n".join(top), re.sub(r"^\s*\.\.\.\s*$", ";", "\n".join(stmts), flags=re.M)


def compiles(source):
    rc, out = lib.try_compile(source, FLAGS)
    return rc == 0, out


def compile_program(text):
    """A whole program, in a tree where both "protocol/auth.h" and "../protocol/auth.h" lead to the library."""
    top = harness.tmpdir("program")
    os.symlink(lib.SRC, os.path.join(top, "protocol"))
    os.mkdir(os.path.join(top, "app"))
    path = os.path.join(top, "app", "p.c")
    with open(path, "w") as f:
        f.write(text + "\n")
    c_flags, _ = lib.sodium()
    rc, out = lib.run([lib.cc(), "-c", "-o", os.path.join(top, "app", "p.o"), "-I", top] + FLAGS + c_flags + [path])
    return rc == 0, out


def compile_block(text):
    """(compiled, compiler output) for one fenced C block of a document."""
    t = text.strip("\n")
    code = strip_comments(t)
    if re.search(r"^#include", code, re.M) and re.search(r"^int main\(", code, re.M):
        return compile_program(t)
    if code.lstrip().startswith("typedef"):
        for pre in HEADER_PRELUDES:                      # the headers the type is built on
            ok, out = compiles(pre + t + "\n")
            if ok:
                break
        return ok, out
    if re.match(r"(const char \*|int |char \*|void |unsigned char \*)proto_\w+\(", code.lstrip()) \
            or re.search(r"^int main\(", code, re.M):
        return compiles(PRELUDE + t + "\n")              # a prototype redeclares the header's; a main leans on the prelude
    top, stmts = split_fragment(t)
    for ret in ("int", "void"):
        ok, out = compiles(PRELUDE + top + "\nstatic %s fragment(void) {\n%s\n%s\n}\n" % (ret, stmts, LABELS))
        if ok:
            break
    return ok, out


@case("T-413", timeout=300)
def t413():
    """Every C example compiles."""
    blocks = []
    for doc in ("README.md", "docs.md"):
        for lang, text, heading, line in docsx.fenced_blocks(doc):
            if lang == "c":
                blocks.append(("%s:%d (%s)" % (doc, line, heading), text))
    lib.sodium()
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(8, os.cpu_count() or 4)) as pool:
        results = list(pool.map(lambda b: compile_block(b[1]), blocks))
    problems = []
    for (where, _), (ok, out) in zip(blocks, results):
        if not ok:
            errs = [l for l in out.splitlines() if "error" in l]
            problems.append("%s: %s" % (where, re.sub(r"^\S*/(?:t|p)\.c:", "", errs[0])[:160] if errs else "?"))
    if len(blocks) < 40:
        broken("found only %d C blocks in README.md and docs.md" % len(blocks))
    check(not problems, "%d of %d examples do not compile:\n%s" % (len(problems), len(blocks), "\n".join(problems)))


# ------------------------------------------------------------------ T-414

STATEMENTS = [
    # (file, the wording, the tests whose passing makes it true, what is wrong)
    ("docs.md", r"a lone `\\r` before it is tolerated", [],
     "the appendix says a lone \\r before the newline is tolerated, and every \\r is dropped (T-055)"),
    ("auth.c", r"which the caller can read off the wire", ["T-226"],
     "auth.c says the caller can read the reason of a refusal off the wire, and it is consumed (T-226)"),
    ("docs.md", r"On every failure path a descriptive `FAIL <reason>` line", ["T-246", "T-247"],
     "docs.md promises a FAIL line on every failure path (T-246, T-247)"),
    ("docs.md", r"On failure `conn->fd` is left at `-1` and the socket is closed", ["T-262"],
     "docs.md says conn->fd is left at -1 on failure (T-262)"),
    ("docs.md", r"tunnelled through another program's standard input and output", ["T-050", "T-381"],
     "docs.md presents pipes as the stdin and stdout tunnel (T-050, T-381)"),
    ("architecture.md", r"tunnelled through another program's stdin and stdout", ["T-050", "T-381"],
     "architecture.md presents pipes as the stdin and stdout tunnel (T-050, T-381)"),
    ("docs.md", r"the tool stops with `already exists; refusing to overwrite a key` and creates nothing", ["T-360"],
     "docs.md says keygen creates nothing when a file exists (T-360)"),
]


def passes(tid):
    c = harness.REGISTRY[tid]
    out = harness.run_isolated(c.fn, timeout=c.timeout)
    return out.kind == "ok" and not out.noise


@case("T-414", FINDING, timeout=300)
def t414():
    """The statements the probes contradict are corrected."""
    problems = []
    for name, pattern, tests, why in STATEMENTS:
        if re.search(pattern, squash(docsx.read(name))) is None:
            continue                                    # the wording is gone
        if tests and all(passes(t) for t in tests):
            continue                                    # the behaviour now matches the statement
        problems.append(why)
    check(not problems, "%d statements still contradicted: %s" % (len(problems), "; ".join(problems)))


# ------------------------------------------------------------------ T-415

LINK = re.compile(r"(?<!\!)\[[^\]\n]*\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)")


def markdown_files():
    files = glob.glob(os.path.join(ROOT, "*.md"))
    files += glob.glob(os.path.join(ROOT, "testing", "*.md")) + glob.glob(os.path.join(ROOT, "keygen", "*.md"))
    return sorted(files)


@functools.lru_cache(maxsize=None)
def anchors_of(path):
    seen, res = {}, set()
    in_block = False
    with open(path, encoding="utf-8") as f:
        for line in f:
            if re.match(r"^\s*(```|~~~)", line):
                in_block = not in_block
                continue
            m = None if in_block else re.match(r"^#{1,6}\s+(.*?)\s*#*\s*$", line)
            if m:
                a = docsx.anchor(m.group(1).replace("`", ""))
                n = seen.get(a, 0)
                seen[a] = n + 1
                res.add(a if n == 0 else "%s-%d" % (a, n))
    return res


@case("T-415")
def t415():
    """Every link and anchor resolves."""
    bad, total = [], 0
    for path in markdown_files():
        base = os.path.dirname(path)
        in_block = False
        with open(path, encoding="utf-8") as f:
            lines = f.read().split("\n")
        for no, line in enumerate(lines, 1):
            if re.match(r"^\s*(```|~~~)", line):
                in_block = not in_block
                continue
            if in_block:
                continue
            for m in LINK.finditer(re.sub(r"`[^`]*`", "", line)):
                target = m.group(1)
                if re.match(r"^[a-z]+:", target):
                    continue
                total += 1
                file_part, _, frag = target.partition("#")
                dest = os.path.normpath(os.path.join(base, file_part)) if file_part else path
                where = "%s:%d -> %s" % (os.path.relpath(path, ROOT), no, target)
                if not os.path.exists(dest):
                    bad.append(where + " (no such file)")
                elif frag and dest.endswith(".md") and frag not in anchors_of(dest):
                    bad.append(where + " (no such anchor)")
    if total < 30:
        broken("found only %d links" % total)
    check(not bad, "%d links do not resolve: %s" % (len(bad), " | ".join(bad[:5])))


# ------------------------------------------------------------------ T-416

def normalise(text):
    return re.sub(r"\s+", " ", text.replace("`", "")).strip().rstrip(".").lower()


def measured_leads():
    """The release note each 'Measured on ...' sentence belongs to: the bold lead of its bullet, or its heading."""
    leads, heading = [], ""
    for line in docsx.read("RELEASE_NOTES.md").split("\n"):
        if line.startswith("#"):
            heading = line.lstrip("#").strip()
        if re.search(r"(?:^|\. )(?:Measured|Checked) (?:on|in|case)", line):
            m = re.match(r"^- \*\*(.*?)\*\*", line)
            lead = m.group(1) if m else heading
            if lead not in leads:
                leads.append(lead)
    return leads


def traceability():
    """{note: test ids} from the 'Release notes traceability' table of testing/README.md."""
    with open(os.path.join(harness.HERE, "README.md"), encoding="utf-8") as f:
        text = f.read()
    if "## Release notes traceability" not in text:
        return {}
    rows = {}
    for m in re.finditer(r"^\| (.+?) \| (.+?) \|\s*$", text[text.index("## Release notes traceability"):], re.M):
        if m.group(1) in ("Release note", "---"):
            continue
        ids = set()
        for part in re.findall(r"T-\d{3}(?: to T-\d{3})?", m.group(2)):
            if " to " in part:
                a, b = (int(x[2:]) for x in part.split(" to "))
                ids |= {"T-%03d" % i for i in range(a, b + 1)}
            else:
                ids.add(part)
        rows[normalise(m.group(1))] = ids
    return rows


@case("T-416")
def t416():
    """Every measurement in the release notes names its test."""
    leads = measured_leads()
    if len(leads) < 5:
        broken("found only %d release notes with a measurement" % len(leads))
    rows = traceability()
    problems = []
    for lead in leads:
        key = normalise(lead)
        if key not in rows:
            problems.append("no row for: %s" % lead[:70])
            continue
        unknown = sorted(t for t in rows[key] if t not in harness.REGISTRY)
        if not rows[key] or unknown:
            problems.append("%s: tests %s do not exist" % (lead[:50], unknown or "(none)"))
    check(not problems, "; ".join(problems))
