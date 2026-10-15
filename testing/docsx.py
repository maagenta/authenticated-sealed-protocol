"""Reading the Markdown documents: fenced blocks, headings, links."""

import os
import re

from harness import ROOT


def read(name):
    with open(os.path.join(ROOT, name), encoding="utf-8") as f:
        return f.read()


def fenced_blocks(name):
    """[(lang, text, heading, first_line)] for every fenced block of a document."""
    out = []
    lines = read(name).split("\n")
    heading = ""
    i = 0
    while i < len(lines):
        line = lines[i]
        m = re.match(r"^(\s*)(`{3,}|~{3,})\s*([\w+-]*)\s*$", line)
        if m:
            fence, lang, start = m.group(2), m.group(3), i + 1
            body = []
            i += 1
            while i < len(lines) and not re.match(r"^\s*" + re.escape(fence) + r"\s*$", lines[i]):
                body.append(lines[i])
                i += 1
            out.append((lang, "\n".join(body) + "\n", heading, start))
        elif line.startswith("#"):
            heading = line.lstrip("#").strip()
        i += 1
    return out


def find_block(name, lang, contains):
    for blk in fenced_blocks(name):
        if blk[0] == lang and contains in blk[1]:
            return blk[1]
    raise LookupError("no %s block containing %r in %s" % (lang, contains, name))


def headings(name):
    """[(level, text, line)]: headings outside fenced blocks."""
    res = []
    in_block = False
    for n, line in enumerate(read(name).split("\n"), 1):
        if re.match(r"^\s*(```|~~~)", line):
            in_block = not in_block
            continue
        if not in_block:
            m = re.match(r"^(#{1,6})\s+(.*?)\s*$", line)
            if m:
                res.append((len(m.group(1)), m.group(2), n))
    return res


def anchor(text):
    """GitHub's anchor for a heading."""
    a = text.strip().lower()
    a = re.sub(r"[^\w\- ]", "", a, flags=re.UNICODE)
    return a.replace(" ", "-")
