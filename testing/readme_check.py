"""Keep README.md and the registered tests in step (run.py --check).

Every registered test has an entry in README.md, every entry has a test, the
verdict and tags the README states are the ones the test is registered with, and
the table of counts at the top of the README adds up to the registry.
"""

import os
import re

import harness

README = os.path.join(harness.HERE, "README.md")

ENTRY = re.compile(r"^\*\*(T-\d{3}) — ", re.M)
COUNTS = re.compile(r"^\| ([IVX]+)\. .*? \| (\d+) \| (\d+) \| (\d+) \| (\d+) \|$", re.M)
TOTAL = re.compile(r"^\| \*\*Total\*\* \| \*\*(\d+)\*\* \| \*\*(\d+)\*\* \| \*\*(\d+)\*\* \| \*\*(\d+)\*\* \|$", re.M)
TAG_NAMES = {"linux": "linux", "macos": "macos", "root": "root", "not as root": "notroot",
             "seam": "seam", "slow": "slow", "ipv6": "ipv6", "fuzz": "fuzz"}


def entries(text):
    """{id: body} of the entries of the README."""
    marks = list(ENTRY.finditer(text))
    res = {}
    for i, m in enumerate(marks):
        end = marks[i + 1].start() if i + 1 < len(marks) else len(text)
        body = text[m.end():end]
        body = re.split(r"\n---\n|\n## ", body)[0]
        res[m.group(1)] = body
    return res


def stated_verdict(body):
    if "**Fails today.**" in body:
        return harness.FINDING
    if "**Pin.**" in body:
        return harness.PIN
    return harness.GUARD


def stated_tags(body):
    """Tags in the last parenthesised list of the entry, before its Code line."""
    body = re.sub(r"\s+", " ", re.split(r"\nCode: ", body)[0].strip())
    m = re.search(r"\(([A-Za-z0-9, ]+)\)\s*$", body)
    if not m:
        return set()
    tags = set()
    for word in m.group(1).split(","):
        word = word.strip().lower()
        if word in TAG_NAMES:
            tags.add(TAG_NAMES[word])
    return tags


def counts_of(tests):
    """[tests, guards, findings, pins] of a list of registered tests."""
    return [len(tests)] + [sum(1 for c in tests if c.verdict == v)
                           for v in (harness.GUARD, harness.FINDING, harness.PIN)]


def count_problems(text):
    """The table of counts against the registry, section by section and in total."""
    problems = []
    rows = {m.group(1): [int(g) for g in m.groups()[1:]] for m in COUNTS.finditer(text)}
    if not rows:
        return ["the table of counts under 'What the suite covers' is missing"]
    for numeral, got in sorted(rows.items()):
        want = counts_of([c for c in harness.REGISTRY.values() if c.section == numeral])
        if got != want:
            problems.append("section %s: the table says %s (tests, guards, findings, pins), the registry has %s"
                            % (numeral, got, want))
    total = TOTAL.search(text)
    want = counts_of(list(harness.REGISTRY.values()))
    if not total or [int(g) for g in total.groups()] != want:
        problems.append("the total of the table of counts is not %s (tests, guards, findings, pins)" % want)
    return problems


def main():
    with open(README, encoding="utf-8") as f:
        text = f.read()
    found = entries(text)
    problems = count_problems(text)
    for tid in sorted(set(harness.REGISTRY) - set(found)):
        problems.append("%s is registered but has no README entry" % tid)
    for tid in sorted(set(found) - set(harness.REGISTRY)):
        problems.append("%s has a README entry but no test" % tid)
    for tid in sorted(set(found) & set(harness.REGISTRY)):
        c = harness.REGISTRY[tid]
        if stated_verdict(found[tid]) != c.verdict:
            problems.append("%s: the README says %s, the test is registered as %s"
                            % (tid, stated_verdict(found[tid]), c.verdict))
        want = set(stated_tags(found[tid]))
        have = set(c.tags) & set(TAG_NAMES.values())
        both = {"linux", "macos"} <= want
        if both:
            want -= {"linux", "macos"}          # meaningful on both: no platform tag
        if want != have:
            problems.append("%s: the README lists tags %s, the test has %s"
                            % (tid, sorted(want), sorted(have)))
    ids = sorted(harness.REGISTRY)
    if ids:
        numbers = [int(i[2:]) for i in ids]
        gaps = [n for n in range(min(numbers), max(numbers) + 1) if "T-%03d" % n not in harness.REGISTRY]
        if gaps and os.environ.get("PROTO_TEST_PARTIAL") != "1":
            problems.append("ids with no test, inside the numbering: %s" % ", ".join("T-%03d" % g for g in gaps[:12]))
    if problems:
        print("\n".join(problems))
        print("\n%d problem(s)" % len(problems))
        return 1
    print("README.md and the registry agree on %d tests" % len(ids))
    return 0
