"""Keep README.md and the registered tests in step (run.py --check).

Every registered test has an entry in README.md, every entry has a test, and the
verdict and tags the README states are the ones the test is registered with.
"""

import os
import re

import harness

README = os.path.join(harness.HERE, "README.md")

ENTRY = re.compile(r"^\*\*(T-\d{3}) — ", re.M)
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
    m = re.search(r"\(([A-Za-z, ]+)\)\s*$", body)
    if not m:
        return set()
    tags = set()
    for word in m.group(1).split(","):
        word = word.strip().lower()
        if word in TAG_NAMES:
            tags.add(TAG_NAMES[word])
    return tags


def main():
    with open(README, encoding="utf-8") as f:
        text = f.read()
    found = entries(text)
    problems = []
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
            problems.append("tests missing from the catalogue: %s" % ", ".join("T-%03d" % g for g in gaps[:12]))
    if problems:
        print("\n".join(problems))
        print("\n%d problem(s)" % len(problems))
        return 1
    print("README.md and the registry agree on %d tests" % len(ids))
    return 0
