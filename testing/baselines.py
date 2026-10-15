"""Baselines: the findings of a tool at the time they were accepted.

A baseline is a text file of "<name> <count>" lines under testing/baselines/.
A test fails when a count grows; --record-baselines rewrites the file.
"""

import os

import harness
from harness import HERE

DIR = os.path.join(HERE, "baselines")


def path(name):
    return os.path.join(DIR, name)


def load(name):
    """{key: count}, or None if no baseline was ever recorded."""
    try:
        with open(path(name)) as f:
            res = {}
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    key, _, count = line.rpartition(" ")
                    res[key] = int(count)
            return res
    except OSError:
        return None


def save(name, counts, header=""):
    os.makedirs(DIR, exist_ok=True)
    with open(path(name), "w") as f:
        if header:
            for h in header.splitlines():
                f.write("# " + h + "\n")
        for key in sorted(counts):
            f.write("%s %d\n" % (key, counts[key]))


def recording():
    return bool(harness.OPTS and getattr(harness.OPTS, "record_baselines", False))
