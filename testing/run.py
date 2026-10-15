#!/usr/bin/env python3
"""Run the proto test suite.

    python3 testing/run.py                  everything that applies here, not slow
    python3 testing/run.py --slow           ... and the slow ones too
    python3 testing/run.py --section VII    one section of the catalogue
    python3 testing/run.py --id T-057       one test; ranges: T-052..T-079
    python3 testing/run.py --list           what there is, and what would be skipped
    python3 testing/run.py --check          the registry against README.md

Exit status 0 means every guard and pin passed, every finding failed as
expected, and nothing unexpected passed.
"""

import argparse
import glob
import importlib
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import harness  # noqa: E402


def load_sections():
    names = sorted(os.path.basename(p)[:-3] for p in glob.glob(os.path.join(HERE, "s[0-9][0-9]_*.py")))
    for name in names:
        importlib.import_module(name)
    return names


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--id", action="append", help="test ids: T-057, 57, T-052..T-079, comma lists")
    ap.add_argument("--section", action="append", help="section numerals: VII, 7")
    ap.add_argument("--tag", action="append", help="only tests with this tag")
    ap.add_argument("--slow", action="store_true", help="include the slow tests")
    ap.add_argument("--only-slow", action="store_true", help="run only the slow tests")
    ap.add_argument("--fuzz", action="store_true", help="include the fuzz targets")
    ap.add_argument("--fuzz-seconds", type=int, default=None,
                    help="time budget of each fuzz target (default 20; CI uses 60)")
    ap.add_argument("--soak-seconds", type=int, default=None,
                    help="how long the soak test T-422 runs (default 60; the nightly job uses 300)")
    ap.add_argument("-v", "--verbose", action="store_true", help="one line per test")
    ap.add_argument("--list", action="store_true", help="list the tests and exit")
    ap.add_argument("--check", action="store_true", help="check the registry against README.md")
    ap.add_argument("--record-baselines", action="store_true",
                    help="write the warning and analyzer baselines of this compiler")
    ap.add_argument("--clean", action="store_true", help="remove testing/.build first")
    args = ap.parse_args(argv)
    harness.OPTS = args

    if args.clean:
        import shutil
        shutil.rmtree(os.path.join(HERE, ".build"), ignore_errors=True)
    if args.fuzz_seconds is not None:
        os.environ["PROTO_FUZZ_SECONDS"] = str(args.fuzz_seconds)
    if args.soak_seconds is not None:
        os.environ["PROTO_SOAK_SECONDS"] = str(args.soak_seconds)

    load_sections()

    if args.check:
        import readme_check
        return readme_check.main()

    if args.list:
        for c in harness.select_cases(args):
            why = harness.skip_reason(c, args)
            print("%s  %-7s %-8s %s%s" % (c.id, c.effective_verdict(),
                                           ",".join(sorted(c.tags)) or "-", c.title,
                                           ("   [skipped here: %s]" % why) if why else ""))
        return 0

    tally = harness.run_selected(args)
    bad = tally.counts["FAIL"] + tally.counts["XPASS"]
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
