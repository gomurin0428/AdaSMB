#!/usr/bin/env python3
"""The most proof steps that any check took, per prover, from GNATprove's
output with --report=statistics (`make prove PROOF_REPORT=statistics` writes
it to gnatprove.out), as Markdown for a job summary.

The steps limit (PROOF_STEPS in the Makefile) must leave a margin over these:
a check that needs more steps than the limit fails. The limit applies to
each prover separately, in GNATprove's own unit of steps, which is the one
reported here.

Usage: proof_steps.py GNATPROVE_OUTPUT
"""

import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PROVER = re.compile(r"(\w[\w-]*): (\d+) VC in max ([\d.]+) seconds and (\d+) steps?")


def limit() -> int:
    """PROOF_STEPS as `make prove` used it: from the environment (make
    passes a value given on its command line) or the Makefile."""
    if os.environ.get("PROOF_STEPS"):
        return int(os.environ["PROOF_STEPS"])
    text = (ROOT / "Makefile").read_text(encoding="utf-8")
    found = re.search(r"^PROOF_STEPS\s*\?=\s*(\d+)\s*$", text, re.M)
    return int(found.group(1)) if found else 0


def main() -> int:
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    output = Path(sys.argv[1])
    if not output.is_file():
        print("### Proof steps\n\nNo proof ran.")
        return 0
    lines = output.read_text(encoding="utf-8", errors="replace").splitlines()
    most: dict[str, tuple[int, str, str]] = {}
    checks = 0
    for index, line in enumerate(lines):
        if "proved (" not in line:
            continue
        found = PROVER.findall(line)
        if not found:
            continue
        checks += 1
        where = ""
        if index + 1 < len(lines) and lines[index + 1].startswith("-->"):
            where = lines[index + 1][3:].strip()
        what = line.strip().split(" proved (")[0].removeprefix("info: ")
        for prover, _vcs, _seconds, steps in found:
            if prover == "Trivial":
                continue
            if int(steps) > most.get(prover, (0, "", ""))[0]:
                most[prover] = (int(steps), where, what)
    print("### Proof steps\n")
    if checks == 0:
        print("No statistics found (was the report `statistics`?).")
        return 0
    steps_limit = limit()
    print(f"{checks} proved checks with statistics. Steps limit: "
          + (f"{steps_limit}." if steps_limit else "none."))
    print()
    print("| Prover | Most steps | Check | Where |")
    print("| --- | --- | --- | --- |")
    for prover, (steps, where, what) in sorted(most.items()):
        print(f"| {prover} | {steps} | {what} | `{where}` |")
    if steps_limit and most:
        highest = max(steps for steps, _, _ in most.values())
        print()
        print(f"Highest: {highest}, {highest * 100 // steps_limit}% of the limit.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
