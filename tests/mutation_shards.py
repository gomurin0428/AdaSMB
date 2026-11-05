#!/usr/bin/env python3
"""Print the AdaMutant --mutate options of one shard of the mutated files.

Usage: mutation_shards.py K/N

Deals the files that "adamutant list" reports to N shards with about the same
number of mutants, so the weekly mutation workflow can run them as parallel
jobs. Every file lands in exactly one shard, including files added later.
"""

import os
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
# "#12 src/smb-wire.adb:82:27 ArithmeticOperator + -> -"; mutants disabled by
# a comment end with "(ignored)" and do not run.
MUTANT = re.compile(r"^#\d+ (\S+):\d+:\d+ (?!.*\(ignored\)$)", re.MULTILINE)


def main() -> int:
    try:
        shard, shards = (int(part) for part in sys.argv[1].split("/"))
    except (IndexError, ValueError):
        sys.exit("usage: mutation_shards.py K/N")
    listing = subprocess.run(
        [os.environ.get("ADAMUTANT", "adamutant"), "list"],
        cwd=ROOT, capture_output=True, text=True, check=True,
    ).stdout
    counts = Counter(MUTANT.findall(listing))
    if not 1 <= shard <= shards <= len(counts):
        sys.exit(f"need 1 <= K <= N <= {len(counts)} (the number of mutated files)")
    files: list[list[str]] = [[] for _ in range(shards)]
    sizes = [0] * shards
    for path, count in sorted(counts.items(), key=lambda item: (-item[1], item[0])):
        smallest = sizes.index(min(sizes))
        files[smallest].append(path)
        sizes[smallest] += count
    print(" ".join(f"--mutate {path}" for path in sorted(files[shard - 1])))
    return 0


if __name__ == "__main__":
    sys.exit(main())
