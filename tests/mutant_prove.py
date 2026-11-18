#!/usr/bin/env python3
"""The AdaMutant prove command (see adamutant.toml): the proof of one mutant.

AdaMutant runs it for each mutant that the tests do not detect. It proves the
unit of the mutated file with the switches of `make prove`, plus the
counterexamples that AdaMutant needs to tell a confirmed failure from a
contract that says too little. A mutant of a body changes only the proof
goals of its own unit, because the other units see only its specification.

The proof uses GNATprove's proof cache, so that only the goals a mutant
changes are proved. AdaMutant gives each sandbox a cache directory of its
own in ADAMUTANT_PROVE_CACHE, and removes what a proof wrote when the proof
runs out of time (an entry cut short stops GNATprove). PROOF_CACHE, when
set, is a cache that the whole proof of the project has filled (CI fills it
with `make prove PROOF_CACHE=...` before AdaMutant runs): the baseline run of
each sandbox links its entries into the sandbox's cache, so that the mutants
start from it. Run by hand, outside AdaMutant, the proof uses PROOF_CACHE
directly.

The cache keys hold the provers' limits, so the switches here, the steps
limit (PROOF_STEPS, as in the Makefile) included, must be those of
`make prove` for the goals to hit the cache. A unit that
tests/mutant_low_steps.py listed in PROOF_CACHE/low/units.txt, because it
proves unmodified at the much lower LOW_STEPS, is proved at that limit
instead, so that a goal a mutant breaks fails sooner; its goals come from
PROOF_CACHE/low/cache, which the baseline links in too.

A mutated file that proof.gpr does not prove (a non-SPARK unit) passes: no
proof can detect its mutants. The baseline run, with no mutant, proves one
small unit: the whole project is proved before AdaMutant runs, and the
baseline only has to show that the command works.
"""

import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

from mutant_low_steps import LOW_STEPS, forget_results, low_directory, low_units

ROOT = Path(__file__).resolve().parents[1]
BASELINE_UNIT = "smb-core_request.adb"


def proved_sources() -> set[str]:
    text = (ROOT / "proof.gpr").read_text(encoding="utf-8")
    sources = re.search(r"for Source_Files use\s*\((.*?)\);", text, re.S)
    if sources is None:
        sys.exit("mutant_prove.py: no Source_Files in proof.gpr")
    return set(re.findall(r'"([^"]+)"', sources.group(1)))


def proof_steps() -> str:
    text = (ROOT / "Makefile").read_text(encoding="utf-8")
    steps = re.search(r"^PROOF_STEPS\s*\?=\s*(\d+)\s*$", text, re.M)
    if steps is None:
        sys.exit("mutant_prove.py: no PROOF_STEPS in the Makefile")
    return os.environ.get("PROOF_STEPS") or steps.group(1)


def link_tree(source: Path, target: Path, skip: str = "") -> int:
    """Hard-links (or copies) every file of source into target, but those
    under the subdirectory skip."""
    count = 0
    for path in source.rglob("*"):
        if skip and path.relative_to(source).parts[0] == skip:
            continue
        if path.is_file():
            destination = target / path.relative_to(source)
            if destination.exists():
                continue
            destination.parent.mkdir(parents=True, exist_ok=True)
            try:
                os.link(path, destination)
            except OSError:
                shutil.copy2(path, destination)
            count += 1
    return count


def cache_directory(baseline: bool, low: bool) -> str:
    shared = os.environ.get("PROOF_CACHE", "")
    own = os.environ.get("ADAMUTANT_PROVE_CACHE", "")
    if not own:
        if not shared:
            return ""
        return str(low_directory(shared) / "cache" if low
                   else Path(shared).resolve())
    if baseline and shared and Path(shared).is_dir():
        count = link_tree(Path(shared).resolve(), Path(own), skip="low")
        low_cache = low_directory(shared) / "cache"
        if low_cache.is_dir():
            count += link_tree(low_cache, Path(own))
        print(f"mutant_prove.py: {count} cache entries linked into {own}",
              flush=True)
    return own


def main() -> int:
    mutated = os.environ.get("ADAMUTANT_MUTANT_FILE", "")
    unit = Path(mutated).name if mutated else BASELINE_UNIT
    low = unit in low_units(os.environ.get("PROOF_CACHE", ""))
    cache = cache_directory(baseline=not mutated, low=low)
    if unit not in proved_sources():
        print(f"mutant_prove.py: {unit} is not proved; nothing to do")
        return 0
    steps = str(LOW_STEPS) if low else proof_steps()
    command = [
        os.environ.get("GNATPROVE", "gnatprove"), "-P", "proof.gpr",
        "--mode=all", "--level=2", "--proof=progressive",
        f"--steps={steps}",
        "--checks-as-errors=on", "--prover=cvc5,z3,altergo",
        "--counterexamples=on", "-j1", "-u", unit,
    ]
    if cache:
        command.append(f"--memcached-server=file:{cache}")
    # A mutant of another unit that this sandbox proved before may have left
    # unproved checks, which GNATprove would count against this one.
    forget_results()
    print("+", " ".join(command), flush=True)
    return subprocess.run(command, cwd=ROOT).returncode


if __name__ == "__main__":
    sys.exit(main())
