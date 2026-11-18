#!/usr/bin/env python3
"""The AdaMutant prove command (see adamutant.toml): the proof of one mutant.

AdaMutant runs it for each mutant that the tests do not detect. It proves the
unit of the mutated file with the switches of `make prove`, plus the
counterexamples that AdaMutant needs to tell a confirmed failure from a
contract that says too little. A mutant of a body changes only the proof
goals of its own unit, because the other units see only its specification.

With PROOF_CACHE, the directory of GNATprove's proof cache, the goals that the
mutant leaves unchanged come from the cache. CI fills it with `make prove
PROOF_CACHE=...` before AdaMutant runs, so only the goals that a mutant
changes are proved.

A mutated file that proof.gpr does not prove (a non-SPARK unit) passes: no
proof can detect its mutants. The baseline run, with no mutant, proves one
small unit: the whole project is proved before AdaMutant runs, and the
baseline only has to show that the command works.
"""

import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASELINE_UNIT = "smb-core_request.adb"


def proved_sources() -> set[str]:
    text = (ROOT / "proof.gpr").read_text(encoding="utf-8")
    sources = re.search(r"for Source_Files use\s*\((.*?)\);", text, re.S)
    if sources is None:
        sys.exit("mutant_prove.py: no Source_Files in proof.gpr")
    return set(re.findall(r'"([^"]+)"', sources.group(1)))


def main() -> int:
    mutated = os.environ.get("ADAMUTANT_MUTANT_FILE", "")
    unit = Path(mutated).name if mutated else BASELINE_UNIT
    if unit not in proved_sources():
        print(f"mutant_prove.py: {unit} is not proved; nothing to do")
        return 0
    command = [
        os.environ.get("GNATPROVE", "gnatprove"), "-P", "proof.gpr",
        "--mode=all", "--level=2", "--proof=progressive",
        "--checks-as-errors=on", "--prover=cvc5,z3,altergo",
        "--counterexamples=on", "-j1", "-u", unit,
    ]
    cache = os.environ.get("PROOF_CACHE", "")
    if cache:
        command.append(f"--memcached-server=file:{Path(cache).resolve()}")
    print("+", " ".join(command), flush=True)
    return subprocess.run(command, cwd=ROOT).returncode


if __name__ == "__main__":
    sys.exit(main())
