#!/usr/bin/env python3
"""The units whose mutants are proved at the low steps limit.

A mutant's proof (tests/mutant_prove.py) uses PROOF_STEPS, the limit of
`make prove`, so that it can take the goals it does not change from the
proof cache. At a much lower limit, LOW_STEPS, a goal that a mutant breaks
fails far sooner, and most units still prove: a unit's mutants are proved
there when the unmodified unit proves there. This script proves each given
unit at LOW_STEPS into CACHE/low/cache, a cache for those proofs, and lists
the units that proved in CACHE/low/units.txt; mutant_prove.py reads both. A
unit that does not prove at LOW_STEPS keeps PROOF_STEPS, so a mutant is
never counted as detected because of the limit alone. `make prove` and CI's
proof of a pull request are not affected.

The list is made again before each mutation run, from the units it names
only, so it follows the code.

Usage: mutant_low_steps.py CACHE (--since BASE | --all | FILE...)
"""

import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LOW_STEPS = 20000
# The switches of `make prove` but the steps limit; mutant_prove.py adds
# --counterexamples=on and -j1, which leave the cache keys as they are.
SWITCHES = [
    "--mode=all", "--level=2", "--proof=progressive",
    "--checks-as-errors=on", "--prover=cvc5,z3,altergo",
]


def proved_sources() -> set[str]:
    text = (ROOT / "proof.gpr").read_text(encoding="utf-8")
    sources = re.search(r"for Source_Files use\s*\((.*?)\);", text, re.S)
    if sources is None:
        sys.exit("mutant_low_steps.py: no Source_Files in proof.gpr")
    return set(re.findall(r'"([^"]+)"', sources.group(1)))


def low_directory(cache: str) -> Path:
    return Path(cache).resolve() / "low"


def forget_results(root: Path = ROOT) -> None:
    """Removes GNATprove's results of earlier runs. With -u, GNATprove's exit
    status still counts the unproved checks that an earlier run left for
    other units, so a proof of one unit after a failed one would fail too."""
    results = root / "build" / "proof-obj" / "gnatprove"
    if results.is_dir():
        for path in results.glob("*.spark"):
            path.unlink()


def low_units(cache: str) -> set[str]:
    """The units listed for the low limit, none when there is no list."""
    listing = low_directory(cache) / "units.txt"
    if not cache or not listing.is_file():
        return set()
    return set(listing.read_text(encoding="utf-8").split())


def changed_units(base: str) -> list[str]:
    names = subprocess.run(
        ["git", "diff", "--name-only", base, "--", "src"],
        cwd=ROOT, capture_output=True, text=True, check=True,
    ).stdout.split()
    return [Path(name).name for name in names if name.endswith(".adb")]


def main() -> int:
    arguments = sys.argv[1:]
    if len(arguments) < 2:
        sys.exit(__doc__)
    cache, selection = arguments[0], arguments[1:]
    proved = proved_sources()
    if selection == ["--all"]:
        units = sorted(name for name in proved if name.endswith(".adb"))
    elif selection[0] == "--since" and len(selection) == 2:
        units = sorted(set(changed_units(selection[1])) & proved)
    else:
        units = sorted({Path(name).name for name in selection
                        if name != "--mutate"} & proved)
    low = low_directory(cache)
    (low / "cache").mkdir(parents=True, exist_ok=True)
    passed = []
    for unit in units:
        forget_results()
        command = [
            os.environ.get("GNATPROVE", "gnatprove"), "-P", "proof.gpr",
            *SWITCHES, f"--steps={LOW_STEPS}", "-j4", "-u", unit,
            f"--memcached-server=file:{low / 'cache'}",
        ]
        result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True)
        verdict = "proved" if result.returncode == 0 else "not proved"
        print(f"{unit}: {verdict} at {LOW_STEPS} steps", flush=True)
        if result.returncode == 0:
            passed.append(unit)
    forget_results()
    # Only the units checked now: a list from an earlier run may be stale.
    (low / "units.txt").write_text(
        "".join(f"{unit}\n" for unit in passed), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
