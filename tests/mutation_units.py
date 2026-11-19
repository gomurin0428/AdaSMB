#!/usr/bin/env python3
"""Print the proved units (bodies in proof.gpr) that a mutation run mutates.

AdaMutant's proof with proof warnings, which looks for where the proof proves
anything, proves them (tests/mutant_prove.py reads ADASMB_MUTATION_UNITS).

Usage: mutation_units.py (--all | --since BASE | [--mutate] FILE...)
"""

import sys
from pathlib import Path

from mutant_low_steps import changed_units, proved_sources


def main() -> int:
    arguments = sys.argv[1:]
    proved = proved_sources()
    if arguments == ["--all"]:
        units = {name for name in proved if name.endswith(".adb")}
    elif len(arguments) == 2 and arguments[0] == "--since":
        units = set(changed_units(arguments[1])) & proved
    else:
        units = {Path(name).name for name in arguments if name != "--mutate"} & proved
    print(" ".join(sorted(units)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
