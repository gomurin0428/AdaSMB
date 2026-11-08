#!/usr/bin/env python3
"""The AdaMutant test command (see adamutant.toml): the tests of one mutant.

Runs test_suite. If the mutant survives it, also runs the comparison tests
that cover the mutated unit beyond test_suite, so only the mutants that every
applicable test misses survive. Only those survivors pay for the second stage.

AdaMutant names the mutated file in ADAMUTANT_MUTANT_FILE. The baseline run
leaves it empty and runs every comparison test: that checks them on the
unmodified sources, and AdaMutant's timeout, taken from the baseline, then
covers the longest mutant run.
"""

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXE = ".exe" if os.name == "nt" else ""
# Comparison tests against Python, OpenSSL, hashlib and cryptography: (probe mains, scripts).
CONFORMANCE = {
    "ntlm": (["ntlm_av_probe.adb"], ["ntlm_av_conformance.py", "ntlm_challenge_fields.py"]),
    "crypto": (["crypto_probe.adb"], ["crypto_conformance.py"]),
    "aes": (["crypto_probe.adb"], ["aes_conformance.py"]),
    "cmac": (["crypto_probe.adb"], ["cmac_conformance.py"]),
    "kdf": (["crypto_probe.adb"], ["kdf_conformance.py"]),
    "signing": (["crypto_probe.adb"], ["signing_conformance.py"]),
    "unicode": (["unicode_probe.adb"], ["unicode_conformance.py"]),
    "clock": (["clock_probe.adb"], ["clock_conformance.py"]),
}
# The units each comparison test covers beyond test_suite.
SECOND_STAGE = {
    "smb-core_auth.adb": ["ntlm"],
    "smb-core_ntlm.adb": ["ntlm"],
    "smb-ntlm.adb": ["ntlm"],
    "smb-crypto.adb": ["crypto", "signing"],
    "smb-aes.adb": ["aes"],
    "smb-aes-cmac.adb": ["cmac"],
    "smb-kdf.adb": ["kdf"],
    "smb-core_wire.adb": ["signing"],
    "smb-wire.adb": ["signing"],
    "smb-core_text.adb": ["unicode"],
    "smb-text.adb": ["unicode"],
    "smb-core_clock.adb": ["clock"],
    "smb-clock.adb": ["clock"],
}


def passes(command: list[str]) -> bool:
    print("+", " ".join(command), flush=True)
    return subprocess.run(command, cwd=ROOT).returncode == 0


def main() -> int:
    if not passes([str(ROOT / "build" / "bin" / ("test_suite" + EXE))]):
        return 1
    mutated = os.environ.get("ADAMUTANT_MUTANT_FILE", "")
    suites = SECOND_STAGE.get(Path(mutated).name, []) if mutated else list(CONFORMANCE)
    built = set()
    for suite in suites:
        mains, scripts = CONFORMANCE[suite]
        for main_unit in mains:
            if main_unit not in built:
                gprbuild = os.environ.get("GPRBUILD", "gprbuild")
                if not passes([gprbuild, "-q", "-p", "-P", "smb_tests.gpr", main_unit]):
                    return 1
                built.add(main_unit)
        for script in scripts:
            if not passes([sys.executable, str(ROOT / "tests" / script)]):
                return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
