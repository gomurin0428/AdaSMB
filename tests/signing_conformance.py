#!/usr/bin/env python3
"""Differential tests of SMB 2.1 wire signing, not SMB header validation."""

from __future__ import annotations

import hmac
import pathlib
import subprocess
import sys

from crypto_conformance import FRAME, patterned

ROOT = pathlib.Path(__file__).resolve().parents[1]


def status(key: bytes, data: bytes) -> str:
    if len(data) < 64:
        return "Invalid_Length"
    return "Ok" if key else "Invalid_Value"


def signature(key: bytes, data: bytes) -> bytes:
    return hmac.digest(key, data[:48] + b"\0" * 16 + data[64:], "sha256")[:16]


def signed(key: bytes, data: bytes) -> bytes:
    return data[:48] + signature(key, data) + data[64:]


def fixtures() -> list[str]:
    cases: list[str] = []

    def field(data: bytes) -> str:
        return data.hex() or "-"

    def verify(key: bytes, data: bytes) -> None:
        result = status(key, data)
        valid = result == "Ok" and hmac.compare_digest(data[48:64], signature(key, data))
        cases.append(f"V {field(key)} {field(data)} {str(valid).lower()} {result}")

    sizes = list(range(130)) + [255, 256, 257, 511, 512, 513, 65535, 65536,
                               FRAME - 1, FRAME]
    for key_size in (0, 1, 16, 63, 64, 65, 131):
        key = patterned(key_size, 197)
        for size in sizes:
            data = patterned(size, 11)
            result = status(key, data)
            expected = signed(key, data) if result == "Ok" else data
            cases.append(f"S {field(key)} {field(data)} {field(expected)} {result}")
            verify(key, expected)

    key = patterned(16, 197)
    packet = signed(key, patterned(129, 11))
    for position in range(len(packet)):
        for bit in range(8):
            changed = bytearray(packet)
            changed[position] ^= 1 << bit
            verify(key, bytes(changed))
    for position in range(len(key)):
        for bit in range(8):
            changed = bytearray(key)
            changed[position] ^= 1 << bit
            verify(bytes(changed), packet)

    # HMAC pads short keys: appending zero bytes is not a different MAC key.
    for changed in (key[:-1], key + b"\0", key + b"\x01"):
        verify(changed, packet)
    for changed in (packet[:-1], packet + b"\0", packet + b"\xff",
                    packet[:48] + b"\0" * 16 + packet[64:],
                    packet[:48] + b"\xff" * 16 + packet[64:]):
        verify(key, changed)
    large = signed(key, patterned(FRAME, 11))
    for position in (0, 47, 48, 63, 64, FRAME // 2, FRAME - 1):
        changed = bytearray(large)
        changed[position] ^= 1
        verify(key, bytes(changed))
    return cases


def main() -> None:
    cases = fixtures()
    probe = ROOT / "build" / "bin" / ("crypto_probe.exe" if sys.platform == "win32" else "crypto_probe")
    result = subprocess.run([str(probe)], input="\n".join(cases) + "\n",
                            text=True, capture_output=True, timeout=300)
    if result.returncode != 0 or result.stdout.strip() != f"PASS {len(cases)}":
        print(result.stdout + result.stderr, file=sys.stderr)
        raise RuntimeError("SMB signing conformance failed")

    signing = next(case.split() for case in cases if case.startswith("S ") and case.endswith(" Ok"))
    bad_signature = bytearray.fromhex(signing[3])
    bad_signature[48] ^= 1
    signing[3] = bad_signature.hex()
    valid = next(case.split() for case in cases if " true Ok" in case)
    valid[3] = "false"
    invalid = next(case.split() for case in cases if " false Ok" in case)
    invalid[3] = "true"
    error = next(case.split() for case in cases if case.startswith("V ") and case.endswith(" Invalid_Length"))
    error[3] = "true"
    for fields, diagnostic in ((signing, "core signing mismatch"),
                               (valid, "core verification mismatch"),
                               (invalid, "core verification mismatch"),
                               (error, "core verification mismatch")):
        check = subprocess.run([str(probe)], input=" ".join(fields) + "\n",
                               text=True, capture_output=True, timeout=30)
        if check.returncode == 0 or diagnostic not in check.stderr:
            raise RuntimeError("signing probe sensitivity check failed or could not execute")
    print(f"PASS: {len(cases)} signing/verification fixtures / {4 * len(cases)} "
          "rebased cases through core/public APIs; four sensitivity checks")


if __name__ == "__main__":
    main()
