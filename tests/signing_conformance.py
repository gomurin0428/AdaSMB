#!/usr/bin/env python3
"""Differential tests of SMB wire signing, not SMB header validation.

SMB 2.1 signs with HMAC-SHA256 (S and V fixtures, against hmac) and SMB
3.1.1 with AES-128-CMAC (SC and VC fixtures, against Python's
cryptography, a test-only dependency), each over the whole message with
the Signature field zeroed.
"""

from __future__ import annotations

import hmac
import pathlib
import subprocess
import sys

from crypto_conformance import FRAME, patterned

try:
    from cryptography.hazmat.primitives.ciphers import algorithms
    from cryptography.hazmat.primitives.cmac import CMAC
except ImportError as error:
    raise RuntimeError(
        "Python's cryptography package is required for signing-test and mutation testing"
    ) from error

ROOT = pathlib.Path(__file__).resolve().parents[1]


def status(key: bytes, data: bytes) -> str:
    if len(data) < 64:
        return "Invalid_Length"
    return "Ok" if key else "Invalid_Value"


def signature(key: bytes, data: bytes) -> bytes:
    return hmac.digest(key, data[:48] + b"\0" * 16 + data[64:], "sha256")[:16]


def signed(key: bytes, data: bytes) -> bytes:
    return data[:48] + signature(key, data) + data[64:]


def cmac_signature(key: bytes, data: bytes) -> bytes:
    mac = CMAC(algorithms.AES(key))
    mac.update(data[:48] + b"\0" * 16 + data[64:])
    return mac.finalize()


def cmac_signed(key: bytes, data: bytes) -> bytes:
    return data[:48] + cmac_signature(key, data) + data[64:]


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

    # SMB 3.1.1: AES-128-CMAC with a 16-byte key. Lengths around the header,
    # CMAC's block boundaries and the frame limit.
    def cmac_verify(key: bytes, data: bytes) -> None:
        result = "Invalid_Length" if len(data) < 64 else "Ok"
        valid = result == "Ok" and hmac.compare_digest(data[48:64], cmac_signature(key, data))
        cases.append(f"VC {field(key)} {field(data)} {str(valid).lower()} {result}")

    cmac_sizes = list(range(130)) + [255, 256, 257, 4095, 4096, 4097, 65535,
                                    65536, FRAME - 1, FRAME]
    for seed in (5, 199):
        key = patterned(16, seed)
        for size in cmac_sizes:
            data = patterned(size, seed + 1)
            result = "Invalid_Length" if size < 64 else "Ok"
            expected = cmac_signed(key, data) if result == "Ok" else data
            cases.append(f"SC {field(key)} {field(data)} {field(expected)} {result}")
            cmac_verify(key, expected)
    key = patterned(16, 211)
    packet = cmac_signed(key, patterned(129, 13))
    for position in range(len(packet)):
        for bit in (0, 7):
            changed = bytearray(packet)
            changed[position] ^= 1 << bit
            cmac_verify(key, bytes(changed))
    for position in range(len(key)):
        for bit in (0, 7):
            changed = bytearray(key)
            changed[position] ^= 1 << bit
            cmac_verify(bytes(changed), packet)
    for changed in (packet[:-1], packet + b"\0",
                    packet[:48] + b"\0" * 16 + packet[64:]):
        cmac_verify(key, changed)
    # An HMAC-signed message is not CMAC-signed, and the other way round.
    cmac_verify(key, signed(key, patterned(129, 13)))
    verify(key, packet)
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
    cmac_signing = next(case.split() for case in cases if case.startswith("SC ") and case.endswith(" Ok"))
    bad_tag = bytearray.fromhex(cmac_signing[3])
    bad_tag[63] ^= 1
    cmac_signing[3] = bad_tag.hex()
    cmac_valid = next(case.split() for case in cases if case.startswith("VC ") and " true Ok" in case)
    cmac_valid[3] = "false"
    for fields, diagnostic in ((signing, "core signing mismatch"),
                               (valid, "core verification mismatch"),
                               (invalid, "core verification mismatch"),
                               (error, "core verification mismatch"),
                               (cmac_signing, "core signing mismatch"),
                               (cmac_valid, "core verification mismatch")):
        check = subprocess.run([str(probe)], input=" ".join(fields) + "\n",
                               text=True, capture_output=True, timeout=30)
        if check.returncode == 0 or diagnostic not in check.stderr:
            raise RuntimeError("signing probe sensitivity check failed or could not execute")
    print(f"PASS: {len(cases)} signing/verification fixtures / {4 * len(cases)} "
          "rebased cases through the core API, and the public one for HMAC; "
          "six sensitivity checks")


if __name__ == "__main__":
    main()
