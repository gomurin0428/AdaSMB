#!/usr/bin/env python3
"""AES-128 differential tests against Python's cryptography package.

cryptography is a test-only dependency, as OpenSSL and hashlib are for the
hash tests. The fixtures cover the FIPS 197 examples, every single-bit key
and plaintext, every byte value in the first round's S-box input, and
seeded random keys and plaintexts.
"""

from __future__ import annotations

import pathlib
import random
import subprocess
import sys

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
except ImportError as error:
    raise RuntimeError(
        "Python's cryptography package is required for aes-test and mutation testing"
    ) from error

ROOT = pathlib.Path(__file__).resolve().parents[1]


def encrypt(key: bytes, plain: bytes) -> bytes:
    encryptor = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return encryptor.update(plain) + encryptor.finalize()


def fixtures() -> list[str]:
    cases: list[str] = []

    def aes(key: bytes, plain: bytes, known: str | None = None) -> None:
        cipher = encrypt(key, plain).hex()
        if known is not None and cipher != known:
            raise AssertionError("cryptography differs from a published AES-128 vector")
        cases.append(f"A {key.hex()} {plain.hex()} {cipher} -")

    # FIPS 197 appendices B and C.1, and the first AESAVS GFSbox vector.
    aes(bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c"),
        bytes.fromhex("3243f6a8885a308d313198a2e0370734"),
        "3925841d02dc09fbdc118597196a0b32")
    aes(bytes(range(16)), bytes.fromhex("00112233445566778899aabbccddeeff"),
        "69c4e0d86a7b0430d8cdb78070b4c55a")
    aes(bytes(16), bytes.fromhex("f34481ec3cc627bacd5dc3fb08f273e6"),
        "0336763e966d92595a567cc9ce537f5e")

    zero = bytes(16)
    for key, plain in ((zero, zero), (b"\xff" * 16, b"\xff" * 16),
                       (zero, b"\xff" * 16), (b"\xff" * 16, zero)):
        aes(key, plain)
    for position in range(16):
        for bit in range(8):
            single = bytearray(16)
            single[position] = 1 << bit
            aes(bytes(single), zero)
            aes(zero, bytes(single))
    for value in range(256):
        aes(zero, bytes([value]) * 16)
        aes(bytes([value]) * 16, bytes(range(16)))
    generator = random.Random(2026)
    for _ in range(512):
        aes(generator.randbytes(16), generator.randbytes(16))
    return cases


def main() -> None:
    cases = fixtures()
    probe = ROOT / "build" / "bin" / ("crypto_probe.exe" if sys.platform == "win32" else "crypto_probe")
    result = subprocess.run([str(probe)], input="\n".join(cases) + "\n",
                            text=True, capture_output=True, timeout=300)
    if result.returncode != 0 or result.stdout.strip() != f"PASS {len(cases)}":
        print(result.stdout + result.stderr, file=sys.stderr)
        raise RuntimeError("AES conformance failed")
    for column in (1, 2, 3):
        fields = cases[0].split()
        corrupted = bytearray.fromhex(fields[column])
        corrupted[0] ^= 1
        fields[column] = corrupted.hex()
        check = subprocess.run([str(probe)], input=" ".join(fields) + "\n",
                               text=True, capture_output=True, timeout=30)
        if check.returncode == 0 or "raised PROGRAM_ERROR" not in check.stderr:
            raise RuntimeError("AES probe sensitivity check failed or could not execute")
    print(f"PASS: {len(cases)} AES-128 fixtures; three sensitivity checks")


if __name__ == "__main__":
    main()
