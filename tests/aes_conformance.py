#!/usr/bin/env python3
"""AES-128 and AES-256 differential tests against Python's cryptography package.

cryptography is a test-only dependency, as OpenSSL and hashlib are for the
hash tests. For each key length, the fixtures cover the FIPS 197 examples
(and SP 800-38A F.1.5 for AES-256), every single-bit key and plaintext,
every byte value in the first round's S-box input and in the key, and
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
            raise AssertionError("cryptography differs from a published AES vector")
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

    # AES-256: FIPS 197 C.3 and SP 800-38A F.1.5, then the same families
    # with 32-byte keys.
    aes(bytes(range(32)), bytes.fromhex("00112233445566778899aabbccddeeff"),
        "8ea2b7ca516745bfeafc49904b496089")
    aes(bytes.fromhex("603deb1015ca71be2b73aef0857d7781"
                      "1f352c073b6108d72d9810a30914dff4"),
        bytes.fromhex("6bc1bee22e409f96e93d7e117393172a"),
        "f3eed1bdb5d2a03c064b5a7e3db181f8")
    long_zero = bytes(32)
    for key, plain in ((long_zero, zero), (b"\xff" * 32, b"\xff" * 16),
                       (long_zero, b"\xff" * 16), (b"\xff" * 32, zero)):
        aes(key, plain)
    for position in range(32):
        for bit in range(8):
            single = bytearray(32)
            single[position] = 1 << bit
            aes(bytes(single), zero)
    for position in range(16):
        for bit in range(8):
            single = bytearray(16)
            single[position] = 1 << bit
            aes(long_zero, bytes(single))
    for value in range(256):
        aes(long_zero, bytes([value]) * 16)
        aes(bytes([value]) * 32, bytes(range(16)))
    generator = random.Random(2027)
    for _ in range(512):
        aes(generator.randbytes(32), generator.randbytes(16))
    return cases


def main() -> None:
    cases = fixtures()
    probe = ROOT / "build" / "bin" / ("crypto_probe.exe" if sys.platform == "win32" else "crypto_probe")
    result = subprocess.run([str(probe)], input="\n".join(cases) + "\n",
                            text=True, capture_output=True, timeout=300)
    if result.returncode != 0 or result.stdout.strip() != f"PASS {len(cases)}":
        print(result.stdout + result.stderr, file=sys.stderr)
        raise RuntimeError("AES conformance failed")
    # The first AES-128 and the first AES-256 fixture, each with a changed
    # key, plaintext or ciphertext, must fail.
    first_long = next(case for case in cases if len(case.split()[1]) == 64)
    for example in (cases[0], first_long):
        for column in (1, 2, 3):
            fields = example.split()
            corrupted = bytearray.fromhex(fields[column])
            corrupted[0] ^= 1
            fields[column] = corrupted.hex()
            check = subprocess.run([str(probe)], input=" ".join(fields) + "\n",
                                   text=True, capture_output=True, timeout=30)
            if check.returncode == 0 or "raised PROGRAM_ERROR" not in check.stderr:
                raise RuntimeError("AES probe sensitivity check failed or could not execute")
    print(f"PASS: {len(cases)} AES-128 and AES-256 fixtures; six sensitivity checks")


if __name__ == "__main__":
    main()
