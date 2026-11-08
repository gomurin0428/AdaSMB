#!/usr/bin/env python3
"""AES-128-CMAC differential tests against Python's cryptography package.

cryptography is a test-only dependency. The fixtures cover the RFC 4493 and
NIST examples, every length up to five blocks and the lengths around larger
block and frame boundaries under keys whose subkey generation takes each
path, messages that only padding or the subkey can tell apart, single-bit
changes, and seeded random keys, lengths and messages. crypto_probe checks
each fixture one-shot and in many incremental splits (see Check_CMAC).
"""

from __future__ import annotations

import pathlib
import random
import subprocess
import sys

from crypto_conformance import FRAME, patterned

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.cmac import CMAC
except ImportError as error:
    raise RuntimeError(
        "Python's cryptography package is required for cmac-test and mutation testing"
    ) from error

ROOT = pathlib.Path(__file__).resolve().parents[1]
RFC_KEY = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
RFC_MESSAGE = bytes.fromhex(
    "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51"
    "30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710")


def cmac(key: bytes, data: bytes) -> bytes:
    mac = CMAC(algorithms.AES(key))
    mac.update(data)
    return mac.finalize()


def subkeys(key: bytes) -> tuple[bytes, bytes, bytes]:
    """L, K1 and K2, only to choose keys; the oracle is cryptography's CMAC."""
    encryptor = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    value = encryptor.update(bytes(16)) + encryptor.finalize()
    result = [value]
    for _ in range(2):
        number = int.from_bytes(result[-1], "big") << 1
        if number >> 128:
            number ^= (1 << 128) | 0x87
        result.append(number.to_bytes(16, "big"))
    return result[0], result[1], result[2]


def chosen_keys() -> list[bytes]:
    """Keys under which doubling L and K1 meets every case.

    The top bit of L decides whether K1 is reduced by 16#87#, and that of K1
    whether K2 is; each of the 15 byte boundaries of L and K1 carries a 0 and
    a 1 under some key.
    """
    keys = [RFC_KEY, bytes(16), b"\xff" * 16]
    generator = random.Random(4493)
    reductions: set[tuple[int, int]] = set()
    carries: set[tuple[int, int, int]] = set()

    def cover(key: bytes) -> bool:
        l_value, k1, _ = subkeys(key)
        new = {(l_value[0] >> 7, k1[0] >> 7)} - reductions
        new_carries = {(source, index, value[index] >> 7)
                       for source, value in enumerate((l_value, k1))
                       for index in range(1, 16)} - carries
        reductions.update(new)
        carries.update(new_carries)
        return bool(new or new_carries)

    for key in keys:
        cover(key)
    while len(reductions) < 4 or len(carries) < 60:
        key = generator.randbytes(16)
        if cover(key):
            keys.append(key)
    return keys


def fixtures() -> list[str]:
    cases: list[str] = []

    def mac(key: bytes, data: bytes, known: str | None = None) -> None:
        tag = cmac(key, data).hex()
        if known is not None and tag != known:
            raise AssertionError("cryptography differs from a published AES-CMAC vector")
        cases.append(f"C {key.hex()} {data.hex() or '-'} {tag} -")

    # RFC 4493 section 4 (= SP 800-38B D.1) and NIST's 160-bit example.
    for size, known in ((0, "bb1d6929e95937287fa37d129b756746"),
                        (16, "070a16b46b4d4144f79bdd9dd04a287c"),
                        (20, "7d85449ea6ea19c823a7bf78837dfade"),
                        (40, "dfa66747de9ae63030ca32611497c827"),
                        (64, "51f0bebf7e3b9d92fc49741779363cfe")):
        mac(RFC_KEY, RFC_MESSAGE[:size], known)

    sizes = list(range(81)) + [95, 96, 97, 127, 128, 129, 255, 256, 257,
                               4095, 4096, 4097]
    for seed, key in enumerate(chosen_keys()):
        for size in sizes:
            mac(key, patterned(size, 11 + seed))
    for size in (65535, 65536, 65537, FRAME - 1, FRAME):
        mac(RFC_KEY, patterned(size, 11))

    # Messages that differ only in what padding would add: a partial block,
    # the same block padded by hand, and with one more zero byte.
    for size in (0, 1, 15, 16, 17, 31, 47):
        data = patterned(size, 29)
        for suffix in (b"", b"\x80", b"\x80\x00", b"\x80" + bytes(15 - size % 16),
                       b"\x00"):
            mac(RFC_KEY, data + suffix)

    # Single-bit changes in each block of a 40-byte message, and in the key.
    for position in (0, 15, 16, 31, 32, 39):
        for bit in (0, 7):
            changed = bytearray(RFC_MESSAGE[:40])
            changed[position] ^= 1 << bit
            mac(RFC_KEY, bytes(changed))
    for position in range(16):
        changed = bytearray(RFC_KEY)
        changed[position] ^= 0x80
        mac(bytes(changed), RFC_MESSAGE[:40])

    generator = random.Random(2026)
    for _ in range(256):
        mac(generator.randbytes(16), generator.randbytes(generator.randrange(301)))
    return cases


def main() -> None:
    cases = fixtures()
    probe = ROOT / "build" / "bin" / ("crypto_probe.exe" if sys.platform == "win32" else "crypto_probe")
    result = subprocess.run([str(probe)], input="\n".join(cases) + "\n",
                            text=True, capture_output=True, timeout=600)
    if result.returncode != 0 or result.stdout.strip() != f"PASS {len(cases)}":
        print(result.stdout + result.stderr, file=sys.stderr)
        raise RuntimeError("AES-CMAC conformance failed")
    # A corrupted key, message or tag must fail, and so must the 16-byte
    # example without its last byte and the 15-byte message with 16#80#
    # appended, which the K1/K2 split exists to tell apart.
    example = next(case for case in cases if case.startswith(f"C {RFC_KEY.hex()} {RFC_MESSAGE[:16].hex()} "))
    variants = []
    for column in (1, 2, 3):
        fields = example.split()
        corrupted = bytearray.fromhex(fields[column])
        corrupted[0] ^= 1
        fields[column] = corrupted.hex()
        variants.append(fields)
    for data in (RFC_MESSAGE[:15], RFC_MESSAGE[:15] + b"\x80"):
        fields = example.split()
        fields[2] = data.hex()
        fields[3] = cmac(RFC_KEY, RFC_MESSAGE[:15] + (b"" if len(data) == 16 else b"\x80")).hex()
        variants.append(fields)
    for fields in variants:
        check = subprocess.run([str(probe)], input=" ".join(fields) + "\n",
                               text=True, capture_output=True, timeout=30)
        if check.returncode == 0 or "raised PROGRAM_ERROR" not in check.stderr:
            raise RuntimeError("AES-CMAC probe sensitivity check failed or could not execute")
    print(f"PASS: {len(cases)} AES-CMAC fixtures, each one-shot at three lower bounds "
          f"and in incremental splits; {len(variants)} sensitivity checks")


if __name__ == "__main__":
    main()
