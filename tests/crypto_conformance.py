#!/usr/bin/env python3
"""Hash/HMAC differential tests; external crypto is a test dependency only.

MD4 is checked by OpenSSL 3's legacy provider, not the Python MD4 used by
the Samba proxy. MD5/SHA256 and their HMACs use Python hashlib/hmac.
"""

from __future__ import annotations

import hashlib
import hmac
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
FRAME = 1_048_576
HASH_MAX = FRAME + 64


def md4(data: bytes) -> bytes:
    try:
        result = subprocess.run(
            ["openssl", "dgst", "-provider", "legacy", "-md4", "-binary"],
            input=data, capture_output=True, check=True, timeout=30,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise RuntimeError("OpenSSL 3 with the legacy MD4 provider is required for crypto-test") from error
    if len(result.stdout) != 16:
        raise RuntimeError("OpenSSL MD4 returned an invalid digest length")
    return result.stdout


def patterned(size: int, seed: int) -> bytes:
    cycle = bytes((37 * index + seed) % 256 for index in range(256))
    return cycle * (size // 256) + cycle[:size % 256]


def fixtures() -> list[str]:
    cases: list[str] = []

    def field(data: bytes) -> str:
        return data.hex() or "-"

    def digest(data: bytes, known_md4: str | None = None) -> None:
        expected = md4(data).hex()
        if known_md4 is not None and expected != known_md4:
            raise AssertionError("OpenSSL MD4 differs from RFC 1320 test vector")
        cases.append(f"D {field(data)} {expected} {hashlib.md5(data).hexdigest()} {hashlib.sha256(data).hexdigest()}")

    def mac(key: bytes, data: bytes, known_md5: str | None = None,
            known_sha256: str | None = None) -> None:
        md5 = hmac.digest(key, data, "md5").hex()
        sha256 = hmac.digest(key, data, "sha256").hex()
        if known_md5 is not None and md5 != known_md5:
            raise AssertionError("HMAC-MD5 differs from RFC 2202 test vector")
        if known_sha256 is not None and sha256 != known_sha256:
            raise AssertionError("HMAC-SHA256 differs from RFC 4231 test vector")
        cases.append(f"H {field(key)} {field(data)} {md5} {sha256}")

    for data, expected in (
        (b"", "31d6cfe0d16ae931b73c59d7e0c089c0"),
        (b"a", "bde52cb31de33e46245e05fbdbd6fb24"),
        (b"abc", "a448017aaf21d8525fc10ae87aa6729d"),
        (b"message digest", "d9130a8164549fe818874806e1c7014b"),
        (b"abcdefghijklmnopqrstuvwxyz", "d79e1c308aa5bbcdeea8ed63df412da9"),
        (b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "043f8582f241db351ce627e153e7f0e4"),
        (b"1234567890" * 8, "e33b4ddc9c38f2199c3e7b164fcc0536"),
    ):
        digest(data, expected)

    sizes = list(range(130)) + [255, 256, 257, 511, 512, 513, 1023, 1024,
                               4095, 4096, 65535, 65536,
                               FRAME - 1, FRAME, HASH_MAX - 1, HASH_MAX]
    for size in sizes:
        for data in (b"\0" * size, b"\xff" * size, patterned(size, 11)):
            digest(data)

    mac(b"\x0b" * 16, b"Hi There", known_md5="9294727a3638bb1c13f48ef8158bfc9d")
    mac(b"\x0b" * 20, b"Hi There", known_sha256="b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")
    mac(b"Jefe", b"what do ya want for nothing?", "750c783e6ab0b503eaa86e310a5db738",
        "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")
    message = b"Test Using Larger Than Block-Size Key - Hash Key First"
    mac(b"\xaa" * 80, message, known_md5="6b1ab7fe4bd7bf8f0b62e6ce61b9d0cd")
    mac(b"\xaa" * 131, message, known_sha256="60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54")
    for key_size in (0, 1, 15, 16, 31, 32, 55, 56, 63, 64, 65, 127, 128, 129):
        for size in range(130):
            mac(patterned(key_size, 197), patterned(size, 11))
    for key_size, size in ((0, FRAME), (64, FRAME), (65, FRAME), (FRAME, 0),
                           (FRAME, 55), (FRAME, FRAME), (FRAME - 1, FRAME - 1)):
        mac(patterned(key_size, 197), patterned(size, 11))
    return cases


def main() -> None:
    cases = fixtures()
    probe = ROOT / "build" / "bin" / ("crypto_probe.exe" if sys.platform == "win32" else "crypto_probe")
    result = subprocess.run([str(probe)], input="\n".join(cases) + "\n",
                            text=True, capture_output=True, timeout=300)
    if result.returncode != 0 or result.stdout.strip() != f"PASS {len(cases)}":
        print(result.stdout + result.stderr, file=sys.stderr)
        raise RuntimeError("hash/HMAC conformance failed")
    for mode, columns in (("D", (2, 3, 4)), ("H", (3, 4))):
        original = next(case for case in cases if case.startswith(mode + " "))
        for column in columns:
            fields = original.split()
            corrupted = bytearray.fromhex(fields[column])
            corrupted[0] ^= 1
            fields[column] = corrupted.hex()
            check = subprocess.run([str(probe)], input=" ".join(fields) + "\n",
                                   text=True, capture_output=True, timeout=30)
            if check.returncode == 0 or "raised PROGRAM_ERROR" not in check.stderr:
                raise RuntimeError("crypto probe sensitivity check failed or could not execute")
    hashes = sum(case.startswith("D ") for case in cases)
    macs = len(cases) - hashes
    print(f"PASS: {hashes} hash fixtures / {2 * hashes} rebased cases; "
          f"{macs} HMAC fixtures / {4 * macs} rebased cases; five sensitivity checks")


if __name__ == "__main__":
    main()
