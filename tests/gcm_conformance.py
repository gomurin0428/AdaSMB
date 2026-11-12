#!/usr/bin/env python3
"""AES-GCM differential tests against Python's cryptography package.

cryptography is a test-only dependency. Every fixture uses SMB's parameters:
a 12-byte nonce and a 16-byte tag. They cover the four AES-GCM messages of
Microsoft's SMB 3.1.1 encryption blog (appendix A.1); every data length up
to five blocks and the lengths around larger block boundaries, with SMB's
32 bytes of associated data; the lengths at which the counter carries into
another byte, up to the frame limit; associated data of every length up to
three blocks and some longer, up to the frame limit, with no data, one byte
and a few blocks; the lengths at which the length block's bit counts carry;
single-bit changes; and seeded random fixtures. Those use 16-byte keys
(AES-128-GCM). The AES-256-GCM fixtures, for which no SMB messages are
published, start with test cases 13 to 16 of the GCM specification (McGrew
and Viega), then repeat the data lengths up to three blocks and the block
and frame boundaries, a few associated-data lengths, single-bit changes in
each byte of a 32-byte key, and seeded random fixtures. crypto_probe seals
and opens each fixture at four lower bounds and checks that Open rejects a
changed tag and ciphertext and leaves only zeros (see Check_AEAD).
"""

from __future__ import annotations

import pathlib
import random
import subprocess
import sys

from crypto_conformance import FRAME, patterned

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError as error:
    raise RuntimeError(
        "Python's cryptography package is required for gcm-test and mutation testing"
    ) from error

ROOT = pathlib.Path(__file__).resolve().parents[1]

# Microsoft's "SMB 3.1.1 Encryption in Windows 10", appendix A.1: the key,
# the transformed message (transform header, then ciphertext) and the
# plaintext SMB2 message, for a WRITE request and response and a READ
# request and response.
PUBLISHED = (
    ("A2F5E80E5D59103034F32E52F698E5EC",
     "FD534D42BD73D97D2BC9001BCAFAC0FDFF5FEEBCC7D6822D269CAF48904C664C"
     "0000000087000000000001002500000000100000"
     "6ECDD2A7AFC7B47763057A041B8FD4DAFFE990B70C9E09D36C084E02D14EF247"
     "F8BDE38ACF6256F8B1D3B56F77FBDEB312FEA5E92CBCC1ED8FB2EBBFAA75E49A"
     "4A394BB44576545567C24D4C014D47C9FBDFDAFD2C4F9B72F8D256452620A299"
     "F48E29E53D6B61D1C13A19E91AF013F00D17E3ABC2FC3D36C8C1B6B939732538"
     "52DBD442E46EE8",
     "FE534D4240000100000000000900010008000000000000000500000000000000"
     "FFFE000001000000250000000010000000000000000000000000000000000000"
     "3100700017000000000000000000000006000000040000000100000004000000"
     "00000000000000007000000000000000536D623320656E637279707469"
     "6F6E2074657374696E67"),
    ("748C50868C90F302962A5C35F5F9A8BF",
     "FD534D42ACBE1CB7ED343ADF1725EF144D90D4B0E06831DD2E8EB7B400000000"
     "0000000050000000000001002500000000100000"
     "26BBBF949983A6C1C796559D0F2C510CB651D1F7B6AC8DED32A2A0B8F2D793A8"
     "15C6F6B848D69767A215841A42D400AE6DDB5F0B44173A014973321FDD7950DA"
     "6179159B82E03C9E18A050FF0EA1C967",
     "FE534D4240000100000000000900010001000000000000000500000000000000"
     "FFFE000001000000250000000010000000000000000000000000000000000000"
     "11000000170000000000000000000000"),
    ("A2F5E80E5D59103034F32E52F698E5EC",
     "FD534D426DAC0B6FD85A3ED42BB917DA38FE0386D7AA8C6D36859243B715E0A6"
     "0000000071000000000001002500000000100000"
     "88A47BF09CA3C3141CDD7306BE9D9475AB24FCCB833D77461C041F8FB983D0C1"
     "88F0729272B31D9D3D0DC6B687C069EEE0CC8EACA2C536D019ACC9E185D1EB63"
     "0E0FCB793EEECEB06D82A1D77706E700DBEBFB4FEB54D7AD2D97E7288804F907"
     "57FE4D08D6A84A3FF433E7451E768E4699",
     "FE534D4240000100000000000800010008000000000000000600000000000000"
     "FFFE000001000000250000000010000000000000000000000000000000000000"
     "3100000017000000000000000000000006000000040000000100000004000000"
     "0000000000000000000000000000000000"),
    ("748C50868C90F302962A5C35F5F9A8BF",
     "FD534D427F714B3B9D8FA1198584E71C2BAA1CB6E16831DD2E8EB7B400000000"
     "0000000067000000000001002500000000100000"
     "FECEDF4D03BB11A6CC5D8A53BE33D6D8701986342B4197D306E16F9CBB218E92"
     "F7F8281F51CE68BB85A20D87DE90EBBF80538066D1C37513C0A58D70936D537B"
     "624F5500202A612B6CD30D448A82791A0B2E049ED512AFAEFB06E98AB3D6F931"
     "D7D50DB2DBD36A",
     "FE534D4240000100000000000800010001000000000000000600000000000000"
     "FFFE000001000000250000000010000000000000000000000000000000000000"
     "11005000170000000000000000000000536D623320656E637279707469"
     "6F6E2074657374696E67"),
)


# Test cases 13 to 16 of McGrew and Viega, "The Galois/Counter Mode of
# Operation (GCM)": the key, the nonce, the associated data, the plaintext,
# and the ciphertext followed by the tag.
_GCM_KEY = "feffe9928665731c6d6a8f9467308308"
_GCM_PLAIN = ("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
              "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255")
_GCM_CIPHER = ("522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa"
               "8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad")
AES_256_PUBLISHED = (
    ("00" * 32, "00" * 12, "", "", "530f8afbc74536b9a963b4f1c4cb738b"),
    ("00" * 32, "00" * 12, "", "00" * 16,
     "cea7403d4d606b6e074ec5d3baf39d18" "d0d1c8a799996bf0265b98b5d48ab919"),
    (_GCM_KEY * 2, "cafebabefacedbaddecaf888", "", _GCM_PLAIN,
     _GCM_CIPHER + "b094dac5d93471bdec1a502270e3cc6c"),
    (_GCM_KEY * 2, "cafebabefacedbaddecaf888",
     "feedfacedeadbeeffeedfacedeadbeefabaddad2", _GCM_PLAIN[:120],
     _GCM_CIPHER[:120] + "76fc6ece0f4e1768cddf8853bb2d551b"),
)


def seal(key: bytes, nonce: bytes, aad: bytes, data: bytes) -> bytes:
    """The ciphertext followed by the 16-byte tag."""
    return AESGCM(key).encrypt(nonce, data, aad)


def fixtures() -> list[str]:
    cases: list[str] = []

    def add(key: bytes, nonce: bytes, aad: bytes, data: bytes,
            known: bytes | None = None) -> None:
        sealed = seal(key, nonce, aad, data)
        if known is not None and sealed != known:
            raise AssertionError("cryptography differs from a published AES-GCM message")
        cases.append(f"G {(key + nonce).hex()} {aad.hex() or '-'} "
                     f"{data.hex() or '-'} {sealed.hex()}")

    for key, transformed, plain in PUBLISHED:
        message = bytes.fromhex(transformed)
        aad = message[20:52]
        add(bytes.fromhex(key), aad[:12], aad, bytes.fromhex(plain),
            known=message[52:] + message[4:20])

    smb_aad = bytes.fromhex(PUBLISHED[0][1])[20:52]
    # The length block's bit count gains a byte at 32 and 8,192 bytes.
    sizes = list(range(81)) + [95, 96, 97, 127, 128, 129, 255, 256, 257,
                               4063, 4064, 4065, 4079, 4080, 4081,
                               8191, 8192, 8193]
    for size in sizes:
        add(patterned(16, size), patterned(12, size + 1), smb_aad,
            patterned(size, 11))
    # The data counters start at 2. The last one reaches 2**8 at 4,065
    # bytes, 2**16 at FRAME - 31 and 2**16 + 1, its largest, at FRAME - 15.
    for size in (FRAME - 32, FRAME - 31, FRAME - 16, FRAME - 15, FRAME - 1,
                 FRAME):
        add(patterned(16, 3), patterned(12, 5), smb_aad, patterned(size, 13))

    aad_sizes = list(range(49)) + [63, 64, 65, 255, 256, 257, 4096,
                                   8191, 8192, 8193, 65536]
    for aad_size in aad_sizes:
        for size in (0, 1, 16, 37):
            add(patterned(16, 7), patterned(12, aad_size),
                patterned(aad_size, 17), patterned(size, 19))
    # Associated data up to the frame limit Seal and Open accept.
    for aad_size in (FRAME - 1, FRAME):
        for size in (0, 37):
            add(patterned(16, 7), patterned(12, 1), patterned(aad_size, 17),
                patterned(size, 19))

    # Single-bit changes in the key, the nonce, the associated data and the
    # data of a 40-byte message, at both ends of a GHASH word.
    key, nonce = patterned(16, 23), patterned(12, 29)
    data, aad = patterned(40, 31), patterned(32, 37)
    for position in range(16):
        for bit in (0x01, 0x80):
            changed = bytearray(key)
            changed[position] ^= bit
            add(bytes(changed), nonce, aad, data)
    for position in range(12):
        changed = bytearray(nonce)
        changed[position] ^= 0x01
        add(key, bytes(changed), aad, data)
    for position in (0, 7, 8, 15, 16, 31):
        for bit in (0x01, 0x80):
            changed = bytearray(aad)
            changed[position] ^= bit
            add(key, nonce, bytes(changed), data)
    for position in (0, 7, 8, 15, 16, 31, 32, 39):
        for bit in (0x01, 0x80):
            changed = bytearray(data)
            changed[position] ^= bit
            add(key, nonce, aad, bytes(changed))

    generator = random.Random(38_400)
    for _ in range(256):
        add(generator.randbytes(16), generator.randbytes(12),
            generator.randbytes(generator.randrange(65)),
            generator.randbytes(generator.randrange(301)))

    # AES-256-GCM: test cases 13 to 16 of "The Galois/Counter Mode of
    # Operation (GCM)", then the same families as above under a 32-byte key.
    for key, nonce_hex, aad_hex, plain_hex, known in AES_256_PUBLISHED:
        add(bytes.fromhex(key), bytes.fromhex(nonce_hex),
            bytes.fromhex(aad_hex), bytes.fromhex(plain_hex),
            known=bytes.fromhex(known))
    for size in list(range(49)) + [127, 128, 129, 4095, 4096, 4097, FRAME]:
        add(patterned(32, size), patterned(12, size + 1), smb_aad,
            patterned(size, 11))
    for aad_size in (0, 1, 15, 16, 17, 32, FRAME):
        add(patterned(32, 7), patterned(12, aad_size),
            patterned(aad_size, 17), patterned(37, 19))
    long_key = patterned(32, 23)
    add(long_key, nonce, aad, data)
    for position in range(32):
        changed = bytearray(long_key)
        changed[position] ^= 0x80
        add(bytes(changed), nonce, aad, data)
    generator = random.Random(38_401)
    for _ in range(128):
        add(generator.randbytes(32), generator.randbytes(12),
            generator.randbytes(generator.randrange(65)),
            generator.randbytes(generator.randrange(301)))
    return cases


def main() -> None:
    cases = fixtures()
    probe = ROOT / "build" / "bin" / ("crypto_probe.exe" if sys.platform == "win32" else "crypto_probe")
    result = subprocess.run([str(probe)], input="\n".join(cases) + "\n",
                            text=True, capture_output=True, timeout=600)
    if result.returncode != 0 or result.stdout.strip() != f"PASS {len(cases)}":
        print(result.stdout + result.stderr, file=sys.stderr)
        raise RuntimeError("AES-GCM conformance failed")
    # A changed key, nonce, associated data, plaintext, ciphertext or tag in
    # the first published message must fail.
    # A change in either half of the key, or in the nonce, of the first
    # AES-256 fixture must fail too.
    example = cases[0].split()
    variants = []
    for column, position in ((1, 0), (1, 16), (2, 0), (3, 0), (4, 0), (4, -1)):
        fields = list(example)
        changed = bytearray.fromhex(fields[column])
        changed[position] ^= 1
        fields[column] = changed.hex()
        variants.append(fields)
    long_example = next(case.split() for case in cases
                        if len(case.split()[1]) == 2 * (32 + 12))
    for position in (0, 31, 32):
        fields = list(long_example)
        changed = bytearray.fromhex(fields[1])
        changed[position] ^= 1
        fields[1] = changed.hex()
        variants.append(fields)
    for fields in variants:
        check = subprocess.run([str(probe)], input=" ".join(fields) + "\n",
                               text=True, capture_output=True, timeout=30)
        if check.returncode == 0 or "raised PROGRAM_ERROR" not in check.stderr:
            raise RuntimeError("AES-GCM probe sensitivity check failed or could not execute")
    print(f"PASS: {len(cases)} AES-GCM fixtures, each sealed and opened at four lower "
          f"bounds with rejection checks; {len(variants)} sensitivity checks")


if __name__ == "__main__":
    main()
