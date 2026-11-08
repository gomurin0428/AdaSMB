#!/usr/bin/env python3
"""AES-128-CCM differential tests against Python's cryptography package.

cryptography is a test-only dependency. Every fixture uses SMB's parameters:
an 11-byte nonce and a 16-byte tag. They cover the four AES-CCM messages of
Microsoft's SMB 3.1.1 encryption blog (appendix A.2); every data length up
to five blocks and the lengths around larger block boundaries, with SMB's
32 bytes of associated data; the lengths at which the counter and the
length field carry into another byte, up to the frame limit; associated
data around the first block, which holds its two-byte length and 14 bytes,
and up to the longest the two-byte encoding allows; no associated data and
no data; single-bit changes; and seeded random fixtures. crypto_probe seals
and opens each fixture at four lower bounds and checks that Open rejects a
changed tag and ciphertext and leaves only zeros (see Check_CCM).
"""

from __future__ import annotations

import pathlib
import random
import subprocess
import sys

from crypto_conformance import FRAME, patterned

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESCCM
except ImportError as error:
    raise RuntimeError(
        "Python's cryptography package is required for ccm-test and mutation testing"
    ) from error

ROOT = pathlib.Path(__file__).resolve().parents[1]

# Microsoft's "SMB 3.1.1 Encryption in Windows 10", appendix A.2: the key,
# the transformed message (transform header, then ciphertext) and the
# plaintext SMB2 message, for a WRITE request and response and a READ
# request and response.
PUBLISHED = (
    ("DFAAA31AAE40A2485D47AC4DF09FDA1D",
     "FD534D42E89551D666DAB8993488F5A97103116C9F6F1EAAD7E9F24AACD38F00"
     "0000000087000000000001002100000000100000"
     "56A74778199A9D2B6E9C3A376FD88D27680694FED253A313BEB07381AE8689F9"
     "73ACDB8D716E4477803BCE53A92E1B81FA3E965AD9AF2C89C08CE66A34466445"
     "3B8FC88118EDC9814CF58E92AA465E6EFB09958A9FDAD96FBD55B36A710C30D5"
     "E7C64AD7B9449F9F17EDD024FE8BA79154F340A82740D1D5180C69B0A2DE6A4B"
     "A893BD55D3210E",
     "FE534D4240000100000000000900010008000000000000000500000000000000"
     "FFFE000001000000210000000010000000000000000000000000000000000000"
     "3100700017000000000000000000000005000000040000000100000004000000"
     "00000000000000007000000000000000536D623320656E637279707469"
     "6F6E2074657374696E67"),
    ("95C544AEF6072680DA1CE49A68A97FA6",
     "FD534D42DD33EC41A927DD51476FE887C2D3C136D96831DD2E8EB7B400000000"
     "0000000050000000000001002100000000100000"
     "F783157E0F6F1C055D746753CA16D20C21088E2A67564E056C2F68A7F14F226C"
     "3BD809B7A2D52E5FE4ECF49821BC6001733430CF174E2764B3CCB213AAD8BB9F"
     "BAF6C15E13D9120965390E004A96A3F7",
     "FE534D4240000100000000000900010001000000000000000500000000000000"
     "FFFE000001000000210000000010000000000000000000000000000000000000"
     "11000000170000000000000000000000"),
    ("DFAAA31AAE40A2485D47AC4DF09FDA1D",
     "FD534D4235BF9600C841F0CDA9BD1BC3727B7E36A0F92E964EDC3049B86E1900"
     "0000000071000000000001002100000000100000"
     "C4CCD3EB483A0638E69C99E391E7F64BCC10D6BEE46FEEA258C4BCAF792CB5A6"
     "E69283924081806DAB64827E9D14A5345D5221AB6DAFCB0E89FC2606B63D9216"
     "3F4F6C93D1213D86ABF123B93EAD3AEF9A3471EFD68A423A00A6E0064D9AE3C8"
     "42EFFFAD236A3BF25D37F4CD054C97DE18",
     "FE534D4240000100000000000800010008000000000000000600000000000000"
     "FFFE000001000000210000000010000000000000000000000000000000000000"
     "3100000017000000000000000000000005000000040000000100000004000000"
     "0000000000000000000000000000000000"),
    ("95C544AEF6072680DA1CE49A68A97FA6",
     "FD534D42E241A13C7E1EE42ECF1FD69F3B8668C6DA6831DD2E8EB7B400000000"
     "0000000067000000000001002100000000100000"
     "15D67234FC8358D7BA1BF037ABC8EFD41A0A8F9BB04B16DEB1E85606BD8C2770"
     "823FE6239A286CB3E3D5762ABBD53FD8DE11ED491FE905E146A8FFCE09414AB7"
     "41103D637E28B19C6BA759B399DCC21FAE24CF2A455A13B215FC2857ABB51392"
     "7F9F271D1C208B",
     "FE534D4240000100000000000800010001000000000000000600000000000000"
     "FFFE000001000000210000000010000000000000000000000000000000000000"
     "11005000170000000000000000000000536D623320656E637279707469"
     "6F6E2074657374696E67"),
)


def seal(key: bytes, nonce: bytes, aad: bytes, data: bytes) -> bytes:
    """The ciphertext followed by the 16-byte tag."""
    return AESCCM(key, tag_length=16).encrypt(nonce, data, aad)


def fixtures() -> list[str]:
    cases: list[str] = []

    def add(key: bytes, nonce: bytes, aad: bytes, data: bytes,
            known: bytes | None = None) -> None:
        sealed = seal(key, nonce, aad, data)
        if known is not None and sealed != known:
            raise AssertionError("cryptography differs from a published AES-CCM message")
        cases.append(f"E {(key + nonce).hex()} {aad.hex() or '-'} "
                     f"{data.hex() or '-'} {sealed.hex()}")

    for key, transformed, plain in PUBLISHED:
        message = bytes.fromhex(transformed)
        aad = message[20:52]
        add(bytes.fromhex(key), aad[:11], aad, bytes.fromhex(plain),
            known=message[52:] + message[4:20])

    smb_aad = bytes.fromhex(PUBLISHED[0][1])[20:52]
    sizes = list(range(81)) + [95, 96, 97, 127, 128, 129, 255, 256, 257,
                               4079, 4080, 4081, 4095, 4096, 4097]
    for size in sizes:
        add(patterned(16, size), patterned(11, size + 1), smb_aad,
            patterned(size, 11))
    # The counter of the last block reaches 2**8 at 4,096 bytes and 2**16 at
    # the frame limit; the length field passes 2**8 and 2**16 on the way.
    for size in (65535, 65536, 65537, FRAME - 16, FRAME - 1, FRAME):
        add(patterned(16, 3), patterned(11, 5), smb_aad, patterned(size, 13))

    aad_sizes = [0, 1, 2, 13, 14, 15, 16, 17, 29, 30, 31, 32, 33, 46, 47, 48,
                 255, 256, 257, 4096, 65278, 65279]
    for aad_size in aad_sizes:
        for size in (0, 1, 16, 37):
            add(patterned(16, 7), patterned(11, aad_size),
                patterned(aad_size, 17), patterned(size, 19))

    # Single-bit changes in the key, the nonce, the associated data and the
    # data of a 40-byte message.
    key, nonce = patterned(16, 23), patterned(11, 29)
    data, aad = patterned(40, 31), patterned(32, 37)
    for position in range(16):
        changed = bytearray(key)
        changed[position] ^= 0x80
        add(bytes(changed), nonce, aad, data)
    for position in range(11):
        changed = bytearray(nonce)
        changed[position] ^= 0x01
        add(key, bytes(changed), aad, data)
    for position in (0, 13, 14, 31):
        changed = bytearray(aad)
        changed[position] ^= 0x01
        add(key, nonce, bytes(changed), data)
    for position in (0, 15, 16, 31, 32, 39):
        changed = bytearray(data)
        changed[position] ^= 0x01
        add(key, nonce, aad, bytes(changed))

    generator = random.Random(3610)
    for _ in range(256):
        add(generator.randbytes(16), generator.randbytes(11),
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
        raise RuntimeError("AES-CCM conformance failed")
    # A changed key, nonce, associated data, plaintext, ciphertext or tag in
    # the first published message must fail.
    example = cases[0].split()
    variants = []
    for column, position in ((1, 0), (1, 16), (2, 0), (3, 0), (4, 0), (4, -1)):
        fields = list(example)
        changed = bytearray.fromhex(fields[column])
        changed[position] ^= 1
        fields[column] = changed.hex()
        variants.append(fields)
    for fields in variants:
        check = subprocess.run([str(probe)], input=" ".join(fields) + "\n",
                               text=True, capture_output=True, timeout=30)
        if check.returncode == 0 or "raised PROGRAM_ERROR" not in check.stderr:
            raise RuntimeError("AES-CCM probe sensitivity check failed or could not execute")
    print(f"PASS: {len(cases)} AES-CCM fixtures, each sealed and opened at four lower "
          f"bounds with rejection checks; {len(variants)} sensitivity checks")


if __name__ == "__main__":
    main()
