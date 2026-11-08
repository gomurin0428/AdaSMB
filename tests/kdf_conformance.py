#!/usr/bin/env python3
"""SMB 3.1.1 key derivation differential tests against Python's cryptography.

cryptography is a test-only dependency. Its KBKDFHMAC (SP 800-108 counter
mode, HMAC-SHA256, a 32-bit counter before the fixed input, a 32-bit L and a
16-byte output) is the reference, and it adds the zero byte between label and
context itself. The fixtures cover Microsoft's twelve published 3.1.1 keys;
all-zero and all-one keys and hashes; and seeded random keys and hashes, each
under all three labels. crypto_probe derives each fixture's key with
SMB.KDF.Derive (see Check_KDF).
"""

from __future__ import annotations

import pathlib
import random
import subprocess
import sys

try:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.kbkdf import (
        KBKDFHMAC, CounterLocation, Mode)
except ImportError as error:
    raise RuntimeError(
        "Python's cryptography package is required for kdf-test and mutation testing"
    ) from error

ROOT = pathlib.Path(__file__).resolve().parents[1]
# MS-SMB2 3.2.5.3.1: each label includes its terminating NUL.
LABELS = {
    "signing": b"SMBSigningKey\x00",
    "encryption": b"SMBC2SCipherKey\x00",
    "decryption": b"SMBS2CCipherKey\x00",
}
# (ExportedSessionKey, final preauth integrity hash, published keys by label)
# from the anatomy blog's master session (= the preauth blog's A.1) and
# binding channel, the preauth blog's A.2 and B, and the encryption blog's
# A.1 (GCM) and A.2 (CCM).
PUBLISHED = (
    ("270e1ba896585eeb7af3472d3b4c75a7",
     "0dd13628cc3ed218ef9df9772d436d0887ab9814bfae63a80aa845f36909db79"
     "28622dddad522d9751640a459762c5a9d6bb084cbb3ce6bdadef5d5bce3c6c01",
     {"signing": "73fe7a9a77bef0bde49c650d8ccb5f76",
      "encryption": "629bcbc54422a0f572b97f45989b6073",
      "decryption": "e2af0dcefac68da71a0dfbd0d1350d74"}),
    ("84b9dbb730116a8fa6e9889555c265f9",
     "ea3bf912b11cbfec5b1889e8209614218687f82fa5294521ad3063425e49e88a"
     "10bd022124ce25123bc9111f52d9566ba88bf46344e6063dc5e3ff0389026f6c",
     {"signing": "c962bca1a9dd1697b030644199705431"}),
    ("fd67875e7df37605f5a9d226991a8782",
     "bd57317658d28e7599c2491165f5d6fb36ad0ad65833774a6684d07f83ef2eba"
     "b8726c1d76704af325285a70fcbad053f39ef4c031ae67c56006c50c6d349ec6",
     {"signing": "d9ae56d84460f692e15673d7ac357904"}),
    ("a8b3fcb8c96884ba9126132ae5b076af",
     "cb3320852ed35231f1087e6a4828c129384f7041005ff76543b46b1590574300"
     "b376771109c29903d0a5e6eb124a3bca8dd9cf0fbf2ef60f2fed746a70ce0533",
     {"signing": "5756ac382298721282d4d9f61cf1195f"}),
    ("419fddf34c1e001909d362ae7fb6af79",
     "b23f3cbfd69487d9832b79b1594a367cdd950909b774c3a4c412b4fcea9edddb"
     "a7db256ba2ea30e977f11f9b113247578e0e915c6d2a513b8f2fca5707dc8770",
     {"signing": "8765949dfeaee105ce9118b45be988f0",
      "encryption": "a2f5e80e5d59103034f32e52f698e5ec",
      "decryption": "748c50868c90f302962a5c35f5f9a8bf"}),
    ("07b7f69c1e2581662df6987e88f9e891",
     "decf98a420718718f22090d3580fcc5e484bd310fa1268210c6e86335a8891e7"
     "67f5bcd99fa5a7859d665ad07a73ea94e1bcdb7cfa69a6962a28a244138340b1",
     {"signing": "3dcc82c5795ae27f383242761078c59b",
      "encryption": "dfaaa31aae40a2485d47ac4df09fda1d",
      "decryption": "95c544aef6072680da1ce49a68a97fa6"}),
)


def derive(key: bytes, purpose: str, context: bytes) -> bytes:
    return KBKDFHMAC(
        algorithm=hashes.SHA256(), mode=Mode.CounterMode, length=16,
        rlen=4, llen=4, location=CounterLocation.BeforeFixed,
        label=LABELS[purpose], context=context, fixed=None,
    ).derive(key)


def fixtures() -> list[str]:
    cases: list[str] = []

    def add(key: bytes, context: bytes, purpose: str, known: str | None = None) -> None:
        result = derive(key, purpose, context).hex()
        if known is not None and result != known:
            raise AssertionError("cryptography differs from a published SMB 3.1.1 key")
        cases.append(f"K {key.hex()} {purpose} {context.hex()} {result}")

    for key, context, published in PUBLISHED:
        for purpose in LABELS:
            add(bytes.fromhex(key), bytes.fromhex(context), purpose, published.get(purpose))
    for key in (bytes(16), b"\xff" * 16):
        for context in (bytes(64), b"\xff" * 64):
            for purpose in LABELS:
                add(key, context, purpose)
    generator = random.Random(800108)
    for _ in range(100):
        key = generator.randbytes(16)
        context = generator.randbytes(64)
        for purpose in LABELS:
            add(key, context, purpose)
    return cases


def main() -> None:
    cases = fixtures()
    probe = ROOT / "build" / "bin" / ("crypto_probe.exe" if sys.platform == "win32" else "crypto_probe")
    result = subprocess.run([str(probe)], input="\n".join(cases) + "\n",
                            text=True, capture_output=True, timeout=600)
    if result.returncode != 0 or result.stdout.strip() != f"PASS {len(cases)}":
        print(result.stdout + result.stderr, file=sys.stderr)
        raise RuntimeError("SMB 3.1.1 KDF conformance failed")
    # A corrupted key, hash or result must fail, and so must each published
    # key checked under each of the other two labels.
    example = cases[0].split()
    variants = []
    for column in (1, 3, 4):
        fields = list(example)
        corrupted = bytearray.fromhex(fields[column])
        corrupted[-1] ^= 0x80
        fields[column] = corrupted.hex()
        variants.append(fields)
    for case in cases[:3]:
        for purpose in LABELS:
            fields = case.split()
            if fields[2] != purpose:
                fields[2] = purpose
                variants.append(fields)
    for fields in variants:
        check = subprocess.run([str(probe)], input=" ".join(fields) + "\n",
                               text=True, capture_output=True, timeout=30)
        if check.returncode == 0 or "raised PROGRAM_ERROR" not in check.stderr:
            raise RuntimeError("SMB 3.1.1 KDF probe sensitivity check failed or could not execute")
    print(f"PASS: {len(cases)} SMB 3.1.1 KDF fixtures; {len(variants)} sensitivity checks")


if __name__ == "__main__":
    main()
