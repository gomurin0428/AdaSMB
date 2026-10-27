#!/usr/bin/env python3
"""Deterministic NTLM AV-pair fixtures; all credentials are public test vectors.

MS-NLMP 2.2.2.1 and 3.1.5.1.2 define AV layout, timestamp selection,
zero LM response with a server timestamp, and MIC flag insertion/preservation.
Python HMAC/MD5 produces the complete expected Type 3 and SPNEGO token.
"""

from __future__ import annotations

import hashlib
import hmac
import itertools
import pathlib
import struct
import subprocess
import sys

from adversarial_proxy import md4


ROOT = pathlib.Path(__file__).resolve().parents[1]
NONCE = bytes.fromhex("ffffff0011223344")
CHALLENGE = bytes.fromhex("0123456789abcdef")
DOMAIN = "Domain".encode("utf-16le")
COMPUTER = "Server".encode("utf-16le")
FLAGS = 0x20888215
EOL = b"\0" * 4
TYPE1 = b"NTLMSSP\0" + struct.pack("<II", 1, FLAGS) + b"\0" * 16
MECHANISM = bytes.fromhex("a10c060a2b06010401823702020a")


def mac(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.md5).digest()


def tlv(tag: int, data: bytes) -> bytes:
    size = len(data)
    length = (bytes((size,)) if size < 128 else
              b"\x81" + bytes((size,)) if size < 256 else
              b"\x82" + struct.pack(">H", size))
    return bytes((tag,)) + length + data


def av(kind: int, value: bytes) -> bytes:
    return struct.pack("<HH", kind, len(value)) + value


def challenge_token(info: bytes) -> tuple[bytes, bytes]:
    raw = (b"NTLMSSP\0" + struct.pack("<IHHII", 2, len(DOMAIN), len(DOMAIN), 48, FLAGS)
           + CHALLENGE + b"\0" * 8 + struct.pack("<HHI", len(info), len(info), 60)
           + DOMAIN + info)
    token = tlv(0xA1, tlv(0x30, bytes.fromhex("a0030a0101") + MECHANISM
                        + tlv(0xA2, tlv(4, raw))))
    return token, raw


def expected_auth(raw: bytes, pairs: list[tuple[int, bytes]], clock: int) -> tuple[bytes, bytes]:
    response_key = mac(md4("Password".encode("utf-16le")), "USERDomain".encode("utf-16le"))
    if response_key.hex() != "0c868a403bfd7a93a3001ef22ef02e3f":
        raise AssertionError("NTLMv2 reference key known-answer mismatch")
    values = dict(pairs)
    timestamp = values.get(7, struct.pack("<Q", clock))
    normalized = [(kind, struct.pack("<I", struct.unpack("<I", value)[0] | 2)
                   if kind == 6 else value) for kind, value in pairs]
    if 6 not in values:
        normalized.append((6, struct.pack("<I", 2)))
    target_info = b"".join(av(kind, value) for kind, value in normalized) + EOL
    blob = b"\x01\x01" + b"\0" * 6 + timestamp + NONCE + b"\0" * 4 + target_info + EOL
    proof = mac(response_key, CHALLENGE + blob)
    key = mac(response_key, proof)
    lm = b"\0" * 24 if 7 in values else mac(response_key, CHALLENGE + NONCE) + NONCE
    fields = [lm, proof + blob, DOMAIN, "USER".encode("utf-16le"), b"", b""]
    type3 = bytearray(88)
    type3[:12] = b"NTLMSSP\0" + struct.pack("<I", 3)
    struct.pack_into("<I", type3, 60, FLAGS)
    for position, field in zip((12, 20, 28, 36, 44, 52), fields):
        struct.pack_into("<HHI", type3, position, len(field), len(field), len(type3))
        type3.extend(field)
    type3[72:88] = mac(key, TYPE1 + raw + type3)
    signing_key = hashlib.md5(key + b"session key to client-to-server signing key magic constant\0").digest()
    mic = b"\x01\0\0\0" + mac(signing_key, EOL + bytes.fromhex("300c060a2b06010401823702020a"))[:8] + EOL
    return key, tlv(0xA1, tlv(0x30, tlv(0xA2, tlv(4, type3)) + tlv(0xA3, tlv(4, mic))))


def fixtures() -> list[tuple[str, str]]:
    cases: list[tuple[str, str]] = []
    names = [(1, COMPUTER), (2, DOMAIN)]

    def good(label: str, pairs: list[tuple[int, bytes]], clock: int = 0x1122334455667788) -> None:
        token, raw = challenge_token(b"".join(av(k, v) for k, v in pairs) + EOL)
        key, expected = expected_auth(raw, pairs, clock)
        cases.append((label, f"{token.hex()} {clock} {key.hex()} {expected.hex()}"))

    def bad(label: str, info: bytes) -> None:
        token, _ = challenge_token(info)
        cases.append((label, f"{token.hex()} 0 - -"))

    baseline = names + [(7, bytes.fromhex("0807060504030201")), (6, struct.pack("<I", 2))]
    good("known-answer", baseline)
    if cases[0][1].split()[2] != "e711de05352dfa50de477e818cffec55":
        raise AssertionError("session base key differs from existing known-answer vector")
    for order in itertools.permutations(baseline):
        good("permuted AV order", list(order))
    for value in (0, 1, 0x0102030405060708, 0xFFFFFFFFFFFFFFFF):
        good("server timestamp overrides clock", names + [(7, struct.pack("<Q", value))])
        good("absent timestamp uses clock and LMv2", names, value)
    for value in (0, 3, 0xFFFFFFFF, *(1 << bit for bit in range(32))):
        good("preserve flags and set MIC bit", names + [(6, struct.pack("<I", value))])
    for kind in (3, 4, 5, 9):
        good("optional Unicode name", names + [(kind, "名前😀".encode("utf-16le"))])
        good("empty optional name", names + [(kind, b"")])
    good("zero channel binding", names + [(10, b"\0" * 16)])
    encoded_names = b"".join(av(k, v) for k, v in names)
    for kind in (1, 2, 3, 4, 5, 9):
        others = b"".join(av(k, v) for k, v in names if k != kind)
        for value in (b"x", b"\0\xd8", b"\0\xdc", b"\0\0", b"x\0\0\0"):
            bad("invalid Unicode name", others + av(kind, value) + EOL)
        if kind in (1, 2):
            bad("empty mandatory name", others + av(kind, b"") + EOL)
    for kind, width in ((6, 4), (7, 8), (10, 16)):
        for length in (0, 1, width - 1, width + 1, 32):
            bad("fixed-width AV length", encoded_names + av(kind, b"\0" * length) + EOL)
    for position in range(16):
        value = bytearray(16)
        value[position] = 1
        bad("unsupported nonzero channel binding", encoded_names + av(10, value) + EOL)
    for kind, value in baseline + [(3, b"a\0"), (4, b"a\0"), (5, b"a\0"), (9, b"a\0"), (10, b"\0" * 16)]:
        others = b"".join(av(k, v) for k, v in names if k != kind)
        bad("duplicate known AV", others + av(kind, value) * 2 + EOL)
    bad("missing computer", av(2, DOMAIN) + EOL)
    bad("missing domain", av(1, COMPUTER) + EOL)
    bad("missing terminator", encoded_names)
    bad("nonempty terminator", encoded_names + av(0, b"x"))
    bad("bytes after terminator", encoded_names + EOL + EOL)
    bad("entry exceeds remaining bytes", encoded_names + struct.pack("<HH", 7, 65535) + EOL)
    valid_info = b"".join(av(k, v) for k, v in baseline) + EOL
    for cut in range(len(valid_info)):
        bad("truncated AV list", valid_info[:cut])
    return cases


def main() -> None:
    probe = ROOT / "build" / "bin" / ("ntlm_av_probe.exe" if sys.platform == "win32" else "ntlm_av_probe")
    cases = fixtures()
    result = subprocess.run([str(probe)], input="\n".join(line for _, line in cases) + "\n",
                            text=True, capture_output=True, timeout=180)
    if result.returncode != 0 or result.stdout.strip() != f"PASS {len(cases)}":
        print(result.stdout + result.stderr, file=sys.stderr)
        raise RuntimeError("NTLM AV conformance failed; fixture ordering is deterministic")
    first = cases[0][1].split()
    changed = bytearray.fromhex(first[3])
    changed[-1] ^= 1
    wrong = " ".join(first[:3] + [changed.hex()])
    false_reject = " ".join(first[:2] + ["-", "-"])
    for corrupt_fixture in (wrong, false_reject):
        check = subprocess.run([str(probe)], input=corrupt_fixture + "\n", text=True,
                               capture_output=True, timeout=30)
        if check.returncode == 0 or "raised PROGRAM_ERROR" not in check.stderr:
            raise RuntimeError("probe sensitivity check failed or could not execute")
    print(f"PASS: {len(cases)} AV fixtures, {2 * len(cases)} rebased cases; core/public agreement; two sensitivity checks")


if __name__ == "__main__":
    main()
