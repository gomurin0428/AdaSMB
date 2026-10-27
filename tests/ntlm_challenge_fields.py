#!/usr/bin/env python3
"""MS-NLMP 2.2.1.2: ignore TargetNameFields when REQUEST_TARGET is clear.

The raw challenge is still part of the MIC transcript. Other negotiation
requirements and active TargetName/TargetInfo bounds remain enforced.
"""

from __future__ import annotations

import struct

from ntlm_av_conformance import (
    COMPUTER, DOMAIN, EOL, FLAGS, av, challenge_token, expected_auth,
    run_cases, wrap_challenge,
)


def fixtures() -> list[tuple[str, str]]:
    pairs = [(1, COMPUTER), (2, DOMAIN), (7, bytes.fromhex("0807060504030201")),
             (6, struct.pack("<I", 2))]
    _, original = challenge_token(b"".join(av(k, v) for k, v in pairs) + EOL)
    cases: list[tuple[str, str]] = []
    clock = 0x1122334455667788

    def add(label: str, raw: bytes | bytearray, accept: bool,
            expected_flags: int = FLAGS) -> None:
        token = wrap_challenge(raw)
        if accept:
            key, result = expected_auth(raw, pairs, clock, expected_flags)
            cases.append((label, f"{token.hex()} {clock} {key.hex()} {result.hex()}"))
        else:
            cases.append((label, f"{token.hex()} {clock} - -"))

    add("original active target name", original, True)
    ignored = bytearray(original)
    struct.pack_into("<I", ignored, 20, FLAGS & ~4)
    add("REQUEST_TARGET clear", ignored, True, FLAGS & ~4)
    for field in range(12, 20):
        for value in range(256):
            raw = ignored.copy()
            raw[field] = value
            add("ignored name metadata, MIC retained", raw, True, FLAGS & ~4)
    for value in (b"\0" * 8, b"\xff" * 8):
        raw = ignored.copy()
        raw[12:20] = value
        add("ignored complete metadata", raw, True, FLAGS & ~4)
    raw = ignored.copy()
    raw[48:50] = b"\0\xdc"
    add("ignored name bytes are not decoded", raw, True, FLAGS & ~4)
    raw = ignored[:48] + ignored[60:]
    raw[12:20] = b"\xff" * 8
    struct.pack_into("<I", raw, 44, 48)
    add("no target name payload", raw, True, FLAGS & ~4)

    for offset in (0, 47, len(original), len(original) + 1, 0x80000000, 0xFFFFFFFF):
        raw = bytearray(original)
        struct.pack_into("<I", raw, 16, offset)
        add("active target name offset rejected", raw, False)
    for size in (1, len(original), 65535):
        raw = bytearray(original)
        struct.pack_into("<H", raw, 12, size)
        add("active target name length rejected", raw, False)
    raw = bytearray(original)
    raw[48:50] = b"\0\xdc"
    add("active target name encoding rejected", raw, False)
    for bit in (0, 4, 9, 15, 19, 23):
        raw = ignored.copy()
        struct.pack_into("<I", raw, 20, (FLAGS & ~4) & ~(1 << bit))
        add("remaining required flag rejected", raw, False)
    for offset in (0, 47, len(original), 0xFFFFFFFF):
        raw = ignored.copy()
        struct.pack_into("<I", raw, 44, offset)
        add("TargetInfo offset remains validated", raw, False)
    return cases


if __name__ == "__main__":
    run_cases(fixtures(), "challenge fields")
