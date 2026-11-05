#!/usr/bin/env python3
"""MS-NLMP challenge flags, optional names, fixed headers and payload placement.

The raw challenge is still part of the MIC transcript. Other negotiation
requirements and active TargetName/TargetInfo bounds remain enforced.
"""

from __future__ import annotations

import struct
from itertools import product

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
            expected_flags: int = FLAGS, status: str = "-") -> None:
        token = wrap_challenge(raw)
        if accept:
            key, result = expected_auth(raw, pairs, clock, expected_flags)
            cases.append((label, f"{token.hex()} {clock} {key.hex()} {result.hex()}"))
        else:
            cases.append((label, f"{token.hex()} {clock} {status} -"))

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
        add("active target name offset rejected", raw, False, status="Invalid_Offset")
    for size in (1, len(original), 65535):
        raw = bytearray(original)
        struct.pack_into("<H", raw, 12, size)
        add("active target name length rejected", raw, False, status="Invalid_Encoding" if size == 1 else "Invalid_Offset")
    raw = bytearray(original)
    raw[48:50] = b"\0\xdc"
    add("active target name encoding rejected", raw, False, status="Invalid_Encoding")
    for bit in (0, 4, 9, 15, 19, 23):
        raw = ignored.copy()
        struct.pack_into("<I", raw, 20, (FLAGS & ~4) & ~(1 << bit))
        add("remaining required flag rejected", raw, False, status="Invalid_Protocol")
    for offset in (0, 47, len(original), 0xFFFFFFFF):
        raw = ignored.copy()
        struct.pack_into("<I", raw, 44, offset)
        add("TargetInfo offset remains validated", raw, False, status="Invalid_Offset")

    info = b"".join(av(k, v) for k, v in pairs) + EOL

    def layout(version: bytes | None, reverse: bool = False,
               prefix: int = 0, gap: int = 0, suffix: int = 0) -> bytearray:
        raw = bytearray(original[:48])
        if version is not None:
            struct.pack_into("<I", raw, 20, FLAGS | 0x02000000)
            raw.extend(version)
        raw.extend(b"\xa5" * prefix)
        order = ((40, info), (12, DOMAIN)) if reverse else ((12, DOMAIN), (40, info))
        for index, (field, data) in enumerate(order):
            if index:
                raw.extend(b"\xa5" * gap)
            if field == 12 and len(raw) % 2:
                raw.append(0xA5)
            struct.pack_into("<HHI", raw, field, len(data), len(data), len(raw))
            raw.extend(data)
        raw.extend(b"\xa5" * suffix)
        return raw

    for version in (None, b"\0" * 8, bytes.fromhex("0a00654a0000000f"), b"\xff" * 8):
        flags = FLAGS if version is None else FLAGS | 0x02000000
        for reverse, prefix, gap, suffix in product((False, True), (0, 1, 4), (0, 1, 4), (0, 1, 4)):
            add("payload order/padding and ignored Version", layout(version, reverse, prefix, gap, suffix), True, flags)
        base = layout(version)
        header = 48 if version is None else 56
        for field in (12, 40):
            for offset in range(header):
                raw = base.copy()
                struct.pack_into("<I", raw, field + 4, offset)
                add("nonempty field points into fixed header", raw, False, status="Invalid_Offset")
            for offset in (len(base), len(base) + 1, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF):
                raw = base.copy()
                struct.pack_into("<I", raw, field + 4, offset)
                add("nonempty field points beyond storage", raw, False, status="Invalid_Offset")
            raw = base.copy()
            struct.pack_into("<H", raw, field, 65535)
            add("field length exceeds storage", raw, False, status="Invalid_Offset")
        raw = base.copy()
        struct.pack_into("<H", raw, 40, 0)
        add("TargetInfo remains required", raw, False, status="Invalid_Encoding")
        for size in ((0, 8, 12, 20, 40, 47) if version is None else range(48, 56)):
            add("fixed header truncated", base[:size], False, status="Invalid_Encoding")
        for value in (1, 128, 255):
            raw = base.copy()
            raw[32:40] = bytes((value,)) * 8
            add("reserved bytes ignored but MIC covered", raw, True, flags)
        raw = base.copy()
        struct.pack_into("<H", raw, 12, 0)
        struct.pack_into("<I", raw, 16, len(raw))
        add("empty target name at payload end", raw, True, flags)
        raw = base.copy()
        info_offset = struct.unpack_from("<I", raw, 44)[0]
        struct.pack_into("<I", raw, 16, info_offset + len(av(1, COMPUTER)) + 4)
        add("bounded name alias inside domain AV", raw, True, flags)

    # Placement boundaries, each status naming the check that fires: the
    # Version flag needs a 56-byte header, a nonempty field starts after it,
    # and an empty TargetInfo is TargetInfo's own encoding error.
    def fields(raw: bytearray, name: tuple[int, int], target: tuple[int, int]) -> bytearray:
        struct.pack_into("<HHI", raw, 12, name[0], name[0], name[1])
        struct.pack_into("<HHI", raw, 40, target[0], target[0], target[1])
        return raw

    add("Version header ends the message", fields(layout(b"\0" * 8)[:56], (0, 0), (1, 56)),
        False, status="Invalid_Offset")
    add("short message without Version", fields(layout(None)[:52], (0, 0), (5, 48)),
        False, status="Invalid_Offset")
    base = layout(None)
    add("empty TargetInfo at the message end", fields(base.copy(), (0, 0), (0, len(base))),
        False, status="Invalid_Encoding")
    add("empty TargetInfo inside the header", fields(base.copy(), (0, 0), (0, 10)),
        False, status="Invalid_Encoding")
    add("one-byte TargetInfo inside the header", fields(base.copy(), (0, 0), (1, 10)),
        False, status="Invalid_Offset")
    add("one-byte name inside the header", fields(base.copy(), (1, 10), (len(info), 60)),
        False, status="Invalid_Offset")

    required_bits = (0, 4, 9, 15, 19, 23)
    complete = (1 << len(required_bits)) - 1
    for request_target, key128, version, oem, target_type in product(
        (False, True), (False, True), (False, True), (False, True),
        (0, 0x10000, 0x20000),
    ):
        base = layout(b"\0" * 8 if version else None)
        optional = ((4 if request_target else 0) | (0x20000000 if key128 else 0)
                    | (0x02000000 if version else 0) | (2 if oem else 0)
                    | target_type)
        for enabled in range(complete + 1):
            required = sum(1 << bit for index, bit in enumerate(required_bits)
                           if enabled & (1 << index))
            flags = required | optional
            raw = base.copy()
            struct.pack_into("<I", raw, 20, flags)
            add("required-profile negotiation matrix", raw, enabled == complete, flags,
                "Invalid_Protocol")
    return cases


if __name__ == "__main__":
    run_cases(fixtures(), "challenge fields")
