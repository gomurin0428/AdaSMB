#!/usr/bin/env python3
"""Compare the real Ada codecs with Python strict codecs (SMB forbids NUL)."""

import argparse
from collections import Counter
import json
from pathlib import Path
import random
import subprocess
import sys
import tempfile


def hex_token(value):
    return value.hex() or "-"


def pair(text):
    return f"P {hex_token(text.encode('utf-8'))} {hex_token(text.encode('utf-16-le'))}\n"


def conversion(data, direction):
    encoding, target = (
        ("utf-8", "utf-16-le") if direction == "8" else ("utf-16-le", "utf-8")
    )
    if direction == "6" and len(data) % 2:
        expected = "L"
    else:
        try:
            text = data.decode(encoding, errors="strict")
            expected = "E" if "\0" in text else hex_token(text.encode(target))
        except UnicodeError:
            expected = "E"
    return f"{direction} {hex_token(data)} {expected}\n"


def corpus():
    for scalar in range(1, 0x110000):
        if not 0xD800 <= scalar <= 0xDFFF:
            yield "scalar_pairs", pair(chr(scalar))
    for text in ("", "ASCII", "Aé€😀", "\x7f\x80\u07ff\u0800\ud7ff\ue000\uffff\U00010000\U0010ffff"):
        yield "fixed_sequences", pair(text)
    for value in range(256):
        yield "utf8_single_bytes", conversion(bytes([value]), "8")
    for value in range(65536):
        data = value.to_bytes(2, "little")
        yield "utf8_byte_pairs", conversion(data, "8")
        yield "utf16_code_units", conversion(data, "6")
    rng = random.Random(0xADA5_B021)
    for _ in range(4096):
        scalars = []
        for _ in range(rng.randrange(33)):
            scalar = rng.randrange(1, 0x110000)
            while 0xD800 <= scalar <= 0xDFFF:
                scalar = rng.randrange(1, 0x110000)
            scalars.append(chr(scalar))
        yield "mixed_sequences", pair("".join(scalars))
    for _ in range(20000):
        for direction in ("8", "6"):
            data = bytes(rng.randrange(256) for _ in range(rng.randrange(65)))
            category = "random_utf8" if direction == "8" else "random_utf16"
            yield category, conversion(data, direction)
    for data in (
        b"\xc0\xaf", b"\xe0\x80\xaf", b"\xf0\x80\x80\xaf",
        b"\xed\xa0\x80", b"\xf4\x90\x80\x80",
        b"A\x00B", b"A\xe2\x82", b"A\xf0\x9f\x98",
    ):
        yield "malformed_utf8", conversion(data, "8")
    for data in (
        b"\x00\xd8A\x00", b"\x00\xdc\x00\xd8",
        b"A\x00\x00\x00B\x00", b"A\x00\x00\xd8",
    ):
        yield "malformed_utf16", conversion(data, "6")


def check_probe(probe):
    for fixture, diagnostic in (
        (b"P 41 4200\n", b"UTF-8 result mismatch"),
        (b"6 4100 42\n", b"UTF-16 result mismatch"),
        (b"8 80 L\n", b"UTF-8 status/bounds mismatch"),
        (b"6 4100 E\n", b"UTF-16 validator status mismatch"),
        (b"6 00d8 41\n", b"UTF-16 validator status mismatch"),
    ):
        control = subprocess.run(
            [probe], input=fixture, capture_output=True, timeout=10
        )
        if control.returncode == 0 or diagnostic not in control.stderr:
            raise SystemExit("negative control did not detect a wrong expectation")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--probe",
        default="build/bin/unicode_probe.exe" if sys.platform == "win32"
        else "build/bin/unicode_probe")
    args = parser.parse_args()
    probe = str(Path(args.probe).resolve())
    if not Path(probe).is_file():
        parser.error("probe not built; run make unicode-test")
    check_probe(probe)
    counts = Counter()
    with tempfile.TemporaryFile() as fixtures:
        for category, line in corpus():
            fixtures.write(line.encode("ascii"))
            counts[category] += 1
        if counts["scalar_pairs"] != 0x110000 - 2048 - 1:
            raise SystemExit("incomplete scalar corpus")
        fixtures.seek(0)
        result = subprocess.run(
            [probe], stdin=fixtures, capture_output=True, timeout=180
        )
    total = sum(counts.values())
    if result.returncode != 0 or result.stdout.strip() != f"PASS {total}".encode():
        raise SystemExit(
            "Unicode conformance failed:\n"
            + result.stdout.decode(errors="replace")
            + result.stderr.decode(errors="replace")
        )
    print(json.dumps({"fixtures": total, "categories": counts, "seed": "0xADA5B021"}))


if __name__ == "__main__":
    main()
