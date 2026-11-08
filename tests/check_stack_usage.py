#!/usr/bin/env python3
"""Bound the stack used by each public SMB.Client call.

Reads the GCC call-graph files written by `-fcallgraph-info=su` (see
`make stack-check`) and sums the largest static frame chain below every public
SMB.Client subprogram. GNAT runtime frames and indirect calls (the entropy
callback) are not in the graph and are not counted.
"""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OBJ = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "build/obj/stack-usage"
# Static stack budget per public call.
STATIC_BUDGET = 256 * 1024
IO_UNITS = {"smb-client.adb", "smb-transport.adb"}
# Runtime-sized frames allowed in the non-SPARK I/O layer. Each one is sized by
# a host, path or name string or by an exception message, never by a frame,
# packet or transfer length.
DYNAMIC_ALLOWED = {
    ("smb-client.adb", "CHECK_HANDLE"),
    ("smb-client.adb", "CONNECT"),
    ("smb-client.adb", "CONNECT_SHARE"),
    ("smb-client.adb", "CREATE_INTERNAL"),
    ("smb-client.adb", "DECODE_NAME"),
    ("smb-client.adb", "ENCODED_PATH"),
    ("smb-client.adb", "RENAME"),
    ("smb-client.adb", "REQUIRE_TRANSFER_STATUS"),
    ("smb-client.adb", "VALIDATED_PATH"),
}
# These frames handle peer-chosen lengths (response signatures before they are
# known to be valid, the NTLM challenge and its target information), so they
# must not grow with that length.
STATIC_REQUIRED = {
    ("smb-core_wire.adb", "VERIFY_SIGNATURE"),
    ("smb-crypto.adb", "SHA256"),
    ("smb-crypto.adb", "SHA256_UPDATE"),
    ("smb-crypto.adb", "SHA512"),
    ("smb-crypto.adb", "SHA512_UPDATE"),
    ("smb-crypto.adb", "HMAC_SHA256"),
    ("smb-crypto.adb", "HMAC_SHA256_UPDATE"),
    ("smb-crypto.adb", "MD5"),
    ("smb-crypto.adb", "MD5_UPDATE"),
    ("smb-crypto.adb", "HMAC_MD5"),
    ("smb-crypto.adb", "HMAC_MD5_UPDATE"),
    ("smb-core_auth.adb", "AUTHENTICATE"),
    ("smb-core_auth.adb", "PROCESS_TARGET_INFO"),
    ("smb-core_auth.adb", "BUILD_TYPE3"),
}

NODE = re.compile(r'node: \{ title: "([^"]+)" label: "([^"]*)"')
EDGE = re.compile(r'edge: \{ sourcename: "([^"]+)" targetname: "([^"]+)"')
LABEL = re.compile(
    r"^(?P<name>[^\\]+)\\n.*?(?P<file>[^\\/:]+\.ad[bs]):\d+:\d+"
    r"\\n(?P<size>\d+) bytes \((?P<kind>[a-z,]+)\)$"
)

files = sorted(OBJ.glob("*.ci"))
if not files:
    raise SystemExit(f"no call-graph files in {OBJ}; run make stack-check")

frames = {}
edges = {}
for path in files:
    text = path.read_text(encoding="utf-8", errors="replace")
    for title, label in NODE.findall(text):
        match = LABEL.match(label)
        if match:
            frames[title] = match
    for source, target in EDGE.findall(text):
        edges.setdefault(source, set()).add(target)

worst = {}


def deepest(title, path):
    if title in path:
        raise SystemExit("recursive call chain: " + " -> ".join(path + (title,)))
    if title not in worst:
        best = (0, ())
        for callee in edges.get(title, ()):
            if callee in frames:
                best = max(best, deepest(callee, path + (title,)))
        worst[title] = (int(frames[title]["size"]) + best[0], (title,) + best[1])
    return worst[title]


spec = (ROOT / "src/smb-client.ads").read_text(encoding="utf-8")
public = {name.lower() for name in
          re.findall(r"^\s*(?:procedure|function)\s+(\w+)", spec, re.M)}
entries = sorted(title for title in frames
                 if (m := re.fullmatch(r"smb__client__([a-z_]+?)(?:__\d+)?", title))
                 and m.group(1) in public)
if not entries:
    raise SystemExit("no public SMB.Client subprograms found in the call graph")

failures = []
for title in entries:
    total, chain = deepest(title, ())
    print(f"{total:>9,} bytes  {title}")
    if total > STATIC_BUDGET:
        failures.append(
            f"{title} needs {total:,} bytes (budget {STATIC_BUDGET:,}): "
            + " -> ".join(frames[t]["name"] for t in chain))

def runtime_sized(kind):
    # "dynamic,bounded" (e.g. stack realignment or probing on x86_64 Linux)
    # reports an upper bound, so the budget above already covers it.
    return "dynamic" in kind and "bounded" not in kind


seen = set()
for title, frame in sorted(frames.items()):
    key = (frame["file"], frame["name"])
    seen.add(key)
    if frame["file"] in IO_UNITS and runtime_sized(frame["kind"]) \
            and key not in DYNAMIC_ALLOWED:
        failures.append(
            f"runtime-sized stack frame in {key[0]}: {key[1]} ({frame['kind']})")
    if key in STATIC_REQUIRED and runtime_sized(frame["kind"]):
        failures.append(
            f"packet-sized stack frame in {key[0]}: {key[1]} ({frame['kind']})")
for key in sorted(STATIC_REQUIRED - seen):
    failures.append(f"expected subprogram not in call graph: {key[0]}: {key[1]}")

if failures:
    raise SystemExit("stack usage check failed:\n  " + "\n  ".join(failures))
print(f"stack usage within {STATIC_BUDGET:,} bytes per public call")
