#!/usr/bin/env python3
"""Reject accidental runtime dependencies outside the Pure Ada profile."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCES = list((ROOT / "src").rglob("*.ad?"))
WINDOWS_ENTROPY = ROOT / "src/platform/windows/smb-entropy.adb"
SOURCE = "\n".join(p.read_text(encoding="utf-8") for p in SOURCES)
FORBIDDEN = (
    "Ada.Numerics",
    "Interfaces.C",
    "libsmbclient",
    "OpenSSL",
    "GNUTLS",
    "System.Address_To_Access_Conversions",
)

for item in FORBIDDEN:
    if item in SOURCE:
        raise SystemExit(f"forbidden runtime dependency: {item}")

for path in SOURCES:
    content = path.read_text(encoding="utf-8")
    if path == WINDOWS_ENTROPY:
        allowed = 'pragma Import (Stdcall, BCryptGenRandom, "BCryptGenRandom");'
        if content.count(allowed) != 1:
            raise SystemExit("Windows entropy must use the reviewed OS RNG binding")
        content = content.replace(allowed, "")
    if "pragma Import" in content or "with Import" in content:
        raise SystemExit(f"unexpected foreign binding: {path}")

if "/dev/urandom" not in SOURCE:
    raise SystemExit("the default entropy source is not documented in code")

PROOF_PROJECT = (ROOT / "proof.gpr").read_text(encoding="utf-8")
PROOF_UNITS = {
    "smb.ads",
    "smb-crypto.ads",
    "smb-crypto.adb",
    "smb-aes.ads",
    "smb-aes.adb",
    "smb-core_wire.ads",
    "smb-core_wire.adb",
    "smb-core_text.ads",
    "smb-core_text.adb",
    "smb-core_ntlm.ads",
    "smb-core_ntlm.adb",
    "smb-core_auth.ads",
    "smb-core_auth.adb",
    "smb-core_framing.ads",
    "smb-core_framing.adb",
    "smb-core_transport.ads",
    "smb-core_transport.adb",
    "smb-core_clock.ads",
    "smb-core_clock.adb",
    "smb-core_protocol.ads",
    "smb-core_protocol.adb",
    "smb-core_connection.ads",
    "smb-core_connection.adb",
    "smb-core_client.ads",
    "smb-core_client.adb",
    "smb-engine.ads",
    "smb-engine.adb",
}
for unit in PROOF_UNITS:
    if f'"{unit}"' not in PROOF_PROJECT:
        raise SystemExit(f"SPARK proof project omits required core unit: {unit}")

PROOF_BODIES = {
    "smb-core_framing.adb",
    "smb-core_transport.adb",
    "smb-core_clock.adb",
    "smb-crypto.adb",
    "smb-aes.adb",
    "smb-core_wire.adb",
    "smb-core_text.adb",
    "smb-core_ntlm.adb",
    "smb-core_auth.adb",
    "smb-core_protocol.adb",
    "smb-core_connection.adb",
    "smb-core_client.adb",
    "smb-engine.adb",
}
for body in PROOF_BODIES:
    contents = (ROOT / "src" / body).read_text(encoding="utf-8")
    if "pragma SPARK_Mode (On);" not in contents and "with SPARK_Mode" not in contents:
        raise SystemExit(f"SPARK analyzer mode is not explicit in core body: {body}")

print("runtime dependency checks passed")
