#!/usr/bin/env python3
"""Reject accidental runtime dependencies outside the Pure Ada profile."""

import re
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

# The specification packages (SMB.Spec.*) transcribe the standards and may
# not depend on the implementation: only on SMB's types, Interfaces and other
# specification packages.
SPEC_ALLOWED = re.compile(r"^(SMB|SMB\.Spec(\.\w+)*|Interfaces(\.\w+)*)$")
for path in sorted((ROOT / "src").glob("smb-spec*.ad?")):
    content = path.read_text(encoding="utf-8")
    if not re.search(r"\bwith\s+Ghost\b", content):
        raise SystemExit(f"specification package is not ghost: {path.name}")
    # The context clause: what comes before the unit itself.
    context = re.split(r"^\s*(?:private\s+)?(?:package|procedure|function|generic)\b",
                       content, maxsplit=1, flags=re.MULTILINE)[0]
    for clause in re.findall(r"^\s*(?:limited\s+|private\s+)*with\s+([^;]+);",
                             context, re.MULTILINE):
        for unit in (name.strip() for name in clause.split(",")):
            if not SPEC_ALLOWED.match(unit):
                raise SystemExit(
                    f"specification {path.name} depends on {unit}")

PROOF_PROJECT = (ROOT / "proof.gpr").read_text(encoding="utf-8")
PROOF_UNITS = {
    "smb.ads",
    "smb-spec.ads",
    "smb-spec-encoding.ads",
    "smb-crypto.ads",
    "smb-crypto.adb",
    "smb-aes.ads",
    "smb-aes.adb",
    "smb-aes-cmac.ads",
    "smb-aes-cmac.adb",
    "smb-aes-ccm.ads",
    "smb-aes-ccm.adb",
    "smb-aes-gcm.ads",
    "smb-aes-gcm.adb",
    "smb-kdf.ads",
    "smb-kdf.adb",
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
    "smb-core_negotiate.ads",
    "smb-core_negotiate.adb",
    "smb-core_preauth.ads",
    "smb-core_preauth.adb",
    "smb-core_transform.ads",
    "smb-core_transform.adb",
    "smb-core_connection.ads",
    "smb-core_connection.adb",
    "smb-core_client.ads",
    "smb-core_client.adb",
    "smb-core_query.ads",
    "smb-core_query.adb",
    "smb-core_request.ads",
    "smb-core_request.adb",
    "smb-core_resize.ads",
    "smb-core_resize.adb",
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
    "smb-aes-cmac.adb",
    "smb-aes-ccm.adb",
    "smb-aes-gcm.adb",
    "smb-kdf.adb",
    "smb-core_wire.adb",
    "smb-core_text.adb",
    "smb-core_ntlm.adb",
    "smb-core_auth.adb",
    "smb-core_protocol.adb",
    "smb-core_negotiate.adb",
    "smb-core_preauth.adb",
    "smb-core_transform.adb",
    "smb-core_connection.adb",
    "smb-core_client.adb",
    "smb-core_query.adb",
    "smb-core_request.adb",
    "smb-core_resize.adb",
    "smb-engine.adb",
}
for body in PROOF_BODIES:
    contents = (ROOT / "src" / body).read_text(encoding="utf-8")
    if "pragma SPARK_Mode (On);" not in contents and "with SPARK_Mode" not in contents:
        raise SystemExit(f"SPARK analyzer mode is not explicit in core body: {body}")

print("runtime dependency checks passed")
