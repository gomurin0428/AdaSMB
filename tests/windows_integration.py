#!/usr/bin/env python3
"""Run the integration client against this machine's Windows SMB server.

Meant for the Windows CI runner: a disposable virtual machine whose job runs
as an administrator. The harness creates a test-only local account, with a
random password generated here and never printed, and a share holding the
same fixture as the Samba test. It then runs the integration client over SMB
3.1.1 five times: with a cipher negotiated but not required, then with the
server requiring encryption and allowing only one cipher, AES-128-GCM,
AES-128-CCM, AES-256-GCM and AES-256-CCM in turn, where the client must
report that cipher. It then puts the server's EncryptData and
EncryptionCiphers settings back as they were and removes the share and the
account.

It refuses to run anywhere but Windows, and without ADASMB_WINDOWS_SERVER=1,
so that it never changes a developer's own machine by accident.
"""

from __future__ import annotations

import os
import pathlib
import secrets
import subprocess
import sys
import tempfile


ROOT = pathlib.Path(__file__).resolve().parents[1]
USER = "adasmb_test_only"
SHARE = "adasmb_test"
CLIENT = ROOT / "build" / "bin" / "integration_client.exe"


def powershell(script: str, env: dict[str, str] | None = None) -> None:
    subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command",
         "$ErrorActionPreference = 'Stop'; " + script],
        check=True, env=env, timeout=120)


def powershell_output(script: str) -> str:
    return subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command",
         "$ErrorActionPreference = 'Stop'; " + script],
        check=True, capture_output=True, text=True, timeout=120).stdout.strip()


def diagnostics() -> None:
    subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command",
         "Get-SmbServerConfiguration | Format-List EnableSMB2Protocol,"
         " EncryptData, EncryptionCiphers, RejectUnencryptedAccess,"
         " RequireSecuritySignature;"
         " Get-SmbShare | Format-Table -AutoSize;"
         " Get-WinEvent -LogName Microsoft-Windows-SMBServer/Operational"
         " -MaxEvents 20 -ErrorAction SilentlyContinue | Format-List"
         " TimeCreated, Id, Message"],
        check=False, timeout=120)


def populate(share: pathlib.Path) -> None:
    (share / "fixture.txt").write_text(
        "AdaSMB integration fixture\n", encoding="utf-8", newline="\n")
    (share / "interrupted-read.bin").write_bytes(
        bytes(index % 251 for index in range(70_001)))
    readonly = share / "readonly.txt"
    readonly.write_text("read-only test fixture\n", encoding="utf-8", newline="\n")
    # On Windows this sets FILE_ATTRIBUTE_READONLY, so opening the file for
    # writing fails with STATUS_ACCESS_DENIED, as the client expects.
    readonly.chmod(0o444)
    for index in range(1_200):
        (share / f"pagination-{index:04}.txt").touch()


def run_client(password: str, encryption: str, label: str,
               cipher: str | None = None) -> None:
    env = os.environ.copy()
    env.update(
        SMB_TEST_HOST="127.0.0.1",
        SMB_TEST_PORT="445",
        SMB_TEST_SHARE=SHARE,
        SMB_TEST_USER=USER,
        SMB_TEST_PASSWORD=password,
        SMB_TEST_DIALECTS="311",
        SMB_TEST_ENCRYPTION=encryption,
    )
    env.pop("SMB_TEST_CIPHER", None)
    if cipher is not None:
        # The client checks that it negotiated this cipher.
        env["SMB_TEST_CIPHER"] = cipher
    subprocess.run([str(CLIENT)], check=True, env=env, timeout=600)
    print(f"Windows SMB server, SMB 3.1.1, {label}: passed", flush=True)


def cleanup(steps: list[str]) -> None:
    """Run every step, even after one fails, then report the failures."""
    failed = []
    for step in steps:
        try:
            powershell(step)
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            failed.append(step)
    if failed:
        raise RuntimeError("windows_integration: cleanup failed: " + "; ".join(failed))


def main() -> int:
    if sys.platform != "win32" or os.environ.get("ADASMB_WINDOWS_SERVER") != "1":
        print("windows_integration: set ADASMB_WINDOWS_SERVER=1 on a disposable "
              "Windows machine; this test adds a local account and a share and "
              "changes the SMB server's encryption settings while it runs",
              file=sys.stderr)
        return 2
    if not CLIENT.exists():
        print(f"windows_integration: build {CLIENT} first", file=sys.stderr)
        return 2
    if powershell_output(
            f"[bool](Get-LocalUser -Name {USER} -ErrorAction SilentlyContinue)"
            f" -or [bool](Get-SmbShare -Name {SHARE} -ErrorAction SilentlyContinue)"
            ) != "False":
        print(f"windows_integration: the account or share {USER} already exists",
              file=sys.stderr)
        return 2
    encrypt_data = powershell_output("(Get-SmbServerConfiguration).EncryptData")
    ciphers = powershell_output("(Get-SmbServerConfiguration).EncryptionCiphers")
    if encrypt_data not in ("True", "False") or not ciphers:
        print("windows_integration: needs an SMB server with the EncryptionCiphers "
              "setting (Windows Server 2022, Windows 11 or later)", file=sys.stderr)
        return 2
    print(f"server ciphers: {ciphers}", flush=True)
    # A fresh random password for a throwaway account on a throwaway
    # machine; the prefix meets the complexity rule.
    password = "Aa1-" + secrets.token_urlsafe(24)
    secret_env = os.environ.copy()
    secret_env["ADASMB_TEST_ACCOUNT_PASSWORD"] = password
    with tempfile.TemporaryDirectory(
            prefix="adasmb-windows-", ignore_cleanup_errors=True) as directory:
        share = pathlib.Path(directory) / "share"
        share.mkdir()
        powershell(
            "if ((Get-Service LanmanServer).Status -ne 'Running')"
            " { Start-Service LanmanServer };"
            f" New-LocalUser -Name {USER} -AccountNeverExpires"
            " -PasswordNeverExpires -Password (ConvertTo-SecureString"
            " $env:ADASMB_TEST_ACCOUNT_PASSWORD -AsPlainText -Force) | Out-Null",
            env=secret_env)
        try:
            # Builtin Users, by SID so that a localized name does not matter.
            powershell(f"Add-LocalGroupMember -SID S-1-5-32-545 -Member {USER}")
            subprocess.run(
                ["icacls", str(share), "/grant", f"{USER}:(OI)(CI)M"],
                check=True, stdout=subprocess.DEVNULL, timeout=120)
            populate(share)
            powershell(
                f"New-SmbShare -Name {SHARE} -Path '{share}'"
                f" -ChangeAccess {USER} | Out-Null")
            try:
                run_client(password, "on", "cipher negotiated, not required")
                powershell("Set-SmbServerConfiguration -EncryptData $true -Force")
                # With one cipher allowed, the client must negotiate it.
                for cipher in ("AES_128_GCM", "AES_128_CCM",
                               "AES_256_GCM", "AES_256_CCM"):
                    powershell("Set-SmbServerConfiguration"
                               f" -EncryptionCiphers '{cipher}' -Force")
                    run_client(password, "required",
                               f"encryption required, {cipher} only", cipher)
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
                diagnostics()
                raise
            finally:
                cleanup([
                    f"Set-SmbServerConfiguration -EncryptData ${encrypt_data}"
                    f" -EncryptionCiphers '{ciphers}' -Force",
                    f"Remove-SmbShare -Name {SHARE} -Force",
                ])
        finally:
            cleanup([f"Remove-LocalUser -Name {USER}"])
            readonly = share / "readonly.txt"
            if readonly.exists():
                readonly.chmod(0o644)
    print("Windows SMB server integration tests passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
