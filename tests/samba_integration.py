#!/usr/bin/env python3
"""Run the opt-in local Samba integration test.

The harness creates a temporary Samba configuration and passdb, then invokes
the Ada test executable.  It requires a local smbd/smbpasswd installation and
does not contact a remote host.
"""

from __future__ import annotations

import os
import pathlib
import pwd
import signal
import shutil
import socket
import subprocess
import sys
import tempfile
import time

from adversarial_proxy import AdversarialProxy, DIRECTORY_MODES


ROOT = pathlib.Path(__file__).resolve().parents[1]
PORT = int(os.environ.get("ADASMB_TEST_PORT", "1445"))
USER = "ada_smb_test_only"
PASSWORD = "AdaSMB-test-only-password"


def run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, check=True, text=True, **kwargs)


def main() -> int:
    if shutil.which("smbd") is None or shutil.which("smbpasswd") is None:
        print("make integration: smbd/smbpasswd not installed", file=sys.stderr)
        return 2
    with tempfile.TemporaryDirectory(prefix="adasmb-samba-") as directory:
        work = pathlib.Path(directory)
        work.chmod(0o755)
        share = work / "share"
        share.mkdir()
        share.chmod(0o777)
        (share / "fixture.txt").write_text("AdaSMB integration fixture\n", encoding="utf-8")
        (share / "interrupted-read.bin").write_bytes(
            bytes(index % 251 for index in range(70_001))
        )
        readonly = share / "readonly.txt"
        readonly.write_text("read-only test fixture\n", encoding="utf-8")
        readonly.chmod(0o444)
        for index in range(1_200):
            (share / f"pagination-{index:04}.txt").touch()
        config = work / "smb.conf"
        config.write_text(
            f"""\
[global]
    workgroup = ADASMBTEST
    server role = standalone server
    security = user
    passdb backend = tdbsam:{work / "passdb.tdb"}
    private dir = {work}
    lock directory = {work}
    state directory = {work}
    cache directory = {work}
    pid directory = {work}
    smb ports = {PORT}
    interfaces = 127.0.0.1
    bind interfaces only = yes
    disable netbios = yes
    log file = {work}/smbd.log
    min protocol = SMB2_10
    max protocol = SMB2_10
    server signing = mandatory
    map to guest = never
    log level = 3

[adasmb_test]
    path = {share}
    read only = no
    valid users = {USER}
    force user = {USER}
""",
            encoding="utf-8",
        )
        # A dedicated local account is intentionally test-only.  Root is
        # required by useradd/smbpasswd; skip rather than altering a host.
        if os.geteuid() != 0:
            print("make integration: run as root to create the test-only account",
                  file=sys.stderr)
            return 2
        try:
            pwd.getpwnam(USER)
        except KeyError:
            pass
        else:
            print("make integration: test-only account already exists", file=sys.stderr)
            return 2
        run(
            ["useradd", "--system", "--no-create-home", "--shell", "/usr/sbin/nologin", USER],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            run(["smbpasswd", "-c", str(config), "-a", "-s", USER],
                input=f"{PASSWORD}\n{PASSWORD}\n")
            daemon = subprocess.Popen(
                ["smbd", "-F", "--no-process-group", "-s", str(config)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
            try:
                deadline = time.monotonic() + 10
                while True:
                    try:
                        with socket.create_connection(("127.0.0.1", PORT), timeout=0.25):
                            break
                    except OSError:
                        if daemon.poll() is not None or time.monotonic() >= deadline:
                            raise RuntimeError("local smbd did not open its test port")
                        time.sleep(0.1)
                env = os.environ.copy()
                env.update(
                    SMB_TEST_HOST="127.0.0.1",
                    SMB_TEST_PORT=str(PORT),
                    SMB_TEST_SHARE="adasmb_test",
                    SMB_TEST_USER=USER,
                    SMB_TEST_PASSWORD=PASSWORD,
                    SMB_TEST_PATH=str(share),
                )
                try:
                    run([str(ROOT / "build/bin/integration_client")], env=env)
                except subprocess.CalledProcessError:
                    log = work / "smbd.log"
                    if log.exists():
                        print(log.read_text(encoding="utf-8", errors="replace"),
                              file=sys.stderr)
                    raise
                for index, mode in enumerate(
                    (
                        "truncated",
                        "oversized",
                        "wrong-correlation-negotiate",
                        "dribble-timeout",
                        "unsigned",
                        "tampered-signature",
                        "wrong-correlation-auth",
                    ),
                    start=1,
                ):
                    proxy_port = PORT + index
                    proxy = AdversarialProxy(mode, proxy_port, PORT)
                    proxy.start()
                    adversarial_env = env.copy()
                    adversarial_env.update(
                        SMB_TEST_HOST="127.0.0.1",
                        SMB_TEST_PORT=str(proxy_port),
                        SMB_TEST_MODE=mode,
                    )
                    try:
                        run(
                            [str(ROOT / "build/bin/adversarial_client")],
                            env=adversarial_env,
                        )
                    finally:
                        proxy.join()
                proxy_port = PORT + 8
                proxy = AdversarialProxy(
                    "malformed-signed-create",
                    proxy_port,
                    PORT,
                    user=USER,
                    password=PASSWORD,
                )
                proxy.start()
                cleanup_env = env.copy()
                cleanup_env.update(
                    SMB_TEST_HOST="127.0.0.1",
                    SMB_TEST_PORT=str(proxy_port),
                    SMB_TEST_BACKEND_PORT=str(PORT),
                )
                try:
                    run([str(ROOT / "build/bin/cleanup_client")], env=cleanup_env)
                finally:
                    proxy.join()
                proxy_port = PORT + 9
                proxy = AdversarialProxy(
                    "interrupted-read-after-progress", proxy_port, PORT
                )
                proxy.start()
                interrupted_env = env.copy()
                interrupted_env.update(
                    SMB_TEST_HOST="127.0.0.1",
                    SMB_TEST_PORT=str(proxy_port),
                    SMB_TEST_BACKEND_PORT=str(PORT),
                    SMB_TEST_MODE="interrupted-read-after-progress",
                )
                try:
                    run([str(ROOT / "build/bin/cleanup_client")], env=interrupted_env)
                finally:
                    proxy.join()
                proxy_port = PORT + 14
                proxy = AdversarialProxy(
                    "read-reserved-fields",
                    proxy_port,
                    PORT,
                    user=USER,
                    password=PASSWORD,
                )
                proxy.start()
                reserved_env = env.copy()
                reserved_env.update(
                    SMB_TEST_HOST="127.0.0.1",
                    SMB_TEST_PORT=str(proxy_port),
                    SMB_TEST_BACKEND_PORT=str(PORT),
                    SMB_TEST_MODE="read-reserved-fields",
                )
                try:
                    run([str(ROOT / "build/bin/cleanup_client")], env=reserved_env)
                finally:
                    proxy.join()
                proxy_port = PORT + 15
                proxy = AdversarialProxy(
                    "error-reserved-field",
                    proxy_port,
                    PORT,
                    user=USER,
                    password=PASSWORD,
                )
                proxy.start()
                error_reserved_env = env.copy()
                error_reserved_env.update(
                    SMB_TEST_HOST="127.0.0.1",
                    SMB_TEST_PORT=str(proxy_port),
                    SMB_TEST_BACKEND_PORT=str(PORT),
                    SMB_TEST_MODE="error-reserved-field",
                )
                try:
                    run([str(ROOT / "build/bin/cleanup_client")], env=error_reserved_env)
                finally:
                    proxy.join()
                proxy_port = PORT + 16
                proxy = AdversarialProxy(
                    "teardown-reserved-fields",
                    proxy_port,
                    PORT,
                    user=USER,
                    password=PASSWORD,
                )
                proxy.start()
                teardown_env = env.copy()
                teardown_env.update(
                    SMB_TEST_HOST="127.0.0.1",
                    SMB_TEST_PORT=str(proxy_port),
                    SMB_TEST_BACKEND_PORT=str(PORT),
                    SMB_TEST_MODE="teardown-reserved-fields",
                )
                try:
                    run([str(ROOT / "build/bin/cleanup_client")], env=teardown_env)
                finally:
                    proxy.join()
                proxy_port = PORT + 17
                proxy = AdversarialProxy(
                    "connection-reserved-fields",
                    proxy_port,
                    PORT,
                    user=USER,
                    password=PASSWORD,
                )
                proxy.start()
                connection_env = env.copy()
                connection_env.update(
                    SMB_TEST_HOST="127.0.0.1",
                    SMB_TEST_PORT=str(proxy_port),
                    SMB_TEST_BACKEND_PORT=str(PORT),
                    SMB_TEST_MODE="connection-reserved-fields",
                )
                try:
                    run([str(ROOT / "build/bin/cleanup_client")], env=connection_env)
                finally:
                    proxy.join()
                proxy_port = PORT + 10
                proxy = AdversarialProxy(
                    "lost-write-response-after-progress", proxy_port, PORT
                )
                proxy.start()
                lost_write_env = env.copy()
                lost_write_env.update(
                    SMB_TEST_HOST="127.0.0.1",
                    SMB_TEST_PORT=str(proxy_port),
                    SMB_TEST_BACKEND_PORT=str(PORT),
                    SMB_TEST_MODE="lost-write-response-after-progress",
                )
                try:
                    run([str(ROOT / "build/bin/cleanup_client")], env=lost_write_env)
                finally:
                    proxy.join()
                proxy_port = PORT + 11
                for directory_mode in DIRECTORY_MODES:
                    proxy = AdversarialProxy(
                        directory_mode,
                        proxy_port,
                        PORT,
                        user=USER,
                        password=PASSWORD,
                    )
                    proxy.start()
                    directory_env = env.copy()
                    directory_env.update(
                        SMB_TEST_HOST="127.0.0.1",
                        SMB_TEST_PORT=str(proxy_port),
                        SMB_TEST_BACKEND_PORT=str(PORT),
                        SMB_TEST_MODE=directory_mode,
                    )
                    try:
                        run([str(ROOT / "build/bin/cleanup_client")], env=directory_env)
                    finally:
                        proxy.join()
                set_info_content = b"set-info-renamed-content"
                (share / "set-info-source.txt").write_bytes(set_info_content)
                proxy_port = PORT + 12
                set_info_mode = "malformed-signed-set-info"
                proxy = AdversarialProxy(
                    set_info_mode, proxy_port, PORT, user=USER, password=PASSWORD
                )
                proxy.start()
                set_info_env = env.copy()
                set_info_env.update(
                    SMB_TEST_HOST="127.0.0.1",
                    SMB_TEST_PORT=str(proxy_port),
                    SMB_TEST_BACKEND_PORT=str(PORT),
                    SMB_TEST_MODE=set_info_mode,
                )
                try:
                    run([str(ROOT / "build/bin/cleanup_client")], env=set_info_env)
                finally:
                    proxy.join()
                renamed = share / "set-info-renamed.txt"
                if (share / "set-info-source.txt").exists():
                    raise RuntimeError("SET_INFO source file still exists after rename")
                if not renamed.is_file() or renamed.read_bytes() != set_info_content:
                    raise RuntimeError("SET_INFO remote rename effect/content mismatch")
                renamed.unlink()
                proxy_port = PORT + 13
                tree_disconnect_mode = "malformed-signed-tree-disconnect"
                proxy = AdversarialProxy(
                    tree_disconnect_mode,
                    proxy_port,
                    PORT,
                    user=USER,
                    password=PASSWORD,
                )
                proxy.start()
                tree_disconnect_env = env.copy()
                tree_disconnect_env.update(
                    SMB_TEST_HOST="127.0.0.1",
                    SMB_TEST_PORT=str(proxy_port),
                    SMB_TEST_BACKEND_PORT=str(PORT),
                    SMB_TEST_MODE=tree_disconnect_mode,
                )
                try:
                    run(
                        [str(ROOT / "build/bin/cleanup_client")],
                        env=tree_disconnect_env,
                    )
                finally:
                    proxy.join()
                for index, mode in enumerate(
                    ("unsigned-auth-error", "unsigned-auth-success", "unsigned-auth-wrong-id"),
                    start=18,
                ):
                    proxy_port = PORT + index
                    proxy = AdversarialProxy(mode, proxy_port, PORT)
                    proxy.start()
                    diagnostic_env = env.copy()
                    diagnostic_env.update(
                        SMB_TEST_PORT=str(proxy_port),
                        SMB_TEST_BACKEND_PORT=str(PORT),
                        SMB_TEST_MODE=mode,
                    )
                    try:
                        run([str(ROOT / "build/bin/auth_diagnostic_client")],
                            env=diagnostic_env)
                    finally:
                        proxy.join()
            finally:
                try:
                    os.killpg(daemon.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                daemon.wait(timeout=10)
        finally:
            subprocess.run(["userdel", USER], check=False,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print(f"local Samba integration passed on 127.0.0.1:{PORT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
