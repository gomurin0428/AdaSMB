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
import select
import signal
import shutil
import socket
import subprocess
import sys
import tempfile
import time

from adversarial_proxy import (
    AdversarialProxy, DIRECTORY_MODES, EntropyFailureProxy, RESPONSE_MUTATIONS,
    SECURITY_BUFFER_MUTATIONS,
)
from async_proxy import AsyncProxy, NEGATIVE_MODES
from directory_limit_proxy import DirectoryLimitProxy, MODES as DIRECTORY_LIMIT_MODES
from counting_proxy import RequestCountingProxy


ROOT = pathlib.Path(__file__).resolve().parents[1]
PORT = int(os.environ.get("ADASMB_TEST_PORT", "1445"))
USER = "ada_smb_test_only"
PASSWORD = "AdaSMB-test-only-password"


def run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, check=True, text=True, **kwargs)


def smbd_diagnostics(work: pathlib.Path) -> str:
    lines = []
    for name in ("smbd.out", "smbd.log"):
        path = work / name
        if path.exists():
            text = path.read_text(encoding="utf-8", errors="replace")
            lines += [f"--- {name} ---", *text.splitlines()[-40:]]
    return "\n".join(lines)


def run_directory_mutation_cases(env: dict[str, str]) -> None:
    selected = os.environ.get("ADASMB_DIRECTORY_MODE")
    if selected is not None and selected not in DIRECTORY_MODES:
        raise ValueError("unknown directory mutation selector")
    for mode in DIRECTORY_MODES:
        if selected is not None and mode != selected:
            continue
        proxy = AdversarialProxy(mode, 0, PORT, user=USER, password=PASSWORD)
        proxy.start()
        directory_env = env.copy()
        directory_env.update(
            SMB_TEST_PORT=str(proxy.listener.getsockname()[1]),
            SMB_TEST_BACKEND_PORT=str(PORT), SMB_TEST_MODE=mode,
        )
        try:
            run([str(ROOT / "build/bin/cleanup_client")], env=directory_env, timeout=60)
        finally:
            proxy.join()


def run_directory_limit_cases(env: dict[str, str]) -> None:
    selected = os.environ.get("ADASMB_DIRECTORY_LIMIT_MODE")
    if selected is not None and selected not in DIRECTORY_LIMIT_MODES:
        raise ValueError("unknown directory limit selector")
    for mode in DIRECTORY_LIMIT_MODES:
        if selected is not None and mode != selected:
            continue
        proxy = DirectoryLimitProxy(mode, 0, PORT, USER, PASSWORD)
        proxy.start()
        limit_env = env.copy()
        limit_env.update(
            SMB_TEST_PORT=str(proxy.listener.getsockname()[1]),
            SMB_TEST_BACKEND_PORT=str(PORT), SMB_TEST_MODE=mode,
        )
        try:
            run([str(ROOT / "build/bin/cleanup_client")], env=limit_env, timeout=180)
        finally:
            proxy.join()


def run_handle_capacity_case(env: dict[str, str]) -> None:
    proxy = RequestCountingProxy(0, PORT)
    proxy.start()
    case_env = env.copy()
    case_env.update(
        SMB_TEST_PORT=str(proxy.listener.getsockname()[1]),
        SMB_TEST_BACKEND_PORT=str(PORT), SMB_TEST_MODE="handle-capacity",
    )
    try:
        run([str(ROOT / "build/bin/cleanup_client")], env=case_env, timeout=60)
    finally:
        proxy.join()
    # One setup directory, 256 files, one enumeration, one replacement, one removal.
    if (proxy.commands[5] != 260 or proxy.commands[6] != 260
            or proxy.peak_handles != 256 or proxy.open_handles != 0
            or proxy.commands[17] != 1 or proxy.commands[4] != 1
            or proxy.commands[2] != 1):
        raise RuntimeError(f"unexpected handle-capacity request counts: {proxy.commands}")
    share = pathlib.Path(env["SMB_TEST_PATH"])
    if (share / "fixture.txt").read_text(encoding="utf-8") != "AdaSMB integration fixture\n":
        raise RuntimeError("capacity refusal modified the fixture")
    if any((share / name).exists() for name in (
        "capacity-created.txt", "capacity-new-dir", "capacity-renamed.txt",
        "capacity-retained-dir",
    )):
        raise RuntimeError("capacity test left an unexpected filesystem change")
    print("handle capacity: peak 256, exactly 260 CREATE/CLOSE, no excess CREATE")


def run_entropy_cases(env: dict[str, str]) -> None:
    for on_call, mode in ((1, "before-connect"), (2, "after-challenge")):
        for kind in ("AUTHENTICATION_FAILURE", "STATE_FAILURE", "UNEXPECTED_FAILURE"):
            proxy = EntropyFailureProxy(mode, 0, PORT)
            proxy.start()
            fault_env = env.copy()
            fault_env.update(
                SMB_TEST_PORT=str(proxy.listener.getsockname()[1]),
                SMB_TEST_BACKEND_PORT=str(PORT),
                SMB_TEST_ENTROPY_CALL=str(on_call),
                SMB_TEST_ENTROPY_KIND=kind,
            )
            joined = False
            process = None
            try:
                process = subprocess.Popen(
                    [str(ROOT / "build/bin/entropy_failure_client")],
                    env=fault_env, stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True,
                )
                assert process.stdout is not None and process.stdin is not None
                ready, _, _ = select.select([process.stdout], [], [], 15)
                if not ready or process.stdout.readline() != "entropy failure checkpoint\n":
                    raise RuntimeError("entropy client did not reach failure checkpoint")
                try:
                    proxy.join()
                finally:
                    joined = True
                process.stdin.write("failure-observed\n")
                process.stdin.flush()
                output, _ = process.communicate(timeout=20)
                print(output, end="", flush=True)
                if process.returncode:
                    raise RuntimeError("entropy recovery client failed")
            finally:
                if process is not None:
                    if process.poll() is None:
                        process.kill()
                    process.wait(timeout=5)
                if not joined:
                    proxy.join()


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
        # ADASMB_SMB311_ONLY=1 runs the integration client in its default,
        # 3.1.1-only policy against a server that speaks only 3.1.1. The
        # proxy tests below need the 2.1 server, as their proxies re-sign
        # with the 2.1 key.
        smb311_only = os.environ.get("ADASMB_SMB311_ONLY") == "1"
        protocol = "SMB3_11" if smb311_only else "SMB2_10"
        # ADASMB_SMB_ENCRYPT sets "server smb encrypt": "off" leaves 3.1.1
        # signed but not encrypted, "required" encrypts every session.
        encrypt = os.environ.get("ADASMB_SMB_ENCRYPT", "off")
        if encrypt not in ("off", "required"):
            raise SystemExit("ADASMB_SMB_ENCRYPT must be off or required")
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
    min protocol = {protocol}
    max protocol = {protocol}
    server signing = mandatory
    server smb encrypt = {encrypt}
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
            # smbd -F exits on EOF when stdin is a pipe or socket, and CI steps
            # run with a closed one; hold a pipe open so smbd also stops if
            # this harness dies.
            with (work / "smbd.out").open("wb") as output:
                daemon = subprocess.Popen(
                    ["smbd", "-F", "--no-process-group", "-s", str(config)],
                    stdin=subprocess.PIPE,
                    stdout=output,
                    stderr=subprocess.STDOUT,
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
                            raise RuntimeError(
                                "local smbd did not open its test port "
                                f"(exit status {daemon.poll()})\n" + smbd_diagnostics(work))
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
                if smb311_only:
                    env["SMB_TEST_DIALECTS"] = "311"
                    env["SMB_TEST_ENCRYPTION"] = "on" if encrypt == "required" else "off"
                    try:
                        run([str(ROOT / "build/bin/integration_client")], env=env)
                    except subprocess.CalledProcessError:
                        log = work / "smbd.log"
                        if log.exists():
                            print(log.read_text(encoding="utf-8", errors="replace"),
                                  file=sys.stderr)
                        raise
                    print("local Samba SMB 3.1.1 integration tests passed")
                    return 0
                if os.environ.get("ADASMB_DIRECTORY_ONLY") == "1":
                    run_directory_mutation_cases(env)
                    print("local Samba directory mutation/recovery tests passed")
                    return 0
                if os.environ.get("ADASMB_HANDLES_ONLY") == "1":
                    run_handle_capacity_case(env)
                    return 0
                if os.environ.get("ADASMB_DIRECTORY_LIMITS_ONLY") == "1":
                    run_directory_limit_cases(env)
                    print("local Samba directory limit/recovery tests passed")
                    return 0
                if os.environ.get("ADASMB_ENTROPY_ONLY") == "1":
                    run_entropy_cases(env)
                    print("local Samba entropy failure/recovery tests passed")
                    return 0
                if os.environ.get("ADASMB_ASYNC_ONLY") != "1":
                    run_handle_capacity_case(env)
                    run_entropy_cases(env)
                try:
                    run([str(ROOT / "build/bin/integration_client")], env=env)
                except subprocess.CalledProcessError:
                    log = work / "smbd.log"
                    if log.exists():
                        print(log.read_text(encoding="utf-8", errors="replace"),
                              file=sys.stderr)
                    raise
                async_modes = ["async-success", *sorted(NEGATIVE_MODES)]
                for index, mode in enumerate(async_modes, start=40):
                    proxy_port = PORT + index
                    proxy = AsyncProxy(mode, proxy_port, PORT, USER, PASSWORD)
                    proxy.start()
                    async_env = env.copy()
                    async_env.update(
                        SMB_TEST_HOST="127.0.0.1",
                        SMB_TEST_PORT=str(proxy_port),
                        SMB_TEST_BACKEND_PORT=str(PORT),
                        SMB_TEST_MODE=mode,
                    )
                    try:
                        run([str(ROOT / "build/bin/async_client")], env=async_env)
                    finally:
                        proxy.join()
                if os.environ.get("ADASMB_ASYNC_ONLY") == "1":
                    return 0
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
                run_directory_mutation_cases(env)
                run_directory_limit_cases(env)
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
                for index, mode in enumerate(RESPONSE_MUTATIONS, start=21):
                    (share / "mutation-write.bin").write_bytes(b"A" * 64)
                    (share / "mutation-write.bin").chmod(0o666)
                    proxy_port = PORT + index
                    proxy = AdversarialProxy(mode, proxy_port, PORT, user=USER, password=PASSWORD)
                    proxy.start()
                    mutation_env = env.copy()
                    mutation_env.update(
                        SMB_TEST_PORT=str(proxy_port),
                        SMB_TEST_BACKEND_PORT=str(PORT),
                        SMB_TEST_MODE=mode,
                    )
                    try:
                        run([str(ROOT / "build/bin/response_mutation_client")], env=mutation_env)
                    finally:
                        proxy.join()
                    expected = (b"B" + b"A" * 63) if RESPONSE_MUTATIONS[mode] == 9 else b"A" * 64
                    if (share / "mutation-write.bin").read_bytes() != expected:
                        raise RuntimeError("unexpected remote WRITE effect after response mutation")
                    (share / "mutation-write.bin").unlink()
                for index, mode in enumerate(SECURITY_BUFFER_MUTATIONS, start=40):
                    proxy_port = PORT + index
                    proxy = AdversarialProxy(mode, proxy_port, PORT, user=USER, password=PASSWORD)
                    proxy.start()
                    security_env = env.copy()
                    security_env.update(
                        SMB_TEST_PORT=str(proxy_port),
                        SMB_TEST_BACKEND_PORT=str(PORT),
                        SMB_TEST_MODE=mode,
                    )
                    try:
                        run([str(ROOT / "build/bin/security_buffer_client")], env=security_env)
                    finally:
                        proxy.join()
            finally:
                try:
                    os.killpg(daemon.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                daemon.wait(timeout=10)
                daemon.stdin.close()
        finally:
            subprocess.run(["userdel", USER], check=False,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print(f"local Samba integration passed on 127.0.0.1:{PORT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
