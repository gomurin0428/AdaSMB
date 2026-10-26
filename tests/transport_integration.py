#!/usr/bin/env python3
"""Exercise a real zero-reader TCP peer without Samba or elevated privileges."""

from __future__ import annotations

import pathlib
import socket
import subprocess


ROOT = pathlib.Path(__file__).resolve().parents[1]


def main() -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        # Set before listen so the accepted connection inherits a small window.
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        listener.settimeout(5)
        with subprocess.Popen(
            [str(ROOT / "build/bin/transport_client"), str(listener.getsockname()[1])],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        ) as client:
            try:
                peer, _ = listener.accept()
                # Keep the peer alive, never recv(): only backpressure, not EOF,
                # can stop the sender. The watchdog makes a blocking send fail.
                with peer:
                    stdout, stderr = client.communicate(timeout=10)
                    if client.returncode:
                        raise RuntimeError(f"transport test failed:\n{stdout}{stderr}")
                    if "stalled write deadline and invalidation passed" not in stdout:
                        raise RuntimeError("transport client did not reach its assertions")
                    print(stdout, end="")
            finally:
                if client.poll() is None:
                    client.kill()
                    client.communicate()


if __name__ == "__main__":
    main()
