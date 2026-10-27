#!/usr/bin/env python3
"""Exercise fragmented frames, receive recovery and send backpressure over TCP."""

from __future__ import annotations

import pathlib
import socket
import subprocess
import time


ROOT = pathlib.Path(__file__).resolve().parents[1]


def backpressure() -> None:
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


def recv_exact(peer: socket.socket, length: int) -> bytes:
    data = bytearray()
    while len(data) < length:
        chunk = peer.recv(length - len(data))
        if not chunk:
            raise RuntimeError("client closed before returning the complete echo")
        data.extend(chunk)
    return bytes(data)


def fragmented_echo(peer: socket.socket, length: int) -> None:
    payload = bytes(i % 256 for i in range(length))
    frame = b"\x00" + length.to_bytes(3, "big") + payload
    peer.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    offset = 0
    for count in (1, 2, 1, 3, 17, 29):
        peer.sendall(frame[offset : offset + count])
        offset += count
        time.sleep(0.01)
    peer.sendall(frame[offset:])
    if recv_exact(peer, len(frame)) != frame:
        raise RuntimeError("echo changed the frame header or payload bytes")
    if peer.recv(1) != b"":
        raise RuntimeError("unexpected bytes after complete echoed frame")


def receive_case(mode: str) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(2)
        listener.settimeout(5)
        with subprocess.Popen(
            [str(ROOT / "build/bin/transport_client"),
             str(listener.getsockname()[1]), mode],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        ) as client:
            try:
                peer, _ = listener.accept()
                with peer:
                    peer.settimeout(5)
                    if mode == "fragmented":
                        fragmented_echo(peer, 512)
                    else:
                        if mode == "eof-header":
                            peer.sendall(b"\x00\x00")
                            peer.shutdown(socket.SHUT_WR)
                        elif mode == "eof-payload":
                            peer.sendall(b"\x00\x00\x00\x40" + bytes(range(13)))
                            peer.shutdown(socket.SHUT_WR)
                        elif mode == "malformed-header":
                            peer.sendall(b"\x81\x00\x00\x40")
                        elif mode == "oversized-header":
                            peer.sendall(b"\x00\x10\x00\x01")
                        elif mode == "stalled-read":
                            # Keep the peer open: the client must enforce its deadline.
                            peer.sendall(b"\x00\x00")
                        else:
                            raise ValueError(mode)
                        if peer.recv(1) != b"":
                            raise RuntimeError("client sent data instead of closing failed receive")
                if mode != "fragmented":
                    recovered, _ = listener.accept()
                    with recovered:
                        recovered.settimeout(5)
                        fragmented_echo(recovered, 64)
                stdout, stderr = client.communicate(timeout=10)
                if client.returncode:
                    raise RuntimeError(f"{mode} failed:\n{stdout}{stderr}")
                expected = (
                    "fragmented receive and byte-exact echo passed"
                    if mode == "fragmented"
                    else f"receive failure and same-connection recovery passed: {mode}"
                )
                if expected not in stdout:
                    raise RuntimeError(f"{mode} did not reach its assertions")
                print(stdout, end="")
            finally:
                if client.poll() is None:
                    client.kill()
                    client.communicate()


def main() -> None:
    backpressure()
    for mode in (
        "fragmented", "eof-header", "eof-payload", "malformed-header",
        "oversized-header", "stalled-read",
    ):
        receive_case(mode)


if __name__ == "__main__":
    main()
