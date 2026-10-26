#!/usr/bin/env python3
"""Local TCP proxy and hostile first-response server for Samba tests."""

from __future__ import annotations

import socket
import struct
import threading
import time


def recv_exact(connection: socket.socket, length: int) -> bytes:
    result = bytearray()
    while len(result) < length:
        chunk = connection.recv(length - len(result))
        if not chunk:
            raise EOFError("peer closed while reading a framed packet")
        result.extend(chunk)
    return bytes(result)


class AdversarialProxy:
    def __init__(
        self,
        mode: str,
        listen_port: int,
        backend_port: int,
    ) -> None:
        self.mode = mode
        self.listen_port = listen_port
        self.backend_port = backend_port
        self.listener = socket.socket()
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(("127.0.0.1", listen_port))
        self.listener.listen(1)
        self.listener.settimeout(10)
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.failure: BaseException | None = None

    def start(self) -> None:
        self.thread.start()

    def join(self) -> None:
        self.thread.join(timeout=12)
        self.listener.close()
        if self.thread.is_alive():
            raise RuntimeError(f"proxy {self.mode} did not stop")
        if self.failure is not None:
            raise self.failure

    def _serve(self) -> None:
        try:
            client, _ = self.listener.accept()
            with client:
                if self.mode in {
                    "truncated",
                    "oversized",
                    "wrong-correlation-negotiate",
                    "dribble-timeout",
                }:
                    self._early_response(client)
                else:
                    self._relay_and_mutate(client)
        except BaseException as error:
            self.failure = error

    def _early_response(self, client: socket.socket) -> None:
        header = recv_exact(client, 4)
        length = int.from_bytes(header[1:4], "big")
        recv_exact(client, length)
        if self.mode == "truncated":
            client.sendall(b"\x00\x00\x00\x40" + b"\xfeSMB" + b"\x00" * 16)
        elif self.mode == "oversized":
            client.sendall(b"\x00\x10\x00\x01")
        elif self.mode == "dribble-timeout":
            client.sendall(b"\x00\x00\x00\x40\xfe")
            time.sleep(2.5)
        else:
            packet = bytearray(64)
            packet[0:4] = b"\xfeSMB"
            struct.pack_into("<H", packet, 4, 64)
            struct.pack_into("<H", packet, 6, 1)
            struct.pack_into("<H", packet, 12, 0)
            struct.pack_into("<H", packet, 14, 1)
            struct.pack_into("<I", packet, 16, 1)
            struct.pack_into("<Q", packet, 24, 1)
            client.sendall(b"\x00\x00\x00\x40" + packet)

    def _relay_and_mutate(self, client: socket.socket) -> None:
        backend = socket.create_connection(("127.0.0.1", self.backend_port), timeout=5)
        backend.settimeout(10)
        client.settimeout(10)
        with backend:
            done = threading.Event()
            relay_error: list[BaseException] = []
            mutated = False

            def client_to_server() -> None:
                try:
                    while not done.is_set():
                        header = recv_exact(client, 4)
                        payload = recv_exact(client, int.from_bytes(header[1:4], "big"))
                        backend.sendall(header + payload)
                except (EOFError, OSError) as error:
                    relay_error.append(error)
                    done.set()

            upstream = threading.Thread(target=client_to_server, daemon=True)
            upstream.start()
            try:
                while not done.is_set():
                    header = recv_exact(backend, 4)
                    payload = bytearray(
                        recv_exact(backend, int.from_bytes(header[1:4], "big"))
                    )
                    if len(payload) >= 64 and payload[12:14] == b"\x03\x00":
                        if self.mode == "unsigned":
                            flags = struct.unpack_from("<I", payload, 16)[0]
                            struct.pack_into("<I", payload, 16, flags & ~8)
                            payload[48:64] = b"\x00" * 16
                        elif self.mode == "tampered-signature":
                            payload[48] ^= 1
                        elif self.mode == "wrong-correlation-auth":
                            message_id = struct.unpack_from("<Q", payload, 24)[0]
                            struct.pack_into("<Q", payload, 24, message_id + 1)
                        else:
                            raise ValueError(f"unknown adversarial mode {self.mode}")
                        client.sendall(header + payload)
                        mutated = True
                        done.set()
                        break
                    client.sendall(header + payload)
            except (EOFError, OSError) as error:
                relay_error.append(error)
                done.set()
            finally:
                done.set()
                for connection in (client, backend):
                    try:
                        connection.shutdown(socket.SHUT_RDWR)
                    except OSError:
                        pass
                upstream.join(timeout=1)
            if upstream.is_alive():
                raise RuntimeError("upstream relay did not stop")
            if not mutated:
                if relay_error:
                    raise relay_error[0]
                raise RuntimeError(f"proxy {self.mode} did not inject its fault")
