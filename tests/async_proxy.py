#!/usr/bin/env python3
"""Deterministic SMB2.1 async-response proxy for local Samba tests."""

from __future__ import annotations

import hashlib
import hmac
import select
import socket
import struct
import threading
import time

from adversarial_proxy import recv_exact, session_key_from_type3

ASYNC_COMMANDS = {2, 4, 5, 6, 8, 9, 14, 17}
NEGATIVE_MODES = {
    "wrong-async-id",
    "wrong-message-id",
    "unsigned-final",
    "tampered-final",
    "malformed-pending",
    "repeat-pending",
    "disconnect-after-pending",
    "truncated-final",
}


def recv_frame(connection: socket.socket) -> tuple[bytes, bytes]:
    header = recv_exact(connection, 4)
    return header, recv_exact(connection, int.from_bytes(header[1:4], "big"))


def frame(payload: bytes) -> bytes:
    return b"\x00" + len(payload).to_bytes(3, "big") + payload


def sign(payload: bytearray, key: bytes) -> None:
    payload[48:64] = b"\x00" * 16
    payload[48:64] = hmac.new(key, payload, hashlib.sha256).digest()[:16]


def verify_signature(payload: bytes, key: bytes) -> None:
    if not struct.unpack_from("<I", payload, 16)[0] & 8:
        raise RuntimeError("backend final response was not signed")
    received = payload[48:64]
    unsigned = bytearray(payload)
    unsigned[48:64] = b"\x00" * 16
    expected = hmac.new(key, unsigned, hashlib.sha256).digest()[:16]
    if not hmac.compare_digest(received, expected):
        raise RuntimeError("backend final signature verification failed")


class AsyncProxy:
    def __init__(
        self, mode: str, listen_port: int, backend_port: int,
        user: str, password: str,
    ) -> None:
        self.mode = mode
        self.listen_port = listen_port
        self.backend_port = backend_port
        self.user = user
        self.password = password
        self.listener = socket.socket()
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(("127.0.0.1", listen_port))
        self.listener.listen(1)
        self.listener.settimeout(10)
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.failure: BaseException | None = None
        self.transformed: set[int] = set()

    def start(self) -> None:
        self.thread.start()

    def join(self) -> None:
        self.thread.join(timeout=15)
        self.listener.close()
        if self.thread.is_alive():
            raise RuntimeError(f"async proxy {self.mode} did not stop")
        if self.failure is not None:
            raise self.failure
        if self.mode == "async-success" and self.transformed != ASYNC_COMMANDS:
            missing = sorted(ASYNC_COMMANDS - self.transformed)
            raise RuntimeError(f"async proxy did not transform commands {missing}")

    def _pending(
        self, request: bytes, async_id: int, malformed: bool = False, credit: int = 1
    ) -> bytes:
        payload = bytearray(72)
        payload[:4] = b"\xfeSMB"
        payload[4:6] = struct.pack("<H", 64)
        payload[8:12] = struct.pack("<I", 0x103)
        payload[12:14] = request[12:14]
        payload[14:16] = struct.pack("<H", credit)
        payload[16:20] = struct.pack("<I", 3)
        payload[24:32] = request[24:32]
        payload[32:40] = struct.pack("<Q", 0 if malformed else async_id)
        payload[40:48] = request[40:48]
        payload[64:66] = struct.pack("<H", 9)
        payload[66] = 0
        payload[68:72] = struct.pack("<I", 1 if malformed else 0)
        return bytes(payload)

    def _async_final(
        self, original: bytes, key: bytes, async_id: int, mode: str | None = None
    ) -> bytes:
        verify_signature(original, key)
        payload = bytearray(original)
        payload[32:40] = struct.pack("<Q", async_id)
        struct.pack_into("<H", payload, 14, 0)
        flags = struct.unpack_from("<I", payload, 16)[0] | 3
        struct.pack_into("<I", payload, 16, flags)
        if mode == "wrong-async-id":
            payload[32:40] = struct.pack("<Q", async_id + 1)
        elif mode == "wrong-message-id":
            struct.pack_into("<Q", payload, 24, struct.unpack_from("<Q", payload, 24)[0] + 1)
        if mode == "unsigned-final":
            struct.pack_into("<I", payload, 16, flags & ~8)
            payload[48:64] = b"\x00" * 16
        else:
            sign(payload, key)
            if mode == "tampered-final":
                payload[48] ^= 1
        return bytes(payload)

    def _serve(self) -> None:
        try:
            client, _ = self.listener.accept()
            with client, socket.create_connection(
                ("127.0.0.1", self.backend_port), timeout=5
            ) as backend:
                client.settimeout(10)
                backend.settimeout(10)
                key: bytes | None = None
                serial = 1
                while True:
                    request_header, request = recv_frame(client)
                    if len(request) >= 64 and struct.unpack_from("<H", request, 12)[0] == 1:
                        key = session_key_from_type3(request, self.user, self.password) or key
                    command = struct.unpack_from("<H", request, 12)[0]
                    selected = (
                        command in ASYNC_COMMANDS
                        if self.mode == "async-success"
                        else command == 8
                    )
                    backend.sendall(request_header + request)
                    while True:
                        response_header, response = recv_frame(backend)
                        status = struct.unpack_from("<I", response, 8)[0]
                        if status == 0x103:
                            if selected:
                                continue
                            client.sendall(response_header + response)
                            continue
                        if not selected:
                            client.sendall(response_header + response)
                            break
                        if key is None:
                            raise RuntimeError("no signing key available for async transform")
                        async_id = 0xA500000000000000 | serial
                        serial += 1
                        if self.mode in NEGATIVE_MODES:
                            if command != 8:
                                client.sendall(response_header + response)
                                break
                            pending = self._pending(request, async_id)
                            if self.mode == "malformed-pending":
                                client.sendall(frame(self._pending(request, async_id, True)))
                                if client.recv(1) != b"":
                                    raise RuntimeError("client did not close after malformed pending")
                                return
                            if self.mode == "repeat-pending":
                                client.sendall(frame(pending))
                                deadline = time.monotonic() + 5
                                while time.monotonic() < deadline:
                                    readable, _, _ = select.select([client], [], [], 0.1)
                                    if readable:
                                        if client.recv(1) == b"":
                                            return
                                        raise RuntimeError("unexpected client data while pending")
                                    client.sendall(frame(
                                        self._pending(request, async_id, credit=0)
                                    ))
                                raise RuntimeError("client did not close after pending deadline")
                            client.sendall(frame(pending))
                            final = self._async_final(response, key, async_id, self.mode)
                            if self.mode in {"disconnect-after-pending", "truncated-final"}:
                                if self.mode == "truncated-final":
                                    client.sendall(frame(final)[:-1])
                                client.shutdown(socket.SHUT_WR)
                                if client.recv(1) != b"":
                                    raise RuntimeError("client sent data after async transport loss")
                                return
                            client.sendall(frame(final))
                            if client.recv(1) != b"":
                                raise RuntimeError("client did not close after invalid async final")
                            return
                        self.transformed.add(command)
                        client.sendall(frame(self._pending(request, async_id)))
                        client.sendall(frame(self._async_final(response, key, async_id)))
                        break
        except EOFError:
            if self.mode in NEGATIVE_MODES:
                self.failure = RuntimeError("client closed before async negative response")
        except OSError as error:
            self.failure = error
        except BaseException as error:
            self.failure = error
