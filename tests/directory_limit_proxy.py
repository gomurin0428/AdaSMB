#!/usr/bin/env python3
"""Signed directory-limit fixtures over a real local SMB connection."""

from __future__ import annotations

import socket
import struct

from adversarial_proxy import session_key_from_type3
from async_proxy import AsyncProxy, frame, recv_frame, sign, verify_signature

MODES = (
    "directory-page-boundary", "directory-page-overflow",
    "directory-entry-boundary", "directory-entry-overflow",
)
PAGE_LIMIT = 4096
ENTRY_LIMIT = 100000
ENTRIES_PER_PAGE = 512
NO_MORE_FILES = 0x80000006


def directory_page(count: int, witness: bool) -> bytes:
    if not 1 <= count <= ENTRIES_PER_PAGE:
        raise ValueError("invalid fixture entry count")
    data = bytearray(count * 128)
    for index in range(count):
        offset = index * 128
        name = ("fixture.txt" if witness and index == 0 else ".").encode("utf-16le")
        struct.pack_into("<I", data, offset, 128 if index + 1 < count else 0)
        struct.pack_into("<I", data, offset + 56, 0x20 if len(name) > 2 else 0x10)
        struct.pack_into("<I", data, offset + 60, len(name))
        data[offset + 104:offset + 104 + len(name)] = name
    return bytes(data)


class DirectoryLimitProxy(AsyncProxy):
    def __init__(self, mode: str, listen_port: int, backend_port: int,
                 user: str, password: str) -> None:
        if mode not in MODES:
            raise ValueError("unknown directory-limit mode")
        super().__init__(mode, listen_port, backend_port, user, password)
        self.page_mode = mode.startswith("directory-page-")
        self.overflow = mode.endswith("-overflow")
        self.expected_queries = (PAGE_LIMIT if self.page_mode else
                                 (ENTRY_LIMIT // ENTRIES_PER_PAGE +
                                  (1 if self.overflow else 2)))
        self.queries = 0
        self.entries = 0
        self.finished = False

    def join(self) -> None:
        super().join()
        if self.queries != self.expected_queries or not self.finished:
            raise RuntimeError(
                f"{self.mode}: incomplete boundary trace; queries={self.queries}, "
                f"expected={self.expected_queries}, finished={self.finished}"
            )

    def _response(self, original: bytes, request: bytes, key: bytes) -> bytes:
        end = not self.overflow and (
            self.queries == PAGE_LIMIT if self.page_mode else self.entries == ENTRY_LIMIT
        )
        payload = bytearray(original[:64]) + bytearray(8)
        struct.pack_into("<I", payload, 8, NO_MORE_FILES if end else 0)
        struct.pack_into("<H", payload, 14, 1)
        struct.pack_into("<I", payload, 16, 9)
        payload[24:48] = request[24:48]
        struct.pack_into("<H", payload, 64, 9)
        if end:
            self.finished = True
        else:
            count = (1 if self.page_mode else min(
                ENTRIES_PER_PAGE, ENTRY_LIMIT + int(self.overflow) - self.entries
            ))
            data = directory_page(count, self.queries == 1)
            self.entries += count
            struct.pack_into("<HI", payload, 66, 72, len(data))
            payload.extend(data)
        sign(payload, key)
        return frame(payload)

    def _serve(self) -> None:
        try:
            client, _ = self.listener.accept()
            with client, socket.create_connection(
                ("127.0.0.1", self.backend_port), timeout=5
            ) as backend:
                client.settimeout(10)
                backend.settimeout(10)
                key: bytes | None = None
                while True:
                    request_header, request = recv_frame(client)
                    command = struct.unpack_from("<H", request, 12)[0]
                    if command == 1:
                        key = session_key_from_type3(request, self.user, self.password) or key
                    if command == 14:
                        self.queries += 1
                        if self.queries > self.expected_queries:
                            raise RuntimeError("extra QUERY_DIRECTORY after limit fixture")
                    backend.sendall(request_header + request)
                    while True:
                        response_header, response = recv_frame(backend)
                        status = struct.unpack_from("<I", response, 8)[0]
                        if status == 0x103:
                            if command != 14:
                                client.sendall(response_header + response)
                            continue
                        if command != 14:
                            client.sendall(response_header + response)
                            break
                        if key is None or status not in (0, NO_MORE_FILES):
                            raise RuntimeError("unexpected backend directory response")
                        verify_signature(response, key)
                        if self.queries == 1 and (
                            status != 0 or len(response) < 72
                            or struct.unpack_from("<I", response, 68)[0] == 0
                        ):
                            raise RuntimeError("first backend directory page had no data")
                        client.sendall(self._response(response, request, key))
                        if self.overflow and self.queries == self.expected_queries:
                            if client.recv(1) != b"":
                                raise RuntimeError("client sent data after directory limit")
                            self.finished = True
                            return
                        break
        except EOFError:
            if self.overflow or not self.finished:
                self.failure = RuntimeError("client closed before directory boundary")
        except BaseException as error:
            self.failure = error
