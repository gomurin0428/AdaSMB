#!/usr/bin/env python3
"""Local TCP proxy and hostile first-response server for Samba tests."""

from __future__ import annotations

import hashlib
import hmac
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


def md4(data: bytes) -> bytes:
    message = bytearray(data)
    bit_length = len(message) * 8
    message.append(0x80)
    message.extend(b"\x00" * ((56 - len(message) % 64) % 64))
    message.extend(struct.pack("<Q", bit_length))
    a, b, c, d = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476
    mask = 0xFFFFFFFF

    def rotate(value: int, amount: int) -> int:
        return ((value << amount) | (value >> (32 - amount))) & mask

    for offset in range(0, len(message), 64):
        words = struct.unpack_from("<16I", message, offset)
        aa, bb, cc, dd = a, b, c, d
        for index in range(16):
            value = (a + ((b & c) | (~b & d)) + words[index]) & mask
            a, d, c, b = d, c, b, rotate(value, (3, 7, 11, 19)[index % 4])
        order = (0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15)
        for index, word_index in enumerate(order):
            value = (
                a
                + ((b & c) | (b & d) | (c & d))
                + words[word_index]
                + 0x5A827999
            ) & mask
            a, d, c, b = d, c, b, rotate(value, (3, 5, 9, 13)[index % 4])
        order = (0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15)
        for index, word_index in enumerate(order):
            value = (a + (b ^ c ^ d) + words[word_index] + 0x6ED9EBA1) & mask
            a, d, c, b = d, c, b, rotate(value, (3, 9, 11, 15)[index % 4])
        a = (a + aa) & mask
        b = (b + bb) & mask
        c = (c + cc) & mask
        d = (d + dd) & mask
    return struct.pack("<4I", a, b, c, d)


def session_key_from_type3(packet: bytes, user: str, password: str) -> bytes | None:
    marker = b"NTLMSSP\x00\x03\x00\x00\x00"
    start = packet.find(marker)
    if start < 0 or len(packet) - start < 88:
        return None
    token = packet[start:]
    nt_length, _, nt_offset = struct.unpack_from("<HHI", token, 20)
    user_length, _, user_offset = struct.unpack_from("<HHI", token, 36)
    domain_length, _, domain_offset = struct.unpack_from("<HHI", token, 28)
    if (
        nt_length < 16
        or nt_offset > len(token)
        or nt_length > len(token) - nt_offset
        or user_offset > len(token)
        or user_length > len(token) - user_offset
        or domain_offset > len(token)
        or domain_length > len(token) - domain_offset
    ):
        return None
    wire_user = token[user_offset : user_offset + user_length].decode("utf-16le")
    wire_domain = token[domain_offset : domain_offset + domain_length].decode(
        "utf-16le"
    )
    identity = (wire_user.upper() + wire_domain).encode("utf-16le")
    response_key = hmac.new(
        md4(password.encode("utf-16le")), identity, hashlib.md5
    ).digest()
    proof = token[nt_offset : nt_offset + 16]
    return hmac.new(response_key, proof, hashlib.md5).digest()


class AdversarialProxy:
    def __init__(
        self,
        mode: str,
        listen_port: int,
        backend_port: int,
        user: str = "",
        password: str = "",
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
            session_key: bytes | None = None
            read_responses = 0
            write_requests = 0
            write_responses = 0
            query_requests = 0
            query_responses = 0
            set_info_requests = 0
            first_query_had_data = False

            def client_to_server() -> None:
                nonlocal session_key, write_requests, query_requests
                nonlocal set_info_requests
                try:
                    while not done.is_set():
                        header = recv_exact(client, 4)
                        payload = recv_exact(client, int.from_bytes(header[1:4], "big"))
                        if len(payload) >= 64 and payload[12:14] == b"\x09\x00":
                            write_requests += 1
                        if len(payload) >= 64 and payload[12:14] == b"\x0e\x00":
                            query_requests += 1
                            if (
                                self.mode
                                == "malformed-signed-directory-second-page"
                                and query_requests > 2
                            ):
                                relay_error.append(
                                    RuntimeError(
                                        "unexpected extra QUERY_DIRECTORY request"
                                    )
                                )
                                done.set()
                                return
                        if len(payload) >= 64 and payload[12:14] == b"\x11\x00":
                            set_info_requests += 1
                            if (
                                self.mode == "malformed-signed-set-info"
                                and set_info_requests > 1
                            ):
                                relay_error.append(
                                    RuntimeError("unexpected extra SET_INFO request")
                                )
                                done.set()
                                return
                        if self.mode in {
                            "malformed-signed-create",
                            "malformed-signed-directory-second-page",
                            "malformed-signed-set-info",
                        }:
                            session_key = (
                                session_key_from_type3(
                                    payload, self.user, self.password
                                )
                                or session_key
                            )
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
                    if len(payload) >= 64 and (
                        payload[12:14] == b"\x03\x00"
                        or (
                            self.mode == "malformed-signed-create"
                            and payload[12:14] == b"\x05\x00"
                        )
                        or (
                            self.mode == "interrupted-read-after-progress"
                            and payload[12:14] == b"\x08\x00"
                        )
                        or (
                            self.mode == "lost-write-response-after-progress"
                            and payload[12:14] == b"\x09\x00"
                        )
                        or (
                            self.mode == "malformed-signed-directory-second-page"
                            and payload[12:14] == b"\x0e\x00"
                        )
                        or (
                            self.mode == "malformed-signed-set-info"
                            and payload[12:14] == b"\x11\x00"
                        )
                    ):
                        if self.mode == "lost-write-response-after-progress":
                            if payload[12:14] != b"\x09\x00":
                                client.sendall(header + payload)
                                continue
                            write_responses += 1
                            if len(payload) < 72:
                                raise RuntimeError("short WRITE response")
                            status = struct.unpack_from("<I", payload, 8)[0]
                            count = struct.unpack_from("<I", payload, 68)[0]
                            if status != 0 or count == 0:
                                raise RuntimeError(
                                    "WRITE response was not successful with progress"
                                )
                            if write_responses == 1:
                                client.sendall(header + payload)
                                continue
                            if write_responses != 2:
                                raise RuntimeError("unexpected extra WRITE response")
                            mutated = True
                            done.set()
                            break
                        elif self.mode == "interrupted-read-after-progress":
                            if payload[12:14] != b"\x08\x00":
                                client.sendall(header + payload)
                                continue
                            read_responses += 1
                            count = struct.unpack_from("<I", payload, 68)[0]
                            if read_responses == 1:
                                if count == 0:
                                    status = struct.unpack_from("<I", payload, 8)[0]
                                    raise RuntimeError(
                                        "first READ response made no progress "
                                        f"(status=0x{status:08x})"
                                    )
                                client.sendall(header + payload)
                                continue
                            if read_responses != 2:
                                raise RuntimeError("unexpected extra READ response")
                            if count == 0:
                                raise RuntimeError(
                                    "second READ response unexpectedly made no progress"
                                )
                            payload[48] ^= 1
                        elif self.mode == "malformed-signed-create":
                            if payload[12:14] != b"\x05\x00":
                                client.sendall(header + payload)
                                continue
                            if session_key is None:
                                raise RuntimeError("could not derive SMB signing key")
                            if struct.unpack_from("<I", payload, 16)[0] & 8 == 0:
                                raise RuntimeError("server CREATE response was unsigned")
                            original_signature = bytes(payload[48:64])
                            signed_payload = bytearray(payload)
                            signed_payload[48:64] = b"\x00" * 16
                            expected_signature = hmac.new(
                                session_key, signed_payload, hashlib.sha256
                            ).digest()[:16]
                            if not hmac.compare_digest(
                                original_signature, expected_signature
                            ):
                                raise RuntimeError(
                                    "derived key did not validate server CREATE signature"
                                )
                            payload[66] = 1
                            payload[48:64] = b"\x00" * 16
                            payload[48:64] = hmac.new(
                                session_key, payload, hashlib.sha256
                            ).digest()[:16]
                        elif self.mode == "malformed-signed-directory-second-page":
                            if payload[12:14] != b"\x0e\x00":
                                client.sendall(header + payload)
                                continue
                            query_responses += 1
                            status = struct.unpack_from("<I", payload, 8)[0]
                            data_offset = struct.unpack_from("<H", payload, 66)[0]
                            data_length = struct.unpack_from("<I", payload, 68)[0]
                            if status != 0 or data_length == 0:
                                raise RuntimeError(
                                    "directory response did not contain successful data"
                                )
                            if query_responses == 1:
                                first_query_had_data = True
                                client.sendall(header + payload)
                                continue
                            if query_responses != 2:
                                raise RuntimeError(
                                    "unexpected extra QUERY_DIRECTORY response"
                                )
                            if session_key is None:
                                raise RuntimeError("could not derive SMB signing key")
                            if struct.unpack_from("<I", payload, 16)[0] & 8 == 0:
                                raise RuntimeError(
                                    "server QUERY_DIRECTORY response was unsigned"
                                )
                            if (
                                data_offset < 72
                                or data_offset > len(payload)
                                or data_length > len(payload) - data_offset
                                or data_length < 104
                            ):
                                raise RuntimeError(
                                    "second directory page has invalid data bounds"
                                )
                            original_signature = bytes(payload[48:64])
                            signed_payload = bytearray(payload)
                            signed_payload[48:64] = b"\x00" * 16
                            expected_signature = hmac.new(
                                session_key, signed_payload, hashlib.sha256
                            ).digest()[:16]
                            if not hmac.compare_digest(
                                original_signature, expected_signature
                            ):
                                raise RuntimeError(
                                    "derived key did not validate QUERY_DIRECTORY signature"
                                )
                            struct.pack_into("<I", payload, data_offset, 1)
                            payload[48:64] = b"\x00" * 16
                            payload[48:64] = hmac.new(
                                session_key, payload, hashlib.sha256
                            ).digest()[:16]
                            client.sendall(header + payload)
                            mutated = True
                            if (
                                self.mode
                                == "malformed-signed-directory-second-page"
                            ):
                                upstream.join(timeout=11)
                                if upstream.is_alive():
                                    raise RuntimeError(
                                        "client did not close after malformed "
                                        "directory response"
                                    )
                                if (
                                    not relay_error
                                    or not isinstance(relay_error[0], EOFError)
                                ):
                                    raise RuntimeError(
                                        "upstream did not exit because the client "
                                        f"closed: {relay_error!r}"
                                    )
                                break
                            done.set()
                            break
                        elif self.mode == "malformed-signed-set-info":
                            if payload[12:14] != b"\x11\x00":
                                client.sendall(header + payload)
                                continue
                            if session_key is None:
                                raise RuntimeError("could not derive SMB signing key")
                            if struct.unpack_from("<I", payload, 16)[0] & 8 == 0:
                                raise RuntimeError("server SET_INFO response was unsigned")
                            if struct.unpack_from("<H", payload, 64)[0] != 2:
                                raise RuntimeError("unexpected SET_INFO structure size")
                            original_signature = bytes(payload[48:64])
                            signed_payload = bytearray(payload)
                            signed_payload[48:64] = b"\x00" * 16
                            expected_signature = hmac.new(
                                session_key, signed_payload, hashlib.sha256
                            ).digest()[:16]
                            if not hmac.compare_digest(
                                original_signature, expected_signature
                            ):
                                raise RuntimeError(
                                    "derived key did not validate SET_INFO signature"
                                )
                            struct.pack_into("<H", payload, 64, 3)
                            payload[48:64] = b"\x00" * 16
                            payload[48:64] = hmac.new(
                                session_key, payload, hashlib.sha256
                            ).digest()[:16]
                            client.sendall(header + payload)
                            mutated = True
                            upstream.join(timeout=11)
                            if upstream.is_alive():
                                raise RuntimeError(
                                    "client did not close after malformed SET_INFO"
                                )
                            if not relay_error or not isinstance(
                                relay_error[0], EOFError
                            ):
                                raise RuntimeError(
                                    "upstream did not exit because the client "
                                    f"closed: {relay_error!r}"
                                )
                            break
                        elif self.mode == "unsigned":
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
                    connection.close()
                upstream.join(timeout=1)
            if upstream.is_alive():
                raise RuntimeError("upstream relay did not stop")
            if not mutated:
                if relay_error:
                    if self.mode == "lost-write-response-after-progress":
                        raise RuntimeError(
                            "lost-WRITE injection did not complete "
                            f"(requests={write_requests}, "
                            f"responses={write_responses}): {relay_error[0]}"
                        )
                    raise relay_error[0]
                raise RuntimeError(f"proxy {self.mode} did not inject its fault")
            if self.mode == "lost-write-response-after-progress":
                if write_responses != 2:
                    raise RuntimeError(
                        f"expected two successful WRITE responses, got {write_responses}"
                    )
                if write_requests != 2:
                    raise RuntimeError(
                        f"expected two client WRITE requests, got {write_requests}"
                    )
            if self.mode == "malformed-signed-directory-second-page":
                if not relay_error or not isinstance(relay_error[0], EOFError):
                    raise RuntimeError(
                        "directory client connection did not close after mutation"
                    )
                if not first_query_had_data:
                    raise RuntimeError("first directory response had no data")
                if query_requests != 2 or query_responses != 2:
                    raise RuntimeError(
                        "expected exactly two QUERY_DIRECTORY request/response pairs "
                        f"(requests={query_requests}, responses={query_responses})"
                    )
            if self.mode == "malformed-signed-set-info":
                if set_info_requests != 1:
                    raise RuntimeError(
                        f"expected exactly one SET_INFO request, got {set_info_requests}"
                    )
                if not relay_error or not isinstance(relay_error[0], EOFError):
                    raise RuntimeError(
                        "SET_INFO client connection did not close after mutation"
                    )
