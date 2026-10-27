#!/usr/bin/env python3
"""Local TCP proxy and hostile first-response server for Samba tests."""

from __future__ import annotations

import hashlib
import hmac
import socket
import struct
import threading
import time

DIRECTORY_MODES = (
    "malformed-signed-directory-second-page",
    "dangling-signed-directory-second-page",
)

RESPONSE_MUTATIONS = {
    "signed-read-offset": 8,
    "signed-read-length": 8,
    "signed-read-over-request": 8,
    "signed-read-truncated": 8,
    "signed-write-zero": 9,
    "signed-write-over-request": 9,
    "signed-write-structure": 9,
    "signed-write-truncated": 9,
    "header-message-id": 8,
    "header-command": 8,
    "header-tree-id": 8,
    "header-session-id": 8,
    "header-async": 8,
    "header-compound": 8,
}

# Command, NTSTATUS, buffer-offset field, fixed-body end, signed response.
SECURITY_BUFFER_MUTATIONS = {
    "negotiate-buffer-offset": (0, 0, 120, 128, False),
    "negotiate-buffer-length": (0, 0, 120, 128, False),
    "challenge-buffer-offset": (1, 0xC0000016, 68, 72, False),
    "challenge-buffer-length": (1, 0xC0000016, 68, 72, False),
    "challenge-ntlm-signature": (1, 0xC0000016, 68, 72, False),
    "challenge-ntlm-type": (1, 0xC0000016, 68, 72, False),
    "final-buffer-offset": (1, 0, 68, 72, True),
    "final-buffer-length": (1, 0, 68, 72, True),
    "final-spnego-mic": (1, 0, 68, 72, True),
    "final-spnego-state": (1, 0, 68, 72, True),
    "final-spnego-duplicate-state": (1, 0, 68, 72, True),
    "final-spnego-missing-mic": (1, 0, 68, 72, True),
}


def _mutate_final_spnego(token: bytes, session_key: bytes, mode: str) -> bytes:
    magic = b"session key to server-to-client signing key magic constant\x00"
    signing_key = hashlib.md5(session_key + magic).digest()
    mechanism_list = bytes.fromhex("300c060a2b06010401823702020a")
    checksum = hmac.new(signing_key, b"\x00" * 4 + mechanism_list, hashlib.md5).digest()[:8]
    mic = b"\x01\x00\x00\x00" + checksum + b"\x00" * 4
    state = bytes.fromhex("a0030a0100")
    mic_field = b"\xa3\x12\x04\x10" + mic

    def wrap(fields: bytes) -> bytes:
        return bytes((0xA1, len(fields) + 2, 0x30, len(fields))) + fields

    valid_tokens = {
        wrap(state + mechanism + response + mic_field)
        for mechanism in (b"", bytes.fromhex("a10c060a2b06010401823702020a"))
        for response in (b"", bytes.fromhex("a2020400"))
    }
    if token not in valid_tokens:
        raise RuntimeError("original final SPNEGO token did not match verified mechanism MIC")
    if mode == "final-spnego-mic":
        return wrap(state + mic_field[:-1] + bytes((mic_field[-1] ^ 1,)))
    if mode == "final-spnego-state":
        return wrap(state[:-1] + b"\x01" + mic_field)
    if mode == "final-spnego-duplicate-state":
        return wrap(state + state + mic_field)
    if mode == "final-spnego-missing-mic":
        return wrap(state)
    raise RuntimeError("unknown final SPNEGO mutation")


def _validate_negotiate_response(payload: bytes | bytearray) -> None:
    if (
        len(payload) < 128
        or struct.unpack_from("<H", payload, 64)[0] != 65
        or not struct.unpack_from("<H", payload, 66)[0] & 1
        or struct.unpack_from("<H", payload, 68)[0] != 0x0210
        or not any(payload[72:88])
        or any(size == 0 for size in struct.unpack_from("<III", payload, 92))
        or bool(struct.unpack_from("<I", payload, 16)[0] & 8)
        or any(payload[48:64])
    ):
        raise RuntimeError("unexpected original NEGOTIATE profile")
    offset, length = struct.unpack_from("<HH", payload, 120)
    if not length or offset < 128 or offset + length > len(payload):
        raise RuntimeError("expected a valid original NEGOTIATE security buffer")


def _validate_session_challenge(payload: bytes | bytearray) -> int:
    if (
        len(payload) < 72
        or struct.unpack_from("<H", payload, 64)[0] != 9
        or struct.unpack_from("<H", payload, 66)[0] != 0
        or bool(struct.unpack_from("<I", payload, 16)[0] & 8)
        or any(payload[48:64])
    ):
        raise RuntimeError("unexpected original SESSION_SETUP challenge")
    session_id = struct.unpack_from("<Q", payload, 40)[0]
    offset, length = struct.unpack_from("<HH", payload, 68)
    if session_id == 0 or not length or offset < 72 or offset + length > len(payload):
        raise RuntimeError("invalid original SESSION_SETUP challenge fields")
    return session_id


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
            error_responses = 0
            teardown_responses: list[int] = []
            connection_responses: list[int] = []
            completed_logoff = False
            write_requests = 0
            write_responses = 0
            query_requests = 0
            query_responses = 0
            set_info_requests = 0
            tree_disconnect_requests = 0
            logoff_requests = 0
            first_query_had_data = False
            mutation_requests = 0
            challenge_session_id: int | None = None

            def client_to_server() -> None:
                nonlocal session_key, write_requests, query_requests
                nonlocal set_info_requests
                nonlocal tree_disconnect_requests, logoff_requests
                nonlocal mutation_requests
                try:
                    while not done.is_set():
                        header = recv_exact(client, 4)
                        payload = recv_exact(client, int.from_bytes(header[1:4], "big"))
                        if self.mode in RESPONSE_MUTATIONS:
                            if mutated:
                                raise RuntimeError("client sent a request after rejected response")
                            if struct.unpack_from("<H", payload, 12)[0] == RESPONSE_MUTATIONS[self.mode]:
                                mutation_requests += 1
                        if self.mode in SECURITY_BUFFER_MUTATIONS:
                            if mutated:
                                raise RuntimeError("client continued after invalid security buffer")
                            if struct.unpack_from("<H", payload, 12)[0] == SECURITY_BUFFER_MUTATIONS[self.mode][0]:
                                mutation_requests += 1
                        if len(payload) >= 64 and payload[12:14] == b"\x04\x00":
                            tree_disconnect_requests += 1
                        if len(payload) >= 64 and payload[12:14] == b"\x02\x00":
                            logoff_requests += 1
                        if self.mode == "malformed-signed-tree-disconnect" and mutated:
                            relay_error.append(RuntimeError(
                                "unexpected client request after malformed TREE_DISCONNECT"
                            ))
                            done.set()
                            return
                        if len(payload) >= 64 and payload[12:14] == b"\x09\x00":
                            write_requests += 1
                        if len(payload) >= 64 and payload[12:14] == b"\x0e\x00":
                            query_requests += 1
                            if (
                                self.mode in DIRECTORY_MODES
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
                        if self.mode in RESPONSE_MUTATIONS or self.mode in SECURITY_BUFFER_MUTATIONS or self.mode in {
                            "malformed-signed-create",
                            "malformed-signed-directory-second-page",
                            "dangling-signed-directory-second-page",
                            "read-reserved-fields",
                            "error-reserved-field",
                            "teardown-reserved-fields",
                            "connection-reserved-fields",
                            "malformed-signed-set-info",
                            "malformed-signed-tree-disconnect",
                        }:
                            session_key = (
                                session_key_from_type3(
                                    payload, self.user, self.password
                                )
                                or session_key
                            )
                        backend.sendall(header + payload)
                except (EOFError, OSError, RuntimeError) as error:
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
                    if self.mode in SECURITY_BUFFER_MUTATIONS:
                        response_command = struct.unpack_from("<H", payload, 12)[0]
                        response_status = struct.unpack_from("<I", payload, 8)[0]
                        if response_command == 0:
                            if response_status != 0:
                                raise RuntimeError("original NEGOTIATE did not succeed")
                            _validate_negotiate_response(payload)
                        elif response_command == 1:
                            if response_status == 0xC0000016:
                                challenge_session_id = _validate_session_challenge(payload)
                            elif response_status != 0:
                                raise RuntimeError("unexpected original SESSION_SETUP status")
                        command, nt_status, field, fixed_end, signed = SECURITY_BUFFER_MUTATIONS[self.mode]
                        if (
                            response_command != command
                            or response_status != nt_status
                        ):
                            client.sendall(header + payload)
                            continue
                        if (
                            len(payload) < fixed_end
                            or struct.unpack_from("<H", payload, 64)[0] != fixed_end - 63
                            or bool(struct.unpack_from("<I", payload, 16)[0] & 8) != signed
                        ):
                            raise RuntimeError("unexpected original security-buffer response")
                        offset, length = struct.unpack_from("<HH", payload, field)
                        if not length or offset < fixed_end or offset + length > len(payload):
                            raise RuntimeError("expected nonempty valid original security buffer")
                        if command == 1:
                            session_id = struct.unpack_from("<Q", payload, 40)[0]
                            if (
                                session_id == 0
                                or (nt_status == 0 and session_id != challenge_session_id)
                            ):
                                raise RuntimeError("unexpected original SESSION_SETUP SessionId")
                        if signed:
                            if session_key is None:
                                raise RuntimeError("missing authentication signing key")
                            signature = bytes(payload[48:64])
                            payload[48:64] = b"\x00" * 16
                            if not hmac.compare_digest(
                                signature, hmac.new(session_key, payload, hashlib.sha256).digest()[:16]
                            ):
                                raise RuntimeError("invalid original authentication signature")
                        elif any(payload[48:64]):
                            raise RuntimeError("unexpected unsigned authentication signature bytes")
                        if self.mode.startswith("final-spnego-"):
                            token = _mutate_final_spnego(
                                bytes(payload[offset:offset + length]), session_key, self.mode
                            )
                            payload = payload[:offset] + token + payload[offset + length:]
                            struct.pack_into("<H", payload, field + 2, len(token))
                        elif self.mode.startswith("challenge-ntlm-"):
                            token = bytes(payload[offset:offset + length])
                            marker = b"NTLMSSP\x00\x02\x00\x00\x00"
                            if token.count(marker) != 1:
                                raise RuntimeError("expected a single original NTLM Type 2 message")
                            start = token.index(marker)
                            if len(token) - start < 48:
                                raise RuntimeError("original NTLM challenge is too short")
                            field_offset = 8 if self.mode == "challenge-ntlm-type" else 0
                            payload[offset + start + field_offset] ^= 1
                        elif self.mode.endswith("-offset"):
                            struct.pack_into("<HH", payload, field, fixed_end - 1, 1)
                        else:
                            struct.pack_into("<HH", payload, field, fixed_end, 0xFFFF)
                        if signed:
                            payload[48:64] = hmac.new(session_key, payload, hashlib.sha256).digest()[:16]
                        mutated = True
                        client.sendall(b"\x00" + len(payload).to_bytes(3, "big") + payload)
                        upstream.join(timeout=11)
                        if (
                            upstream.is_alive()
                            or not relay_error
                            or not isinstance(relay_error[0], EOFError)
                            or mutation_requests != (2 if signed else 1)
                        ):
                            raise RuntimeError("client did not stop at malformed security buffer")
                        break
                    if (
                        self.mode in RESPONSE_MUTATIONS
                        and struct.unpack_from("<H", payload, 12)[0] == RESPONSE_MUTATIONS[self.mode]
                    ):
                        if (
                            len(payload) < 80
                            or struct.unpack_from("<I", payload, 8)[0] != 0
                            or struct.unpack_from("<H", payload, 64)[0] != 17
                            or struct.unpack_from("<I", payload, 68)[0] != 1
                            or struct.unpack_from("<I", payload, 16)[0] & 8 == 0
                            or session_key is None
                        ):
                            raise RuntimeError("expected signed one-byte IO success")
                        original_signature = bytes(payload[48:64])
                        payload[48:64] = b"\x00" * 16
                        if not hmac.compare_digest(
                            original_signature,
                            hmac.new(session_key, payload, hashlib.sha256).digest()[:16],
                        ):
                            raise RuntimeError("derived key did not validate IO signature")
                        if self.mode == "signed-read-offset":
                            payload[66] = 64
                        elif self.mode == "signed-read-length":
                            struct.pack_into("<I", payload, 68, 0xFFFFFFFF)
                        elif self.mode == "signed-read-over-request":
                            offset = payload[66]
                            if offset < 80 or offset + 1 > len(payload):
                                raise RuntimeError("invalid original READ data range")
                            payload = payload[:offset + 1] + b"X"
                            struct.pack_into("<I", payload, 68, 2)
                        elif self.mode.endswith("-truncated"):
                            payload = payload[:79]
                        elif self.mode == "signed-write-zero":
                            struct.pack_into("<I", payload, 68, 0)
                        elif self.mode == "signed-write-over-request":
                            struct.pack_into("<I", payload, 68, 2)
                        elif self.mode == "signed-write-structure":
                            struct.pack_into("<H", payload, 64, 16)
                        elif self.mode == "header-message-id":
                            value = struct.unpack_from("<Q", payload, 24)[0]
                            struct.pack_into("<Q", payload, 24, value ^ 1)
                        elif self.mode == "header-command":
                            struct.pack_into("<H", payload, 12, 9)
                        elif self.mode == "header-tree-id":
                            value = struct.unpack_from("<I", payload, 36)[0]
                            struct.pack_into("<I", payload, 36, value ^ 1)
                        elif self.mode == "header-session-id":
                            value = struct.unpack_from("<Q", payload, 40)[0]
                            struct.pack_into("<Q", payload, 40, value ^ 1)
                        elif self.mode == "header-async":
                            value = struct.unpack_from("<I", payload, 16)[0]
                            struct.pack_into("<I", payload, 16, value | 2)
                        elif self.mode == "header-compound":
                            struct.pack_into("<I", payload, 20, 64)
                        else:
                            raise RuntimeError("unhandled IO mutation")
                        payload[48:64] = hmac.new(
                            session_key, payload, hashlib.sha256
                        ).digest()[:16]
                        mutated = True
                        client.sendall(b"\x00" + len(payload).to_bytes(3, "big") + payload)
                        # The client, not this proxy, must close the connection.
                        upstream.join(timeout=11)
                        if (
                            upstream.is_alive()
                            or not relay_error
                            or not isinstance(relay_error[0], EOFError)
                            or mutation_requests != 1
                        ):
                            raise RuntimeError("IO mutation did not cause immediate client disconnect")
                        break
                    if self.mode in RESPONSE_MUTATIONS:
                        client.sendall(header + payload)
                        continue
                    if (
                        self.mode in {
                            "unsigned-auth-error",
                            "unsigned-auth-success",
                            "unsigned-auth-wrong-id",
                        }
                        and payload[12:14] == b"\x01\x00"
                        and struct.unpack_from("<I", payload, 8)[0] == 0
                    ):
                        if struct.unpack_from("<I", payload, 16)[0] & 8 == 0:
                            raise RuntimeError("expected signed authentication success")
                        if self.mode != "unsigned-auth-success":
                            payload = payload[:64] + bytearray(9)
                            struct.pack_into("<I", payload, 8, 0xC000006D)
                            struct.pack_into("<H", payload, 64, 9)
                        struct.pack_into("<I", payload, 16, 1)
                        payload[48:64] = b"\x00" * 16
                        if self.mode == "unsigned-auth-wrong-id":
                            message_id = struct.unpack_from("<Q", payload, 24)[0]
                            struct.pack_into("<Q", payload, 24, message_id + 1)
                        client.sendall(b"\x00" + len(payload).to_bytes(3, "big") + payload)
                        mutated = True
                        upstream.join(timeout=11)
                        if upstream.is_alive() or not relay_error or not isinstance(
                            relay_error[0], EOFError
                        ):
                            raise RuntimeError("authentication client did not disconnect")
                        break
                    if (
                        self.mode in {
                            "read-reserved-fields",
                            "error-reserved-field",
                            "connection-reserved-fields",
                        }
                        and payload[12:14] == b"\x02\x00"
                    ):
                        if len(payload) < 68 or struct.unpack_from("<I", payload, 8)[0]:
                            raise RuntimeError("reserved-field test LOGOFF failed")
                        client.sendall(header + payload)
                        completed_logoff = True
                        break
                    if (
                        self.mode == "connection-reserved-fields"
                        and payload[12:14] == b"\x00\x00"
                    ):
                        if (
                            len(payload) < 128
                            or struct.unpack_from("<I", payload, 8)[0] != 0
                            or struct.unpack_from("<I", payload, 16)[0] & 8
                            or struct.unpack_from("<H", payload, 64)[0] != 65
                            or struct.unpack_from("<H", payload, 68)[0] != 0x0210
                        ):
                            raise RuntimeError("expected unsigned SMB2.1 NEGOTIATE")
                        payload[70:72] = b"\xFF" * 2
                        payload[124:128] = b"\xFF" * 4
                        client.sendall(header + payload)
                        connection_responses.append(0)
                        mutated = True
                        continue
                    if len(payload) >= 64 and (
                        payload[12:14] == b"\x03\x00"
                        or (
                            self.mode == "teardown-reserved-fields"
                            and struct.unpack_from("<H", payload, 12)[0] in {2, 4, 6}
                        )
                        or (
                            self.mode == "error-reserved-field"
                            and payload[12:14] == b"\x05\x00"
                        )
                        or (
                            self.mode == "malformed-signed-create"
                            and payload[12:14] == b"\x05\x00"
                        )
                        or (
                            self.mode in {
                                "interrupted-read-after-progress",
                                "read-reserved-fields",
                            }
                            and payload[12:14] == b"\x08\x00"
                        )
                        or (
                            self.mode == "lost-write-response-after-progress"
                            and payload[12:14] == b"\x09\x00"
                        )
                        or (
                            self.mode in DIRECTORY_MODES
                            and payload[12:14] == b"\x0e\x00"
                        )
                        or (
                            self.mode == "malformed-signed-set-info"
                            and payload[12:14] == b"\x11\x00"
                        )
                        or (
                            self.mode == "malformed-signed-tree-disconnect"
                            and payload[12:14] == b"\x04\x00"
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
                            payload[67] ^= 0xFF
                        elif self.mode == "read-reserved-fields":
                            if payload[12:14] != b"\x08\x00":
                                client.sendall(header + payload)
                                continue
                            if (
                                len(payload) < 80
                                or struct.unpack_from("<I", payload, 8)[0] != 0
                                or struct.unpack_from("<H", payload, 64)[0] != 17
                                or struct.unpack_from("<I", payload, 68)[0] == 0
                            ):
                                raise RuntimeError("expected a successful nonempty READ")
                            if session_key is None:
                                raise RuntimeError("could not derive SMB signing key")
                            if struct.unpack_from("<I", payload, 16)[0] & 8 == 0:
                                raise RuntimeError("server READ response was unsigned")
                            original_signature = bytes(payload[48:64])
                            payload[48:64] = b"\x00" * 16
                            expected_signature = hmac.new(
                                session_key, payload, hashlib.sha256
                            ).digest()[:16]
                            if not hmac.compare_digest(
                                original_signature, expected_signature
                            ):
                                raise RuntimeError(
                                    "derived key did not validate READ signature"
                                )
                            payload[67] = 0xFF
                            payload[76:80] = b"\xFF" * 4
                            payload[48:64] = hmac.new(
                                session_key, payload, hashlib.sha256
                            ).digest()[:16]
                            client.sendall(header + payload)
                            read_responses += 1
                            mutated = True
                            continue
                        elif self.mode == "connection-reserved-fields":
                            if (
                                len(payload) < 80
                                or struct.unpack_from("<I", payload, 8)[0] != 0
                                or struct.unpack_from("<H", payload, 64)[0] != 16
                            ):
                                raise RuntimeError("expected successful TREE_CONNECT")
                            if session_key is None:
                                raise RuntimeError("could not derive SMB signing key")
                            if struct.unpack_from("<I", payload, 16)[0] & 8 == 0:
                                raise RuntimeError("server TREE_CONNECT was unsigned")
                            original_signature = bytes(payload[48:64])
                            payload[48:64] = b"\x00" * 16
                            expected_signature = hmac.new(
                                session_key, payload, hashlib.sha256
                            ).digest()[:16]
                            if not hmac.compare_digest(
                                original_signature, expected_signature
                            ):
                                raise RuntimeError(
                                    "derived key did not validate TREE_CONNECT signature"
                                )
                            payload[67] = 0xFF
                            payload[48:64] = hmac.new(
                                session_key, payload, hashlib.sha256
                            ).digest()[:16]
                            client.sendall(header + payload)
                            connection_responses.append(3)
                            mutated = True
                            continue
                        elif self.mode == "teardown-reserved-fields":
                            command = struct.unpack_from("<H", payload, 12)[0]
                            if command not in {2, 4, 6}:
                                client.sendall(header + payload)
                                continue
                            length = 124 if command == 6 else 68
                            structure = 60 if command == 6 else 4
                            offset = 68 if command == 6 else 66
                            width = 4 if command == 6 else 2
                            if (
                                len(payload) < length
                                or struct.unpack_from("<I", payload, 8)[0] != 0
                                or struct.unpack_from("<H", payload, 64)[0] != structure
                            ):
                                raise RuntimeError("expected successful teardown response")
                            if session_key is None:
                                raise RuntimeError("could not derive SMB signing key")
                            if struct.unpack_from("<I", payload, 16)[0] & 8 == 0:
                                raise RuntimeError("server teardown response was unsigned")
                            original_signature = bytes(payload[48:64])
                            payload[48:64] = b"\x00" * 16
                            expected_signature = hmac.new(
                                session_key, payload, hashlib.sha256
                            ).digest()[:16]
                            if not hmac.compare_digest(
                                original_signature, expected_signature
                            ):
                                raise RuntimeError(
                                    "derived key did not validate teardown signature"
                                )
                            payload[offset:offset + width] = b"\xFF" * width
                            payload[48:64] = hmac.new(
                                session_key, payload, hashlib.sha256
                            ).digest()[:16]
                            client.sendall(header + payload)
                            teardown_responses.append(command)
                            mutated = True
                            if command == 2:
                                completed_logoff = True
                                break
                            continue
                        elif self.mode == "error-reserved-field":
                            if (
                                payload[12:14] != b"\x05\x00"
                                or struct.unpack_from("<I", payload, 8)[0] == 0
                            ):
                                client.sendall(header + payload)
                                continue
                            if (
                                len(payload) < 72
                                or struct.unpack_from("<I", payload, 8)[0] != 0xC0000034
                                or struct.unpack_from("<H", payload, 64)[0] != 9
                                or payload[66] != 0
                                or struct.unpack_from("<I", payload, 68)[0]
                                > len(payload) - 72
                            ):
                                raise RuntimeError("expected missing-file ERROR body")
                            if session_key is None:
                                raise RuntimeError("could not derive SMB signing key")
                            if struct.unpack_from("<I", payload, 16)[0] & 8 == 0:
                                raise RuntimeError("server ERROR response was unsigned")
                            original_signature = bytes(payload[48:64])
                            payload[48:64] = b"\x00" * 16
                            expected_signature = hmac.new(
                                session_key, payload, hashlib.sha256
                            ).digest()[:16]
                            if not hmac.compare_digest(
                                original_signature, expected_signature
                            ):
                                raise RuntimeError(
                                    "derived key did not validate ERROR signature"
                                )
                            payload[67] = 0xFF
                            payload[48:64] = hmac.new(
                                session_key, payload, hashlib.sha256
                            ).digest()[:16]
                            client.sendall(header + payload)
                            error_responses += 1
                            mutated = True
                            continue
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
                        elif self.mode in DIRECTORY_MODES:
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
                            if self.mode == "dangling-signed-directory-second-page":
                                end = data_offset + data_length
                                entry = data_offset
                                while True:
                                    if end - entry < 104:
                                        raise RuntimeError("truncated directory record")
                                    next_entry = struct.unpack_from("<I", payload, entry)[0]
                                    if next_entry == 0:
                                        break
                                    if (
                                        next_entry < 104
                                        or next_entry % 8 != 0
                                        or next_entry >= end - entry
                                    ):
                                        raise RuntimeError("invalid backend directory link")
                                    entry += next_entry
                                remaining = end - entry
                                name_length = struct.unpack_from(
                                    "<I", payload, entry + 60
                                )[0]
                                if (
                                    name_length == 0
                                    or name_length % 2 != 0
                                    or name_length > remaining - 104
                                ):
                                    raise RuntimeError("invalid backend directory name")
                                padding = (-remaining) % 8
                                if data_length + padding > 65_536:
                                    raise RuntimeError("directory mutation exceeds chunk bound")
                                payload[end:end] = b"\x00" * padding
                                struct.pack_into("<I", payload, 68, data_length + padding)
                                struct.pack_into("<I", payload, entry, remaining + padding)
                                header = b"\x00" + len(payload).to_bytes(3, "big")
                            else:
                                struct.pack_into("<I", payload, data_offset, 1)
                            payload[48:64] = b"\x00" * 16
                            payload[48:64] = hmac.new(
                                session_key, payload, hashlib.sha256
                            ).digest()[:16]
                            client.sendall(header + payload)
                            mutated = True
                            if (
                                self.mode in DIRECTORY_MODES
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
                        elif self.mode == "malformed-signed-tree-disconnect":
                            if payload[12:14] != b"\x04\x00":
                                client.sendall(header + payload)
                                continue
                            if session_key is None:
                                raise RuntimeError("could not derive SMB signing key")
                            if struct.unpack_from("<I", payload, 16)[0] & 8 == 0:
                                raise RuntimeError(
                                    "server TREE_DISCONNECT response was unsigned"
                                )
                            if struct.unpack_from("<H", payload, 64)[0] != 4:
                                raise RuntimeError(
                                    "unexpected TREE_DISCONNECT structure size"
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
                                    "derived key did not validate TREE_DISCONNECT signature"
                                )
                            struct.pack_into("<H", payload, 64, 5)
                            payload[48:64] = b"\x00" * 16
                            payload[48:64] = hmac.new(
                                session_key, payload, hashlib.sha256
                            ).digest()[:16]
                            client.sendall(header + payload)
                            mutated = True
                            upstream.join(timeout=11)
                            if upstream.is_alive():
                                raise RuntimeError(
                                    "client did not close after malformed TREE_DISCONNECT"
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
            if self.mode == "read-reserved-fields":
                if read_responses != 3 or not completed_logoff or logoff_requests != 1:
                    raise RuntimeError(
                        "reserved-field READ exchange did not complete: "
                        f"reads={read_responses}, logoff={completed_logoff}, "
                        f"logoff_requests={logoff_requests}"
                    )
            if self.mode == "error-reserved-field":
                if error_responses != 1 or not completed_logoff or logoff_requests != 1:
                    raise RuntimeError(
                        "reserved-field ERROR exchange did not complete: "
                        f"errors={error_responses}, logoff={completed_logoff}, "
                        f"logoff_requests={logoff_requests}"
                    )
            if self.mode == "teardown-reserved-fields":
                if (
                    teardown_responses != [6, 6, 4, 2]
                    or not completed_logoff
                    or tree_disconnect_requests != 1
                    or logoff_requests != 1
                ):
                    raise RuntimeError(
                        "reserved-field teardown exchange did not complete: "
                        f"responses={teardown_responses}, "
                        f"tree_disconnect={tree_disconnect_requests}, "
                        f"logoff={logoff_requests}"
                    )
            if self.mode == "connection-reserved-fields":
                if (
                    connection_responses != [0, 3]
                    or not completed_logoff
                    or logoff_requests != 1
                ):
                    raise RuntimeError(
                        "reserved-field connection exchange did not complete: "
                        f"responses={connection_responses}, logoff={logoff_requests}"
                    )
            if self.mode in DIRECTORY_MODES:
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
            if self.mode == "malformed-signed-tree-disconnect":
                if tree_disconnect_requests != 1:
                    raise RuntimeError(
                        "expected exactly one TREE_DISCONNECT request, got "
                        f"{tree_disconnect_requests}"
                    )
                if logoff_requests != 0:
                    raise RuntimeError(
                        f"expected zero LOGOFF requests, got {logoff_requests}"
                    )
                if not relay_error or not isinstance(relay_error[0], EOFError):
                    raise RuntimeError(
                        "TREE_DISCONNECT client connection did not close after mutation"
                    )
