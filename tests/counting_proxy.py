"""Count requests and successful handle lifetimes without altering SMB frames."""

from __future__ import annotations

from collections import Counter
import socket
import struct

from adversarial_proxy import AdversarialProxy
from async_proxy import recv_frame


class RequestCountingProxy(AdversarialProxy):
    def __init__(self, listen_port: int, backend_port: int) -> None:
        super().__init__("request-counting", listen_port, backend_port)
        self.commands: Counter[int] = Counter()
        self.open_handles = 0
        self.peak_handles = 0

    def _relay_and_mutate(self, client: socket.socket) -> None:
        with socket.create_connection(("127.0.0.1", self.backend_port), timeout=5) as backend:
            client.settimeout(10)
            backend.settimeout(10)
            while True:
                header, request = recv_frame(client)
                command = struct.unpack_from("<H", request, 12)[0]
                self.commands[command] += 1
                backend.sendall(header + request)
                while True:
                    header, response = recv_frame(backend)
                    status = struct.unpack_from("<I", response, 8)[0]
                    client.sendall(header + response)
                    if status == 0x103:
                        continue
                    if status == 0:
                        if command == 5:
                            self.open_handles += 1
                            self.peak_handles = max(self.peak_handles, self.open_handles)
                        elif command == 6:
                            self.open_handles -= 1
                    break
                if command == 2:
                    if client.recv(1):
                        raise RuntimeError("unexpected traffic after LOGOFF")
                    return
