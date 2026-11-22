"""Deadline-bound HTTP byte exchanges over local TCP or vsock."""

import http.client
import socket
from time import monotonic

HTTP_TIMEOUT = 8


def remaining(deadline):
    timeout = deadline - monotonic()
    if timeout <= 0:
        raise TimeoutError("operator HTTP deadline expired")
    return timeout


class DeadlineSocket(socket.socket):
    def __init__(self, family, deadline):
        super().__init__(family, socket.SOCK_STREAM)
        self.deadline = deadline

    def connect(self, address):
        self.settimeout(remaining(self.deadline))
        return super().connect(address)

    def sendall(self, data, flags=0):
        self.settimeout(remaining(self.deadline))
        return super().sendall(data, flags)

    def recv_into(self, buffer, nbytes=0, flags=0):
        # HTTPResponse reads through socket.makefile(), which uses recv_into.
        self.settimeout(remaining(self.deadline))
        return super().recv_into(buffer, nbytes, flags)


class LocalConnection(http.client.HTTPConnection):
    def __init__(self, family, address, deadline):
        super().__init__("localhost")
        self.family = family
        self.address = address
        self.deadline = deadline

    def connect(self):
        self.sock = DeadlineSocket(self.family, self.deadline)
        self.sock.connect(self.address)


def request_bytes(family, address, method, path, body, limit, *, deadline=None):
    deadline = monotonic() + HTTP_TIMEOUT if deadline is None else deadline
    conn = LocalConnection(family, address, deadline)
    try:
        conn.request(method, path, body, headers={
            "Connection": "close", "Content-Type": "application/octet-stream",
        })
        with conn.getresponse() as response:
            length = response.length
            data = response.read(limit + 1)
            if length is not None and len(data) < min(length, limit + 1):
                raise http.client.IncompleteRead(data, length - len(data))
            remaining(deadline)
            return response.status, data
    finally:
        conn.close()
