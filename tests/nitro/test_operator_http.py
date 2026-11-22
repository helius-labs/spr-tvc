import http.client
import pathlib
import socket
import sys
import unittest
from concurrent.futures import ThreadPoolExecutor
from time import monotonic
from unittest.mock import patch

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2] / "enclave/deploy/nitro"))
from operator_http import DeadlineSocket, request_bytes


class OperatorHttpTests(unittest.TestCase):
    def exchange(self, reply, limit):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen()
            listener.settimeout(2)

            def respond():
                peer, _ = listener.accept()
                with peer:
                    peer.settimeout(2)
                    with peer.makefile("rb") as request:
                        self.assertEqual(request.readline(), b"POST /recipient HTTP/1.1\r\n")
                        while (line := request.readline()) not in (b"\r\n", b""):
                            pass
                        self.assertEqual(request.read(1), b"x")
                    peer.sendall(reply)

            with ThreadPoolExecutor(max_workers=1) as worker:
                response = worker.submit(respond)
                try:
                    return request_bytes(socket.AF_INET, listener.getsockname(), "POST", "/recipient", b"x", limit)
                finally:
                    response.result(timeout=2)

    def test_http_exchange_keeps_existing_response_size_limit(self):
        reply = b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\nabcdef"
        self.assertEqual(self.exchange(reply, 3), (200, b"abcd"))

    def test_short_reply_fails_even_if_delivered_bytes_fit_the_limit(self):
        reply = b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\nabc"
        with self.assertRaises(http.client.IncompleteRead):
            self.exchange(reply, 3)

    def test_buffered_reads_cannot_extend_the_socket_deadline(self):
        start = monotonic()
        with (socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener,
              DeadlineSocket(socket.AF_INET, start + 2) as client,
              patch("operator_http.monotonic", return_value=start) as clock):
            listener.bind(("127.0.0.1", 0))
            listener.listen()
            listener.settimeout(2)
            client.connect(listener.getsockname())
            peer, _ = listener.accept()
            with peer, client.makefile("rb") as body:
                peer.sendall(b"a")
                self.assertEqual(body.read(1), b"a")
                clock.return_value = start + 2
                peer.sendall(b"b")
                with self.assertRaisesRegex(TimeoutError, "operator HTTP deadline expired"):
                    body.read(1)


if __name__ == "__main__":
    unittest.main()
