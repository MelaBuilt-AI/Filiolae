#!/usr/bin/env python3
"""Bounded loopback-only fault shim for Filiolae transparency S2."""

from __future__ import annotations

import argparse
import contextlib
import http.client
import json
import os
import socket
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit


class State:
    def __init__(self, mode: str, target: str, count: int):
        self.mode = mode
        self.target = target
        self.remaining = count
        self.lock = threading.Lock()

    def take(self, path: str) -> bool:
        with self.lock:
            if path != self.target or self.remaining <= 0:
                return False
            self.remaining -= 1
            return True


class Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = False

    def __init__(self, address, handler, upstream_port: int, state: State):  # noqa: ANN001
        super().__init__(address, handler)
        self.upstream_port = upstream_port
        self.state = state


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "FiliolaeS2FaultShim/1"

    def log_message(self, format_string, *args):  # noqa: ANN001
        return

    def do_GET(self):
        self._forward(False)

    def do_POST(self):
        self._forward(True)

    def _forward(self, has_body: bool):
        length = int(self.headers.get("Content-Length", "0")) if has_body else 0
        if length < 0 or length > 65536:
            self.send_error(413)
            return
        body = self.rfile.read(length) if length else None
        headers = {}
        if has_body:
            headers["Content-Type"] = self.headers.get("Content-Type", "")
            headers["Content-Length"] = str(length)
        connection = http.client.HTTPConnection("127.0.0.1", self.server.upstream_port, timeout=15)
        try:
            connection.request(self.command, self.path, body=body, headers=headers)
            response = connection.getresponse()
            raw = response.read(256 * (65536 + 2) + 1)
            status = response.status
            content_type = response.getheader("Content-Type", "application/octet-stream")
        except OSError:
            self.send_error(502)
            return
        finally:
            connection.close()
        inject = self.server.state.take(self.path)
        if inject and self.server.state.mode == "drop-append-response":
            with contextlib.suppress(OSError):
                self.connection.shutdown(socket.SHUT_RDWR)
            self.close_connection = True
            return
        if inject and self.server.state.mode == "truncate-read":
            raw = raw[:-1] if raw else raw
        if inject and self.server.state.mode == "mutate-read" and raw:
            altered = bytearray(raw)
            altered[len(altered) // 2] ^= 1
            raw = bytes(altered)
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Connection", "close")
        self.end_headers()
        if raw:
            with contextlib.suppress(OSError):
                self.wfile.write(raw)
        self.close_connection = True


def write_new(path: Path, data: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--upstream", required=True)
    parser.add_argument(
        "--mode", required=True, choices=["truncate-read", "drop-append-response", "mutate-read"]
    )
    parser.add_argument("--target", required=True)
    parser.add_argument("--count", required=True, type=int)
    parser.add_argument("--port-file", required=True, type=Path)
    parser.add_argument("--events", required=True, type=Path)
    args = parser.parse_args()
    parsed = urlsplit(args.upstream)
    if parsed.scheme != "http" or parsed.hostname != "127.0.0.1" or parsed.port is None:
        parser.error("upstream must be literal IPv4 loopback")
    if args.count < 1 or not args.target.startswith("/") or ".." in args.target:
        parser.error("invalid bounded fault configuration")
    server = Server(("127.0.0.1", 0), Handler, parsed.port, State(args.mode, args.target, args.count))
    port = server.server_address[1]
    write_new(args.port_file, f"{port}\n".encode())
    write_new(
        args.events,
        (
            json.dumps(
                {
                    "schema": "filiolae.transparency-s2-fault.v1",
                    "mode": args.mode,
                    "target": args.target,
                    "count": args.count,
                    "port": port,
                },
                sort_keys=True,
            )
            + "\n"
        ).encode(),
    )
    try:
        server.serve_forever(poll_interval=0.1)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
