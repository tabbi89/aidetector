"""Reproducible, local-only SSLyze versus testssl.sh benchmark.

Starts one bounded TLS/HTTP fixture on an ephemeral loopback port, runs exactly
one scanner, and prints machine-readable timing/resource/connection metrics.
No target or auxiliary Internet access is needed: testssl receives a fixed IP
and no ``--phone-out`` flag; SSLyze's trust-store updater is never invoked.
"""
from __future__ import annotations

import argparse
import json
import resource
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Any


class TlsFixture:
    def __init__(self, certificate: str, key: str, profile: str) -> None:
        self._socket = socket.socket()
        self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._socket.bind(("127.0.0.1", 0))
        self._socket.listen(128)
        self._socket.settimeout(0.2)
        self.port = int(self._socket.getsockname()[1])
        self.connections = 0
        self._stop = threading.Event()
        self._context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self._context.load_cert_chain(certificate, key)
        if profile == "legacy":
            self._context.minimum_version = ssl.TLSVersion.TLSv1
            self._context.maximum_version = ssl.TLSVersion.TLSv1_2
            self._context.set_ciphers("AES128-SHA:@SECLEVEL=0")
        else:
            self._context.minimum_version = ssl.TLSVersion.TLSv1_3
            self._context.maximum_version = ssl.TLSVersion.TLSv1_3
        self._thread = threading.Thread(target=self._serve, daemon=True)

    def __enter__(self) -> TlsFixture:
        self._thread.start()
        return self

    def __exit__(self, *_args: Any) -> None:
        self._stop.set()
        self._thread.join(timeout=2)
        self._socket.close()

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                connection, _ = self._socket.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            self.connections += 1
            threading.Thread(
                target=self._handle, args=(connection,), daemon=True
            ).start()

    def _handle(self, connection: socket.socket) -> None:
        connection.settimeout(1)
        try:
            with self._context.wrap_socket(connection, server_side=True) as tls:
                try:
                    tls.recv(16_384)
                except (OSError, TimeoutError):
                    pass
                try:
                    tls.sendall(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n"
                        b"Connection: close\r\n\r\nok"
                    )
                except OSError:
                    pass
        except (OSError, ssl.SSLError):
            connection.close()


def _command(tool: str, executable: str, port: int, output: Path) -> list[str]:
    target = f"localhost:{port}"
    if tool == "sslyze":
        return [
            executable,
            "--quiet",
            "--slow_connection",
            "--mozilla_config",
            "intermediate",
            "--json_out",
            str(output),
            "--sni",
            "localhost",
            "--certinfo",
            "--sslv2",
            "--sslv3",
            "--tlsv1",
            "--tlsv1_1",
            "--tlsv1_2",
            "--tlsv1_3",
            "--compression",
            "--fallback",
            "--reneg",
            "--openssl_ccs",
            "--heartbleed",
            "--robot",
            "--elliptic_curves",
            target,
        ]
    return [
        executable,
        "--quiet",
        "--color",
        "0",
        "--warnings",
        "batch",
        "--nodns",
        "none",
        "--ip",
        "127.0.0.1",
        "--jsonfile",
        str(output),
        "--overwrite",
        f"https://{target}",
    ]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tool", choices=("sslyze", "testssl"), required=True)
    parser.add_argument("--executable", required=True)
    parser.add_argument("--certificate", required=True)
    parser.add_argument("--key", required=True)
    parser.add_argument("--profile", choices=("legacy", "modern"), required=True)
    parser.add_argument("--timeout", type=float, default=180)
    parser.add_argument("--json-output")
    args = parser.parse_args()

    with tempfile.TemporaryDirectory(prefix="tls-benchmark-") as directory:
        output = Path(directory) / f"{args.tool}.json"
        before = resource.getrusage(resource.RUSAGE_CHILDREN)
        with TlsFixture(args.certificate, args.key, args.profile) as fixture:
            command = _command(args.tool, args.executable, fixture.port, output)
            started = time.monotonic()
            try:
                completed = subprocess.run(
                    command,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=max(1, args.timeout),
                    check=False,
                )
                exit_code: int | None = completed.returncode
                timed_out = False
            except subprocess.TimeoutExpired:
                exit_code = None
                timed_out = True
            wall = time.monotonic() - started
            connections = fixture.connections
        after = resource.getrusage(resource.RUSAGE_CHILDREN)
        if args.json_output and output.exists():
            shutil.copyfile(output, args.json_output)
        max_rss_bytes = after.ru_maxrss if sys.platform == "darwin" else after.ru_maxrss * 1024
        result = {
            "tool": args.tool,
            "profile": args.profile,
            "wall_seconds": round(wall, 3),
            "user_cpu_seconds": round(after.ru_utime - before.ru_utime, 3),
            "system_cpu_seconds": round(after.ru_stime - before.ru_stime, 3),
            "max_rss_bytes": max_rss_bytes,
            "connections": connections,
            "exit_code": exit_code,
            "timed_out": timed_out,
            "json_bytes": output.stat().st_size if output.exists() else 0,
        }
        print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
