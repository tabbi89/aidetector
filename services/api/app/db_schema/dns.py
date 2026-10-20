"""Terminating DNS resolver: asyncio's thread resolver can outlive its timeout."""

from __future__ import annotations

import asyncio
import json
import sys

from app.db_schema.contracts import SchemaUnavailable

# Isolated interpreter, fixed code, no credentials/environment-derived libpq
# configuration. A stuck OS resolver is killed when the call deadline expires.
_SCRIPT = """
import json, socket, sys
try:
    rows = socket.getaddrinfo(sys.argv[1], sys.argv[2], type=socket.SOCK_STREAM,
                              proto=socket.IPPROTO_TCP)
    print(json.dumps([row[4][0] for row in rows[:65]]))
except Exception:
    print('[]')
"""


async def resolve(host: str, port: int) -> list[str]:
    process = await asyncio.create_subprocess_exec(
        sys.executable,
        "-I",
        "-c",
        _SCRIPT,
        host,
        str(port),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
    )
    try:
        stdout, _ = await process.communicate()
        addresses = json.loads(stdout)
        if process.returncode or not isinstance(addresses, list) or len(addresses) > 64:
            raise SchemaUnavailable("destination_not_allowed")
        return addresses
    finally:
        if process.returncode is None:
            process.kill()
        await process.wait()
