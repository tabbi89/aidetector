"""Per-run bearer tokens for the local runner.

When a scan is claimed to run on the CLI machine, the server mints a random
token, hands the clear token back once, and stores only its SHA-256 hash on the
``ScanRun``. Every later call from the runner (events, heartbeat, results)
presents the clear token; the server hashes it and compares in constant time
against the stored hash. The token is scoped to that one run and is cleared when
the run ends, so a leaked or late token cannot post to a finished run or to any
other run.

The hash is stored (never the token) for the same reason a password is: a
database read must not yield a working credential.
"""
from __future__ import annotations

import hashlib
import secrets

#: Clear-token length in URL-safe characters is ~1.3× these bytes. 32 bytes of
#: entropy is well beyond guessable for a value that lives only while one run does.
_TOKEN_BYTES = 32


def new_run_token() -> tuple[str, str]:
    """Return ``(clear_token, token_hash)``. Store the hash; return the token once."""
    clear = secrets.token_urlsafe(_TOKEN_BYTES)
    return clear, hash_run_token(clear)


def hash_run_token(clear: str) -> str:
    """The stored form of a clear token: lowercase hex SHA-256 (64 chars)."""
    return hashlib.sha256(clear.encode("utf-8")).hexdigest()


def token_matches(clear: str | None, stored_hash: str | None) -> bool:
    """Whether ``clear`` is the token behind ``stored_hash``. Constant-time.

    False whenever either side is missing: a run with no token hash (a server
    run, or one already ended) can never be posted to by a runner.
    """
    if not clear or not stored_hash:
        return False
    return secrets.compare_digest(hash_run_token(clear), stored_hash)
