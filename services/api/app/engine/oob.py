"""Out-of-band (OAST) interaction client for blind-vulnerability confirmation.

Blind XXE / RFI / RCE / ESI and blind SSRF never reflect anything into the
response — the only proof is the target reaching out to a server *we* control.
This module is the seam for that: checks embed a unique token into a callback
URL/domain, and after the active pass the runner polls for interactions and
correlates them back to the injection point.

Design mirrors the rest of the engine and the AI cascade:

- The client is **injected via ``ScanContext``**, exactly like ``HttpClient`` —
  so tests bind a deterministic in-memory collector and never touch a network.
- Everything **degrades gracefully**. When no OAST server is configured the
  runner uses :class:`NullOobClient`: ``active`` is False, payload builders
  return ``None`` (checks then skip OOB injection), and ``poll`` yields nothing.
  An OOB problem must never fail a scan — same contract as ``PlannerUnavailable``.

The real transport is :class:`InteractshClient`, which shells out to the
``interactsh-client`` binary against a self-hosted ``interactsh-server`` (see
``docker-compose.yml`` and ``ai_runtime``-style subprocess isolation). We defer
the correlation crypto to that official binary rather than reimplementing it.
"""
from __future__ import annotations

import json
import logging
import re
import subprocess
import threading
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Protocol

log = logging.getLogger("runpentests.oob")

# A bare hostname line (the session callback domain interactsh prints at startup).
_DOMAIN_RE = re.compile(
    r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$", re.IGNORECASE
)


@dataclass(frozen=True)
class Interaction:
    """One inbound callback the OAST server observed."""

    protocol: str          # "http", "dns", "smtp", ...
    token: str             # the correlation token we embedded in the payload
    source_ip: str | None  # remote address that made the callback, if known
    raw: str               # raw interaction record (for evidence)


class OobClient(Protocol):
    """What a check needs from an out-of-band interaction server."""

    @property
    def active(self) -> bool:
        """True when an OAST server is configured and reachable."""
        ...

    def payload_url(self, token: str) -> str | None:
        """An ``http://…/<token>`` callback URL, or None when inactive."""
        ...

    def payload_domain(self, token: str) -> str | None:
        """A ``<token>.<oast-domain>`` callback host, or None when inactive."""
        ...

    def poll(self) -> list[Interaction]:
        """Return interactions observed since the last poll (may be empty)."""
        ...


class NullOobClient:
    """No-op client used when no OAST server is configured.

    Keeps every OOB-aware check a no-op without special-casing: the payload
    builders return None so checks skip injection, and ``poll`` is empty.
    """

    active = False

    def payload_url(self, token: str) -> str | None:
        return None

    def payload_domain(self, token: str) -> str | None:
        return None

    def poll(self) -> list[Interaction]:
        return []


class _Process(Protocol):
    """The subset of ``subprocess.Popen`` the client drives (so tests can fake it)."""

    stdout: Any

    def terminate(self) -> None: ...
    def wait(self, timeout: float | None = ...) -> int: ...


class InteractshClient:
    """OAST client backed by a **persistent** ``interactsh-client`` session.

    The correlation keypair lives in one long-running process: we start it once,
    capture the session callback domain it prints, and a background thread streams
    inbound interaction JSON into a buffer that :meth:`poll` drains. This is the
    fix for the earlier one-shot design — a fresh subprocess per call regenerated
    the session keypair and so could never correlate a callback.

    The subprocess is injectable (``spawn``) so tests drive a deterministic fake
    with no network and no real binary; production spawns the CLI. Every failure
    path degrades to inactive so an OOB problem never fails a scan.

    ``server`` is the interactsh-server domain (e.g. ``oast.internal``); ``token``
    is the server auth token when the server was started with one.
    """

    def __init__(
        self,
        server: str,
        *,
        token: str | None = None,
        binary: str = "interactsh-client",
        spawn: Callable[[], _Process] | None = None,
        startup_timeout: float = 10.0,
    ) -> None:
        self._server = server
        self._token = token
        self._binary = binary
        self._spawn = spawn or self._default_spawn
        self._proc: _Process | None = None
        self._reader: threading.Thread | None = None
        self._session_domain: str | None = None
        self._active = False
        self._lock = threading.Lock()
        self._pending: list[Interaction] = []
        self._domain_ready = threading.Event()
        self._start(startup_timeout)

    def _default_spawn(self) -> _Process:
        args = [self._binary, "-server", self._server, "-json"]
        if self._token:
            args += ["-token", self._token]
        return subprocess.Popen(  # noqa: S603 — fixed binary, no shell
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            bufsize=1,
        )

    def _start(self, startup_timeout: float) -> None:
        try:
            self._proc = self._spawn()
        except Exception:  # noqa: BLE001 — missing binary/unreachable → inactive
            log.warning("interactsh spawn failed; OOB disabled", exc_info=True)
            return
        self._reader = threading.Thread(
            target=self._read_loop, name="interactsh-reader", daemon=True
        )
        self._reader.start()
        # The session domain is the first thing the client prints; wait for it so
        # payload builders return real callback hosts.
        if self._domain_ready.wait(timeout=startup_timeout) and self._session_domain:
            self._active = True
        else:
            log.warning(
                "interactsh: no session domain within %.1fs; OOB disabled",
                startup_timeout,
            )
            self.close()

    def _read_loop(self) -> None:
        stdout = getattr(self._proc, "stdout", None)
        if stdout is None:
            return
        try:
            for line in stdout:
                self._handle_line(line.strip())
        except Exception:  # noqa: BLE001 — a closed pipe simply ends the stream
            pass

    def _handle_line(self, line: str) -> None:
        if not line:
            return
        rec: Any = None
        if line.startswith("{"):
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                rec = None
        if self._session_domain is None:
            domain = _session_domain_from(line, rec)
            if domain:
                self._session_domain = domain
                self._domain_ready.set()
        if rec is not None and self._session_domain is not None:
            interaction = _record_to_interaction(rec, line)
            if interaction is not None:
                with self._lock:
                    self._pending.append(interaction)

    @property
    def active(self) -> bool:
        return self._active

    def payload_url(self, token: str) -> str | None:
        host = self.payload_domain(token)
        return f"http://{host}/{token}" if host else None

    def payload_domain(self, token: str) -> str | None:
        if not self._active or not self._session_domain:
            return None
        # interactsh correlates on a unique subdomain label per injection point.
        return f"{token}.{self._session_domain}"

    def poll(self) -> list[Interaction]:
        if not self._active:
            return []
        with self._lock:
            out, self._pending = self._pending, []
        return out

    def close(self) -> None:
        """Terminate the session process and stop streaming. Idempotent."""
        self._active = False
        proc = self._proc
        if proc is not None:
            try:
                proc.terminate()
            except Exception:  # noqa: BLE001
                pass
            try:
                proc.wait(timeout=5)
            except Exception:  # noqa: BLE001
                pass
        if self._reader is not None:
            self._reader.join(timeout=5)


def _session_domain_from(line: str, rec: Any) -> str | None:
    """Derive the session callback domain from a startup line or a JSON record."""
    if rec is not None:
        full = str(rec.get("full-id") or rec.get("unique-id") or "")
        return full.split(".", 1)[1] if "." in full else None
    return line if _DOMAIN_RE.match(line) else None


def _record_to_interaction(rec: dict[str, Any], raw: str) -> Interaction | None:
    """Convert one interactsh ``-json`` record to an :class:`Interaction`.

    The unique subdomain label the payload carried is the correlation token — the
    left-most label of the full interaction domain.
    """
    full = str(rec.get("full-id") or rec.get("unique-id") or "")
    token = full.split(".", 1)[0] if full else ""
    if not token:
        return None
    return Interaction(
        protocol=str(rec.get("protocol", "")).lower(),
        token=token,
        source_ip=rec.get("remote-address"),
        raw=raw[:1000],
    )
