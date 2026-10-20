"""Bounded, offline, in-memory adapter around ``detect-secrets``.

The scanner process sends text to a short-lived Python subprocess over stdin.
That worker disables detector verification and network primitives, then returns
only a detector name and the caller-supplied structural location. Raw matches,
their hashes and detector objects never cross the process boundary.
"""
from __future__ import annotations

import json
import logging
import re
import socket
import subprocess
import sys
from dataclasses import dataclass
from typing import Any

MAX_UNITS = 256
MAX_UNIT_BYTES = 40_000
MAX_TOTAL_BYTES = 240_000
MAX_MATCHES = 24
SCAN_TIMEOUT_SECONDS = 2.0

_VERIFY_FILTER = "detect_secrets.filters.common.is_ignored_due_to_verification_policies"
_GENERIC_DETECTORS = {
    "Base64 High Entropy String",
    "Hex High Entropy String",
    "Secret Keyword",
}
_PLACEHOLDER_WORDS = {
    "changeme",
    "change-me",
    "dummy",
    "example",
    "fake",
    "not-a-real-secret",
    "placeholder",
    "replace-me",
    "sample",
    "test",
    "your-api-key-here",
}
_SAFE_LABEL = re.compile(r"[^A-Za-z0-9 ._+:/\[\]-]")
_UUID = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-"
    r"[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class ScanUnit:
    source_id: int
    location: str
    text: str


@dataclass(frozen=True)
class SecretMatch:
    source_id: int
    location: str
    detector: str


def _truncate_utf8(value: str, limit: int) -> str:
    return value.encode("utf-8", "replace")[:limit].decode("utf-8", "ignore")


def _safe_label(value: Any, fallback: str) -> str:
    cleaned = _SAFE_LABEL.sub("_", str(value))[:96].strip()
    return cleaned or fallback


def _bounded(units: list[ScanUnit]) -> tuple[list[ScanUnit], bool]:
    """Cap the units for the worker, and report whether anything was cut.

    The ``truncated`` flag tells the caller the scan may be incomplete — a
    silent cap otherwise reads like a clean answer when a secret in the tail
    simply was never scanned.
    """
    output: list[ScanUnit] = []
    remaining = MAX_TOTAL_BYTES
    truncated = len(units) > MAX_UNITS
    for unit in units[:MAX_UNITS]:
        if remaining <= 0:
            truncated = True
            break
        limit = min(MAX_UNIT_BYTES, remaining)
        if len(unit.text.encode("utf-8", "replace")) > limit:
            truncated = True
        text = _truncate_utf8(unit.text, limit)
        if not text:
            continue
        size = len(text.encode("utf-8"))
        remaining -= size
        output.append(
            ScanUnit(
                source_id=int(unit.source_id),
                location=_safe_label(unit.location, "value"),
                text=text,
            )
        )
    return output, truncated


def scan_offline(
    units: list[ScanUnit], *, timeout: float = SCAN_TIMEOUT_SECONDS
) -> list[SecretMatch]:
    """Scan bounded strings without files or network and return value-free matches."""
    matches, _ = scan_offline_truncated(units, timeout=timeout)
    return matches


def scan_offline_truncated(
    units: list[ScanUnit], *, timeout: float = SCAN_TIMEOUT_SECONDS
) -> tuple[list[SecretMatch], bool]:
    """``scan_offline`` plus whether a bound cut the input short.

    The ``truncated`` flag is the caller's signal that the scan may have missed
    a secret in the part of the input it never reached.
    """
    bounded, truncated = _bounded(units)
    if not bounded:
        return [], truncated
    payload = json.dumps(
        {"texts": [unit.text for unit in bounded], "max_matches": MAX_MATCHES},
        separators=(",", ":"),
    )
    try:
        completed = subprocess.run(  # noqa: S603 - fixed interpreter/module only
            [sys.executable, "-m", "app.engine.secret_scan", "--worker"],
            input=payload,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=max(0.1, min(float(timeout), SCAN_TIMEOUT_SECONDS)),
            check=False,
        )
        if completed.returncode != 0 or len(completed.stdout) > 32_000:
            return [], truncated
        decoded = json.loads(completed.stdout)
    except (OSError, ValueError, subprocess.SubprocessError):
        return [], truncated

    rows = decoded.get("matches") if isinstance(decoded, dict) else None
    if not isinstance(rows, list):
        return [], truncated
    matches: list[SecretMatch] = []
    seen: set[tuple[int, str]] = set()
    for row in rows[:MAX_MATCHES]:
        if not isinstance(row, dict):
            continue
        index = row.get("unit")
        if not isinstance(index, int) or not 0 <= index < len(bounded):
            continue
        detector = _safe_label(row.get("detector"), "Potential secret")
        unit = bounded[index]
        key = (index, detector)
        if key in seen:
            continue
        seen.add(key)
        matches.append(SecretMatch(unit.source_id, unit.location, detector))
    return matches, truncated


def _looks_like_placeholder(value: str) -> bool:
    normalized = value.strip().strip("'\"`").lower()
    if not normalized:
        return True
    if normalized in _PLACEHOLDER_WORDS:
        return True
    if _UUID.fullmatch(normalized):
        return True
    if any(token in normalized for token in ("${", "{{", "}}", "<token", "your_")):
        return True
    if normalized.startswith(
        (
            "example-",
            "example_",
            "sample-",
            "sample_",
            "dummy-",
            "dummy_",
            "fake-",
            "fake_",
            "test-",
            "test_",
        )
    ):
        return True
    if len(set(normalized)) <= 2:
        return True
    return False


def _worker_scan(texts: list[str], max_matches: int) -> list[dict[str, Any]]:
    """Run detectors synchronously inside the isolated worker process."""
    from detect_secrets.core.scan import _scan_line
    from detect_secrets.settings import default_settings, get_plugins
    from detect_secrets.util.code_snippet import get_code_snippet

    logger = logging.getLogger("detect-secrets")
    was_disabled = logger.disabled
    logger.disabled = True
    output: list[dict[str, Any]] = []
    try:
        with default_settings() as settings:
            # Public IPs are not credentials. Verification is opt-out in the
            # library, so remove the filter explicitly rather than relying on a
            # default that a dependency upgrade could change.
            settings.disable_plugins("IPPublicDetector")
            settings.disable_filters(_VERIFY_FILTER)
            for index, line in enumerate(texts[:MAX_UNITS]):
                context = get_code_snippet(lines=[line], line_number=1)
                detectors: set[str] = set()
                for plugin in get_plugins():
                    for secret in _scan_line(
                        plugin=plugin,
                        filename="in-memory",
                        line=line,
                        line_number=1,
                        context=context,
                    ):
                        value = secret.secret_value or ""
                        if _looks_like_placeholder(value):
                            continue
                        if secret.type in _GENERIC_DETECTORS and len(value) < 8:
                            continue
                        detectors.add(_safe_label(secret.type, "Potential secret"))
                if detectors:
                    # Prefer a provider/format-specific rule over entropy or a
                    # keyword match at the same structural location.
                    detector = min(
                        detectors,
                        key=lambda item: (item in _GENERIC_DETECTORS, item),
                    )
                    output.append({"unit": index, "detector": detector})
                    if len(output) >= min(max(0, max_matches), MAX_MATCHES):
                        break
    finally:
        logger.disabled = was_disabled
    return output


def _deny_network() -> None:
    """Defense in depth if a detector ever ignores the no-verification setting."""
    def blocked(*_args: Any, **_kwargs: Any) -> Any:
        raise OSError("network disabled for offline secret scan")

    socket.socket.connect = blocked  # type: ignore[method-assign,assignment]
    socket.socket.connect_ex = blocked  # type: ignore[method-assign,assignment]
    socket.create_connection = blocked  # type: ignore[assignment]


def _worker_main() -> int:
    _deny_network()
    try:
        raw = sys.stdin.buffer.read(MAX_TOTAL_BYTES * 6)
        payload = json.loads(raw)
        texts = payload.get("texts") if isinstance(payload, dict) else None
        if not isinstance(texts, list) or not all(isinstance(item, str) for item in texts):
            return 2
        requested = payload.get("max_matches", MAX_MATCHES)
        limit = requested if isinstance(requested, int) else MAX_MATCHES
        result = {"matches": _worker_scan(texts, limit)}
        sys.stdout.write(json.dumps(result, separators=(",", ":")))
        return 0
    except BaseException:  # never print candidate-bearing exception details
        return 1


if __name__ == "__main__":
    raise SystemExit(_worker_main() if "--worker" in sys.argv else 2)
