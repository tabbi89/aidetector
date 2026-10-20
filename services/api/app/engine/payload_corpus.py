"""Vendored payload corpus — the "ready dataset" source.

The curated in-code reflection library (``app/engine/payloads.py``) is small and
hand-authored. This module adds a second, larger source for it: raw attack
strings vendored offline under ``data/payloads/reflection.json`` (a curated
subset in the style of PayloadsAllTheThings / FuzzDB), normalised into the same
marker-carrying template shape the engine already uses.

Only the reflection library draws from here. The signature-injection classes
(``app/engine/signatures.py``) stay curated on purpose: their finding identity
keys on ``family``, so presence must be stable across the per-scan seed rotation,
which a rotating corpus cannot guarantee.

Two properties are load-bearing, both enforced here:

- **The ``aidx`` marker travels.** A raw dataset payload carries no marker, so we
  append ``aidx{m}`` — the exact token ``injection_probe`` substitutes a unique
  needle into. Reflection detection (``Attempt.reflected``) is therefore
  unchanged: the payload's own text is the prefix, the needle the suffix.
- **Every payload carries a neutralizable metacharacter.** A purely alphanumeric
  string would come back verbatim even from a *correctly* output-encoding target,
  which is a false positive. Requiring a metacharacter is what lets escaping
  break the ``prefix + needle`` match on a hardened target — the whole precision
  argument the reflection oracle rests on.

This module is pure (stdlib + JSON on disk, no SQLAlchemy) so it stays importable
from the pure policy tier under ``tests/test_layering.py``. Every failure path —
missing directory, unreadable file, malformed JSON, junk entries — degrades to an
empty corpus rather than raising, so a broken data file can never break the
engine's import or a scan. It returns raw template *strings* grouped by family;
``payloads.py`` and ``signatures.py`` build their own objects from them, so the
corpus depends on neither and there is no import cycle.
"""
from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

_DATA_DIR = Path(__file__).resolve().parent / "data" / "payloads"

#: Upper bounds. Per-scan request volume is unaffected (the injection checks draw
#: one payload per family per scan via ``rotating_set(..., per_family=1)``); these
#: only bound the rotation pool and keep the vendored files reviewable.
MAX_PER_FAMILY = 40
MAX_TEMPLATE_LEN = 256

#: The marker token ``injection_probe`` replaces with a per-request needle. A raw
#: payload that lacks it gets it appended, so the ``aidx<needle>`` reflection
#: contract holds for vendored entries exactly as for the curated library.
_MARKER = "aidx{m}"


def _has_metacharacter(raw: str) -> bool:
    """Whether ``raw`` contains a character output-encoding would neutralise.

    Anything that is not an ASCII letter, digit or space counts — quotes,
    angle brackets, slashes, percent-escapes, braces, semicolons. A string with
    none of these cannot distinguish a verbatim echo from a correctly escaped
    one, so it is dropped rather than shipped as a guaranteed false positive.
    """
    return any(not (c.isalnum() or c.isspace()) for c in raw)


def _has_control_char(raw: str) -> bool:
    """Whether ``raw`` contains a raw C0 control character (CR, LF, tab, NUL…).

    These cannot be placed into a request URL — httpx raises ``InvalidURL`` on a
    bare ``\\r`` or ``\\n`` — so a payload carrying one would crash the injection
    check for that point. CRLF/control probes belong percent-encoded (``%0d%0a``),
    which is printable and travels; a raw control character is dropped here so a
    data-file edit can never reintroduce that crash class.
    """
    return any(ord(c) < 0x20 for c in raw)


def _template(raw: str) -> str | None:
    """Normalise one raw payload into a marker-carrying template, or drop it."""
    if not isinstance(raw, str):
        return None
    if (
        not raw
        or len(raw) > MAX_TEMPLATE_LEN
        or _has_control_char(raw)
        or not _has_metacharacter(raw)
    ):
        return None
    if "{m}" in raw:
        # A bare ``{m}`` that is not the ``aidx{m}`` anchor substitutes to a
        # markerless token, so the reflection needle (``aidx<marker>``) never
        # appears and the payload is silently dead. Require the full anchor when
        # a marker is present; only append one when there is no marker at all.
        if _MARKER not in raw:
            return None
        template = raw
    else:
        template = raw + _MARKER
    # Guard the length again: the appended marker must not push us over the cap.
    return template if len(template) <= MAX_TEMPLATE_LEN + len(_MARKER) else None


def _load(filename: str, allowed: frozenset[str] | None) -> dict[str, list[str]]:
    """Read one corpus file into ``family -> [template, ...]``, degrading to {}.

    ``allowed`` (when given) restricts families to a known set so a typo in the
    data file cannot introduce an unrecognised family the engine has no home for.
    """
    path = _DATA_DIR / filename
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    if not isinstance(data, dict):
        return {}

    out: dict[str, list[str]] = {}
    for family, raws in data.items():
        if family.startswith("_") or not isinstance(raws, list):
            continue  # "_meta" and any non-list value are skipped
        if allowed is not None and family not in allowed:
            continue
        seen: set[str] = set()
        templates: list[str] = []
        for raw in raws:
            template = _template(raw)
            if template is None or template in seen:
                continue
            seen.add(template)
            templates.append(template)
            if len(templates) >= MAX_PER_FAMILY:
                break
        if templates:
            out[family] = templates
    return out


def sanitize_family_map(
    raw: object, allowed: frozenset[str] | None = None
) -> dict[str, list[str]]:
    """Normalise an untrusted ``{family: [payload, ...]}`` map into templates.

    The gate for AI-proposed payloads: it runs each candidate through the exact
    same :func:`_template` rules the vendored corpus obeys (marker present,
    metacharacter present, no control characters, length-capped, deduped,
    per-family cap) and drops the family entirely if it is unknown or empty. A
    malformed or hostile model response therefore degrades to fewer or zero
    variants — never to an unvalidated string reaching the target.
    """
    out: dict[str, list[str]] = {}
    if not isinstance(raw, dict):
        return out
    for family, items in raw.items():
        if allowed is not None and family not in allowed:
            continue
        if not isinstance(items, list):
            continue
        seen: set[str] = set()
        templates: list[str] = []
        for item in items:
            template = _template(item)
            if template is None or template in seen:
                continue
            seen.add(template)
            templates.append(template)
            if len(templates) >= MAX_PER_FAMILY:
                break
        if templates:
            out[family] = templates
    return out


@lru_cache(maxsize=1)
def reflection_templates(
    allowed: frozenset[str] | None = None,
) -> dict[str, list[str]]:
    """Vendored reflection templates by family (each carries ``aidx{m}``).

    Feeds ``reflected_injection`` via :class:`~app.engine.payloads.PayloadProvider`.
    The signature-injection classes deliberately do *not* draw from a corpus —
    their finding identity keys on ``family``, so presence must stay stable across
    seed rotation (see ``app/engine/signatures.py``).
    """
    return _load("reflection.json", allowed)
