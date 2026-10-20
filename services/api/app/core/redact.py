"""Redaction of secrets / PII from stored finding evidence and request traces.

Findings capture ``response_sample`` — up to 400 bytes of the target's actual
response — plus request values, and the run archive keeps a bounded sample of
every response body the probe saw. These are persisted to the DB, the run
snapshots, and the PDF report. Left raw, a scan can copy the target's own
secrets and users' PII straight into our datastore.

:class:`Redactor` masks three things, cheapest and most certain first:

- **Known secrets** — the decrypted credential values the scan itself sent. These
  are the highest-risk leak (our own request echoed back) and we know them
  exactly, so they are masked verbatim.
- **Sensitively named JSON fields** — when a body parses as JSON, the *field
  name* says what the value is far more reliably than the value's shape does.
  A bank routing number and an order number are both nine digits; only the key
  ``routing_number`` distinguishes them. :meth:`Redactor.body` uses this, over
  the shared vocabulary in ``app/domain/sensitive`` — the same names
  ``engine/exposure_policy`` reports on, so the two cannot drift apart.
- **Secret/PII-shaped strings** — JWTs, bearer/API tokens, emails, long
  hex/base64 blobs, national/tax IDs, payment cards, phones and dates — matched
  by pattern for values we don't know up front and for bodies that are not JSON.

The PII half exists because the request trace retains a sample of the target's
own response body. The scanner creates realistic-looking records (see
``engine/resource_bootstrap``) against APIs whose responses carry exactly these
shapes, so masking them is what keeps a scan from copying a customer record
into our datastore.

Applied centrally: in the runner as each ``EngineFinding`` is persisted, and in
``HttpProbe`` as each trace row is recorded — so no individual check has to
remember to sanitize.
"""
from __future__ import annotations

import json
import re
import threading
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import quote, quote_plus

from app.domain.sensitive import REPORTABLE, classify, is_sensitive

_MASK = "«redacted»"

#: Sensitive field names reported per body. Enough to characterise what an
#: endpoint exposes; not so many that one response fills the archive.
_MAX_REPORTED_FIELDS = 25


@dataclass(frozen=True)
class BodyScan:
    """A redacted body, and the reportable field names it was carrying.

    ``sensitive`` holds field *names* only — never a value, and never a sample
    of the body. It is the signal ``engine/checks/data_exposure`` grades.
    """

    text: str
    sensitive: list[str] = field(default_factory=list)

#: Payment card: 13-19 digits, optionally grouped. Matched loosely and then
#: filtered through Luhn, because without that check every long digit run — a
#: request id, an epoch in microseconds — would be masked as a card.
_CARD = re.compile(r"\b(?:\d[ -]?){12,18}\d\b")

# Order matters: longer/more-specific patterns first.
_PATTERNS: tuple[re.Pattern[str], ...] = (
    # JWT: three base64url segments.
    re.compile(r"\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\b"),
    # Authorization: Bearer/Basic <token>
    re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}"),
    # Emails.
    re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    # Long opaque hex/base64 blobs (api keys, session ids).
    re.compile(r"\b[A-Fa-f0-9]{32,}\b"),
    re.compile(r"\b[A-Za-z0-9_-]{40,}\b"),
    # ---- Personal identifiers, by shape ---------------------------------------
    # US national ID, dashed or spaced. A bare nine-digit run is deliberately
    # *not* matched here: unpunctuated, it is indistinguishable from an order
    # number, and masking every 9-digit integer would gut the trace. Field-name
    # redaction in :meth:`Redactor.body` is what catches those.
    re.compile(r"\b\d{3}[- ]\d{2}[- ]\d{4}\b"),
    # US employer/tax ID.
    re.compile(r"\b\d{2}-\d{7}\b"),
    _CARD,
    # Phone numbers in the shapes an API actually returns.
    re.compile(r"\+\d{1,3}[-. ]?\(?\d{2,4}\)?[-. ]?\d{3}[-. ]?\d{4}\b"),
    # No leading ``\b``: the boundary would have to sit between a space and an
    # opening paren, which are both non-word characters, so it never matches.
    re.compile(r"\(\d{3}\)[-. ]?\d{3}[-. ]?\d{4}\b"),
    # Bare ISO dates. Low value in a trace, high value to someone holding the
    # rest of a record.
    re.compile(r"\b(?:19|20)\d{2}-\d{2}-\d{2}\b"),
)

def _luhn(digits: str) -> bool:
    """Whether a digit run passes the Luhn checksum a real card number has."""
    total = 0
    for index, char in enumerate(reversed(digits)):
        value = int(char)
        if index % 2:
            value *= 2
            if value > 9:
                value -= 9
        total += value
    return total % 10 == 0


def _mask_card(match: re.Match[str]) -> str:
    """Mask a card-shaped digit run only when it checksums like a card."""
    return _MASK if _luhn(re.sub(r"[^0-9]", "", match.group(0))) else match.group(0)


def _spellings(secret: str) -> set[str]:
    """A secret as it may come back: verbatim, and percent-encoded.

    A key sent in the query string goes out encoded (``+/=`` become ``%2B%2F%3D``,
    common in base64 keys), and APIs echo request URLs back in pagination links
    and error pages — so the encoded spelling is masked as well.
    """
    return {secret, quote(secret, safe=""), quote_plus(secret)}


class Redactor:
    """Masks known secrets and secret-shaped strings in evidence values."""

    def __init__(self, secrets: list[str] | None = None) -> None:
        # Keep only non-trivial secrets; sort longest-first so a token that
        # contains a shorter one is masked whole.
        self._secrets = sorted(
            {
                form
                for s in (secrets or [])
                if s and len(s) >= 4
                for form in _spellings(s)
            },
            key=len,
            reverse=True,
        )
        self._lock = threading.Lock()

    def add_secret(self, secret: str) -> None:
        """Teach a live redactor about a token minted or refreshed mid-run."""
        if not secret or len(secret) < 4:
            return
        with self._lock:
            for form in _spellings(secret):
                if form not in self._secrets:
                    self._secrets.append(form)
            self._secrets.sort(key=len, reverse=True)

    def text(self, value: str) -> str:
        with self._lock:
            secrets = tuple(self._secrets)
        for secret in secrets:
            if secret in value:
                value = value.replace(secret, _MASK)
        for pat in _PATTERNS:
            value = pat.sub(_mask_card if pat is _CARD else _MASK, value)
        return value

    def value(self, value: Any) -> Any:
        """Redact recursively through strings, dicts, and lists."""
        if isinstance(value, str):
            return self.text(value)
        if isinstance(value, dict):
            return {k: self.value(v) for k, v in value.items()}
        if isinstance(value, list):
            return [self.value(v) for v in value]
        return value

    def evidence(self, evidence: dict[str, Any]) -> dict[str, Any]:
        return {k: self.value(v) for k, v in evidence.items()}

    # ---- Bodies ---------------------------------------------------------------

    def fields(self, value: Any, seen: list[str] | None = None) -> Any:
        """Redact by *field name* through a parsed JSON structure.

        A sensitively named field has its whole value replaced, however deep and
        whatever its type — a nested ``owner.ssn`` object, a list of accounts,
        an integer routing number. Every other value still goes through
        :meth:`value`, so a secret in an innocuously named field is caught too.

        ``seen`` collects the *reportable* names encountered, which is how
        detection rides along with redaction — see :meth:`scan_body`.
        """
        if isinstance(value, dict):
            out: dict[str, Any] = {}
            for key, item in value.items():
                if seen is not None and classify(key, categories=REPORTABLE):
                    seen.append(str(key)[:80])
                if is_sensitive(key):
                    out[key] = _MASK
                else:
                    out[key] = self.fields(item, seen)
            return out
        if isinstance(value, list):
            return [self.fields(item, seen) for item in value]
        return self.value(value)

    def scan_body(self, raw: str) -> BodyScan:
        """Redact a body and report the sensitive field names it carried.

        The report is the point: walking the body to mask it already answers
        "does this response expose credentials or government identifiers", and
        that answer used to be thrown away. Returning it lets ``data_exposure``
        see *every* response the scan made rather than the forty the header
        sweep re-probes — at no extra request, and **without retaining a single
        value**: names only, the same rule that check has always followed.

        Detection is deliberately independent of retention. A caller that drops
        the text (a body past the run's budget) still gets the field names, so
        the archive's size limits cannot create a blind spot.

        Falls back to pattern-only redaction for anything that does not parse —
        HTML error pages, plain text, truncated JSON. Never raises: a body is
        untrusted input and redaction must not be the thing that fails a scan.
        """
        try:
            parsed = json.loads(raw)
        except (TypeError, ValueError, RecursionError):
            return BodyScan(self.text(raw))
        seen: list[str] = []
        try:
            masked = self.fields(parsed, seen)
            text = json.dumps(masked, separators=(",", ":"), ensure_ascii=False)
        except (TypeError, ValueError, RecursionError):
            return BodyScan(self.text(raw))
        # Deduplicated, order preserved, bounded: a 400-field response must not
        # put 400 names in the archive.
        unique = list(dict.fromkeys(seen))[:_MAX_REPORTED_FIELDS]
        return BodyScan(text, unique)

    def body(self, raw: str) -> str:
        """Just the redacted text — :meth:`scan_body` without the report."""
        return self.scan_body(raw).text
