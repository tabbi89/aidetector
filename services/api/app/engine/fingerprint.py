"""Stable identity for a finding, so the same problem is recognisable across runs.

Re-running a scan replaces its findings, so without an identity every run is a
fresh list of strangers: nothing can say "this BOLA is the one you saw last
week", a dismissed false positive comes back unreviewed, and a diff is
impossible. A fingerprint is that identity.

What it must do, and the tension between them:

- **Survive a re-run that changed nothing.** So it is built from the parts of a
  finding that describe *what and where*, never from parts that drift — no
  counts, no status codes, no harvested object ids, no timestamps, no payload
  (payloads rotate per run by design, see ``engine/payloads.py``).
- **Separate findings a human would call different.** A reflected lead on `q` is
  not the one on `name`; a missing CSP is not a missing HSTS.

Identity comes from a small, ordered set of evidence keys — the ones that name
the endpoint, the parameter, the field or the issue. Checks whose evidence
carries none of them (``tls_config``) fall back to the title, which for those
checks is itself descriptive and stable.

**Changing what goes into a fingerprint is a compatibility change.** Every
stored fingerprint is invalidated by it: carried triage stops matching and the
next diff reports the whole affected set as fixed-and-new, once. That is
recoverable (re-triage, and the run after settles) but it is not free — so
change ``DEFAULT_KEYS`` or ``IDENTITY_KEYS`` deliberately, and prefer adding a
per-check override to widening the default.

Pure — no I/O. ``run_record.append_finding`` stamps every finding as it is
recorded.
"""
from __future__ import annotations

import hashlib
import re
from typing import Any

from app.domain.taxonomy import fingerprint_taxonomy_id

#: Evidence keys that name *what and where*, in a fixed order so the same
#: finding hashes identically whatever order the check built its evidence in.
DEFAULT_KEYS: tuple[str, ...] = (
    "method",
    "route",
    "path",
    "param",
    "location",
    "family",
    "field",
    "issue",
    "kind",
    "bypass_class",
    "write",
    "read_back",
)

#: A trailing line index in a ``location`` value. ``potential_secrets`` records
#: the structural path plus a line number (``json/object[3]/text-line-2``); the
#: line number is where the secret happened to sit, not what the weakness is, so
#: it must not be part of identity — a secret that moves one line on an unrelated
#: edit would otherwise report the same finding as new.
_LINE_INDEX = re.compile(r"(?:text-line|line)-\d+$")

#: Checks whose identity is not "an endpoint and a parameter". The header sweep
#: already collapses endpoints into one finding per issue profile, so *which
#: headers* is the whole identity: two findings in one run cannot share a
#: profile, so the endpoint list is not needed to tell them apart — and
#: including it only adds churn, because putting one endpoint back in scope
#: would report the same missing CSP as fixed-and-new. (A real re-scoped run did
#: exactly that before this was narrowed.) The counts in the title move for the
#: same reason and stay out too.
IDENTITY_KEYS: dict[str, tuple[str, ...]] = {
    "security_headers": ("missing", "weak"),
    "info_disclosure": ("headers",),
    "data_exposure": ("issue", "path"),
    # Candidate values are deliberately discarded and may rotate independently
    # of the disclosure. The source, route and structural location identify the
    # weakness without retaining a secret-derived value or hash.
    "potential_secrets": ("source", "method", "route", "detector", "location"),
    # Generated inputs and observed response values vary between runs. Contract
    # drift is the same finding when its rule and structural response location
    # remain the same; a schema mismatch is distinct from an undocumented
    # status on the same route.
    "schema_fuzz": ("method", "route", "rule", "location"),
    # Deliberately *without* ``family``. A reflection lead says "input reaches
    # the response through this parameter"; which payload family happened to
    # carry the marker is a property of the run, not of the weakness — payloads
    # rotate per scan by design, so including it would report the same lead as
    # fixed-and-new on every run. The families that *are* identity keep it:
    # ``signature_injection`` names the backend interpreter that errored, and
    # ``oob_injection`` distinguishes a confirmed blind SSRF from a confirmed
    # RCE — different vulnerabilities, not different payloads.
    "reflected_injection": ("method", "route", "param", "location"),
    # ZAP is not tied to a spec operation, so the alert's own name, location and
    # affected parameter are its whole identity. ``url``, ``attack`` and
    # ``evidence`` are deliberately excluded: ZAP's active scanner reports the
    # attacked URL *with the payload in the query string*, and the payload
    # rotates, so any of the three would report the same alert as fixed-and-new
    # every run. ``location`` is that URL with the query stripped
    # (``zap.alert_location``) — where the alert is, not what was sent.
    "zap": ("name", "param", "location", "plugin_id"),
}

# These checks already emitted dated OWASP labels before the taxonomy cleanup.
# Their stored fingerprints therefore contain the suffix; the older checks do
# not. Preserve each check's historical spelling while the public output moves
# to one canonical form.
_LEGACY_DATED_API_CHECKS = frozenset(
    {
        "design_review",
        "graphql_behavior",
        "graphql_introspection",
        "grpc_reflection",
        "host_header",
        "request_smuggling",
    }
)


def _canonical(value: Any) -> str:
    """One evidence value as a stable string.

    Dicts contribute their *keys* only (a header name is identity; the observed
    value that made it weak is not — a CSP that changes from one permissive
    value to another is the same finding). Lists are sorted, so an ordering
    difference between runs cannot look like a new finding.
    """
    if isinstance(value, dict):
        return ",".join(sorted(str(k) for k in value))
    if isinstance(value, list | tuple | set):
        return ",".join(sorted(str(v) for v in value))
    if isinstance(value, bool):
        return str(value).lower()
    return str(value).strip()


def identity_parts(
    check: str, owasp_id: str | None, title: str, evidence: dict[str, Any] | None
) -> list[str]:
    """The ordered strings a fingerprint is built from. Exposed for testing."""
    parts = [
        check,
        fingerprint_taxonomy_id(
            owasp_id, dated_api=check in _LEGACY_DATED_API_CHECKS
        ),
    ]
    keys = IDENTITY_KEYS.get(check, DEFAULT_KEYS)
    if (evidence or {}).get("route"):
        # The injection checks record both the attacked URL and the route it
        # came from. The URL carries the payload — which rotates every run — so
        # once a route is available it is the only one that can be identity.
        keys = tuple(k for k in keys if k != "path")
    used = False
    for key in keys:
        value = (evidence or {}).get(key)
        if value is None or value == "" or value == [] or value == {}:
            continue
        if key == "location" and isinstance(value, str):
            # A trailing line index is where the secret sat, not what it is.
            value = _LINE_INDEX.sub("", value)
            if not value:
                continue
        parts.append(f"{key}={_canonical(value)}")
        used = True
    if not used:
        # No identity-bearing evidence: the title is what distinguishes these.
        parts.append(f"title={title.strip()}")
    return parts


def fingerprint(
    check: str,
    owasp_id: str | None,
    title: str,
    evidence: dict[str, Any] | None = None,
) -> str:
    """A stable 32-hex-character identity for one finding.

    Truncated SHA-256 — this is a lookup key for matching a finding to its past
    self, not a security boundary, and 128 bits is far past collision concern
    for the number of findings one scan produces.
    """
    joined = "\x1f".join(identity_parts(check, owasp_id, title, evidence))
    return hashlib.sha256(joined.encode("utf-8", "replace")).hexdigest()[:32]
