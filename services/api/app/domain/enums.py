"""The vocabulary a finding is described in: severity, evidence tier, verdict.

These are product concepts, not database column types. They were declared inside
``app/models/finding.py``, so every pure decision module that needed the word
"critical" — ``header_policy``, ``exposure_policy``, ``kali``, ``signatures``,
every check — imported SQLAlchemy and evaluated the declarative ``Base``
registry to get it. The arrow ran from policy to persistence, which is backwards,
and it put a schema migration and a severity-scoring rule in the same file.

They live here instead, and ``models/finding.py`` maps its columns onto them.
Nothing in this module may import SQLAlchemy, FastAPI, ``app.engine`` or
``app.models``.
"""
from __future__ import annotations

import enum


class Severity(str, enum.Enum):
    """How bad the weakness is *if real*. Orthogonal to :class:`Confidence`."""

    info = "info"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class Verdict(str, enum.Enum):
    unreviewed = "unreviewed"   # engine-only, not yet adjudicated
    confirmed = "confirmed"
    dismissed = "dismissed"     # false positive


class Confidence(str, enum.Enum):
    """How strongly a finding's evidence supports the claim the finding makes.

    The evidence-tier vocabulary the product already uses in prose — the
    coverage page, the landing page and every check docstring — promoted to
    data, so consumers can act on it rather than re-read it: SARIF levels,
    report grouping, and a CI gate that blocks a build on verified findings
    only. Severity says *how bad if real*; confidence says *how sure we are*.

    ``heuristic`` is the deliberate default everywhere. A site that forgets to
    grade itself understates its own evidence, which is the safe direction for
    a scanner: it never promotes a lead to a confirmation by omission.
    """

    # A lead. The signal proves input reached the response (or that a tool
    # reported a match), not that the weakness is exploitable. Confirm by hand.
    heuristic = "heuristic"
    # The collected evidence demonstrates the weakness directly — a
    # cross-identity read/write that persisted, an out-of-band callback, a
    # forged token that was accepted, an inspected certificate or header.
    verified = "verified"


#: Rank for sorting most-severe-first.
SEVERITY_RANK = {
    Severity.critical: 4,
    Severity.high: 3,
    Severity.medium: 2,
    Severity.low: 1,
    Severity.info: 0,
}

#: Rank for sorting proof ahead of leads within one severity.
CONFIDENCE_RANK = {
    Confidence.verified: 1,
    Confidence.heuristic: 0,
}


class AuthType(str, enum.Enum):
    bearer = "bearer"          # Authorization: Bearer <token>
    header = "header"          # arbitrary header, value is the secret
    api_key = "api_key"        # X-API-Key style
    basic = "basic"            # user:pass
    query = "query"            # ?<header_name>=<secret> — a key in the query string
    cookie = "cookie"          # Cookie: <header_name>=<secret>
    none = "none"


class GrantType(str, enum.Enum):
    """How a credential obtains the token it authenticates with.

    ``static`` is the original behaviour: the stored secret *is* the token/value
    sent on every request. The others mint a fresh token at scan time by calling
    the target's own auth endpoint, so a scan (especially a scheduled one) never
    carries a token that has since expired — and the scanner can test an API
    whose tokens are short-lived by design.
    """

    static = "static"
    client_credentials = "client_credentials"   # OAuth2 client_credentials grant
    password = "password"                        # OAuth2 resource-owner password
    cookie = "cookie"                            # form/JSON login → Set-Cookie
