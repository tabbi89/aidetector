"""Server-Side Request Forgery (API7) — url-like params probed with internal targets.

Conservative, and the code has to earn that word: a url-named parameter existing
is not a finding. Two outcomes are reported —

- the injected internal marker comes back (*medium*): the value was consumed,
- the target **accepted** the internal URL without complaint (*low*): a blind
  SSRF is possible. This is only reported when an out-of-band collector is
  configured (``ctx.oob.active``), because without one a silent 200 is
  indistinguishable from a URL-storing endpoint that never fetches — and it is
  exactly the case ``oob_injection`` confirms.

A target that **rejects** the internal URL (>= 400) with no reflection is
declining to fetch it, which is exactly the correct behaviour. Reporting that as
an "SSRF candidate" flagged every hardened endpoint that validates its input,
which is the opposite of what this check is for.

Sinks: query params on any operation (always — reads), and JSON body fields on
POST/PUT/PATCH under ``mutate: true`` — many real SSRF sinks are body fields
(webhook registration URLs, return_url, fetch-on-create), and writing a body
changes target state, so it shares the write oracle's opt-in.
"""
from __future__ import annotations

from app.domain.enums import Severity
from app.engine.base import EngineFinding, ScanContext, method_is_allowed, render_path
from app.engine.param_hints import is_urlish
from app.engine.resource_map import path_values
from app.engine.spec_values import base_value

_MUTATING = ("POST", "PUT", "PATCH")
_INTERNAL_MARKER = "http://169.254.169.254/latest/meta-data/aidetector"


def _candidates(op, allow_mutation: bool) -> list[tuple[str, str]]:
    """(param name, location) pairs this operation offers as SSRF sinks."""
    out: list[tuple[str, str]] = []
    if method_is_allowed(op.method, allow_mutation=allow_mutation):
        out = [(p, "query") for p in op.query_params if is_urlish(p)]
    if op.method in _MUTATING and allow_mutation:
        out += [(p, "body") for p in op.body_params if is_urlish(p)]
    return out


class SsrfCheck:
    key = "ssrf"

    @staticmethod
    def inapplicable(ctx: ScanContext) -> str | None:
        """Needs a parameter that plausibly takes a URL."""
        if any(_candidates(op, ctx.allow_mutation) for op in ctx.operations):
            return None
        return (
            "no url-shaped parameter in the spec — SSRF needs somewhere to put "
            "a URL"
        )

    def run(self, ctx: ScanContext) -> list[EngineFinding]:
        headers = ctx.primary_headers()
        findings: list[EngineFinding] = []

        for op in ctx.operations:
            candidates = _candidates(op, ctx.allow_mutation)
            if not candidates:
                continue
            path = render_path(op.path, path_values(op, ctx.resource_ids))
            for name, location in candidates:
                if location == "query":
                    r = ctx.probe.send(
                        op.method, path, headers=headers, params={name: _INTERNAL_MARKER}
                    )
                else:
                    body = {
                        p["name"]: base_value(p.get("schema") or {})
                        for p in op.params
                        if p.get("in") == "body" and p.get("required") and p.get("name") != name
                    }
                    body[name] = _INTERNAL_MARKER
                    r = ctx.probe.send(op.method, path, headers=headers, json=body)
                if r is None:
                    continue
                # Only the exact internal marker counts as "consumed". The looser
                # "meta-data" substring used to fire on any response that merely
                # mentioned the AWS metadata service (docs, an error page), so it
                # was dropped: the marker is what ties the reflection to *this*
                # payload.
                reflected = _INTERNAL_MARKER in r.text
                if not reflected and r.status >= 400:
                    # The target refused the internal URL. No evidence remains.
                    continue
                if not reflected and not getattr(ctx.oob, "active", False):
                    # Accepted without complaint, but with no OAST collector the
                    # check cannot tell "silently fetched it" from "stored it and
                    # ignored it" — both return 200. Reporting it here flagged
                    # every url-shaped parameter of a URL-storing API, so the
                    # confirmation is left to oob_injection, which only runs once
                    # a collector is configured.
                    continue
                title = (
                    f"SSRF candidate via '{name}' on {op.method} {op.path}"
                    if location == "query"
                    else f"SSRF candidate via body '{name}' on {op.method} {op.path}"
                )
                findings.append(
                    EngineFinding(
                        check=self.key,
                        owasp_id="API7:2023",
                        severity=Severity.medium if reflected else Severity.low,
                        title=title,
                        description=(
                            f"The '{name}' {location} parameter accepts a URL and may "
                            "cause the server to fetch attacker-controlled hosts (SSRF). "
                            + ("The internal marker was reflected. "
                               if reflected else "Confirmation needs an out-of-band callback. ")
                        ),
                        evidence={
                            "path": path,
                            "route": op.path,
                            "param": name,
                            "location": location,
                            "injected": _INTERNAL_MARKER,
                            "reflected": reflected,
                            "status": r.status,
                        },
                        operation_id=op.id,
                    )
                )
        return findings
