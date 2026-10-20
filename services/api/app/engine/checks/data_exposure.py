"""Excessive data exposure (OWASP API3): what responses give away.

The check only a spec-driven scanner can do well. Every other check here asks
"can I make the target misbehave"; this one asks "what does the target hand back
when it behaves perfectly" — and answers it by reading the responses the header
sweep already collected, against the response schema the spec already declares.

Two signals, deliberately different tiers:

- **Sensitive field names** — a response carrying `password_hash`, `ssn`,
  `access_token`… is over-exposing regardless of what the schema says. The field
  is *there*, so this is **verified**: no exploitation step is missing.
- **Undeclared fields** — returned but absent from the declared 2xx schema. That
  is spec drift, and drift is a lead, not a bug: the API may be exposing fields
  nobody reviewed, or the spec may simply be stale. **Heuristic**, low.

Costs no requests of its own, and reads **two** free corpora:

- the **header sweep** (`sweep_headers`, memoised on the context), which gives
  the same GET the header checks did — with the whole body, so it can compare
  against the declared schema and report drift;
- the **request trace** (`probe.mutations`), which is every call the scan made.
  The sweep is structurally narrow — GET/HEAD only, capped at
  `MAX_HEADER_ENDPOINTS`, one identity, spec operations only — so on its own it
  cannot see a create that echoes a token back, a 5xx carrying internal state,
  the second identity's view, an endpoint past the cap, or a shadow path
  discovery found. The trace sees all of them, because some other check already
  requested them. Trace rows carry sensitive field *names* only (recorded during
  redaction, `core/redact.py:Redactor.scan_body`), so they feed the
  sensitive-name half; drift needs the full field list and stays with the sweep.

Operations with no declared response schema still get the sensitive-name half;
absence of a contract is not evidence of drift.

**Only field names leave this check.** Never a value, never a body sample — the
same rule that keeps cookie values out of `security_headers` findings, and for
the same reason: a findings table is not a place to accumulate customer data.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from app.domain.enums import Confidence, Severity
from app.engine.base import EngineFinding, HeaderSnapshot, ScanContext
from app.engine.checks.misconfig import sweep_headers
from app.engine.exposure_policy import (
    ExposedField,
    ExposureIssue,
    field_names_truncated,
    sensitive_issues,
    undeclared_issue,
)
from app.specs.parser import declared_response_field_paths

# Field names listed in a finding before the evidence is truncated.
_MAX_LISTED = 25
# Endpoints listed per grouped finding.
_MAX_ENDPOINTS = 20


def _decode(snapshot: HeaderSnapshot) -> Any | None:
    """The snapshot's body as JSON, or None when it is not JSON we can read.

    A truncated body is usually invalid JSON, which is the honest outcome: a
    response too large for the sample is one we decline to report on rather than
    guess at.
    """
    content_type = ""
    for name, value in snapshot.headers.items():
        if name.lower() == "content-type":
            content_type = str(value).lower()
            break
    if "json" not in content_type:
        return None
    body = snapshot.body.strip()
    if not body:
        return None
    try:
        return json.loads(body)
    except (ValueError, RecursionError):
        return None


@dataclass(frozen=True)
class Observation:
    """One endpoint's response, from whichever corpus saw it.

    The sweep and the trace describe an endpoint differently — the sweep knows
    the operation it probed and the rendered path, the trace knows the route
    template and which identity asked. This is what both reduce to so a finding
    can group them together.
    """

    label: str
    method: str
    #: The route to name in remediation — a spec template where one is known.
    route: str
    #: What was actually requested, for reproduction.
    probed_path: str
    operation_id: str | None
    #: Identity whose credentials saw this response, when known.
    identity: str = ""

    @staticmethod
    def from_snapshot(snapshot: HeaderSnapshot, templates: dict[str, str]) -> Observation:
        return Observation(
            label=snapshot.label,
            method=snapshot.method,
            route=templates.get(snapshot.operation_id or "", snapshot.path),
            probed_path=snapshot.path,
            operation_id=snapshot.operation_id,
        )


class DataExposureCheck:
    """Reads response bodies for over-exposure and spec drift (API3)."""

    key = "data_exposure"

    def run(self, ctx: ScanContext) -> list[EngineFinding]:
        # (issue key, label, severity, why, fields) → the endpoints sharing it.
        groups: dict[tuple[str, str, Severity, str, tuple[str, ...]], list[Observation]] = {}
        # Which groups had at least one response body cut short by a walk bound.
        truncated: dict[tuple[str, str, Severity, str, tuple[str, ...]], bool] = {}
        # Operation id → spec path template. The sweep records a *rendered* path
        # (`/users/1`); remediation should name the route a handler is written
        # against (`/users/{user_id}`), so both are kept.
        templates = {op.id: op.path for op in ctx.operations if op.id}
        op_by_id = {op.id: op for op in ctx.operations if op.id}

        def add(issue: ExposureIssue, where: Observation, *, was_truncated: bool = False) -> None:
            key = (issue.key, issue.label, issue.severity, issue.why, issue.fields)
            bucket = groups.setdefault(key, [])
            # One endpoint can be seen by both corpora; report it once.
            if not any(w.label == where.label for w in bucket):
                bucket.append(where)
            if was_truncated:
                truncated[key] = True

        for snapshot in sweep_headers(ctx):
            if not 200 <= snapshot.status < 300:
                continue
            payload = _decode(snapshot)
            if payload is None:
                continue
            fields, was_truncated = field_names_truncated(payload)
            if not fields:
                continue

            issues: list[ExposureIssue] = list(sensitive_issues(fields))
            drift = undeclared_issue(fields, self._declared(ctx, op_by_id, snapshot))
            if drift is not None:
                issues.append(drift)

            where = Observation.from_snapshot(snapshot, templates)
            for issue in issues:
                add(issue, where, was_truncated=was_truncated)

        for where, names in self._traced(ctx):
            # The trace records names, not a body, so only the sensitive half
            # applies — drift needs the fields the response *did not* carry.
            for issue in sensitive_issues([ExposedField(name, "") for name in names]):
                add(issue, where)

        findings: list[EngineFinding] = []
        for key, seen in groups.items():
            issue_key, label, severity, why, issue_fields = key
            findings.append(
                self._finding(
                    issue_key, label, severity, why, issue_fields, seen,
                    truncated=truncated.get(key, False),
                )
            )
        return findings

    def _traced(self, ctx: ScanContext) -> list[tuple[Observation, list[str]]]:
        """Sensitive field names every recorded call saw, with where it saw them.

        Reads ``probe.mutations`` — the run's request trace — so an endpoint any
        check happened to touch is covered whether or not the sweep reached it.
        Rows whose response carried nothing sensitive are skipped, which is the
        overwhelming majority.
        """
        by_route = {(op.method.upper(), op.path): op for op in ctx.operations}
        out: list[tuple[Observation, list[str]]] = []
        for row in getattr(ctx.probe, "mutations", []):
            names = (row.get("response") or {}).get("sensitive_fields") or []
            if not names:
                continue
            method = str(row.get("method", ""))
            route = str(row.get("route", ""))
            op = by_route.get((method.upper(), route))
            identity = str(row.get("identity", ""))
            out.append(
                (
                    Observation(
                        label=f"{method} {route}",
                        method=method,
                        route=route,
                        probed_path=route,
                        operation_id=op.id if op is not None else None,
                        identity=identity,
                    ),
                    [str(n) for n in names],
                )
            )
        return out

    def _declared(
        self, ctx: ScanContext, op_by_id: dict[str, Any], snapshot: HeaderSnapshot
    ) -> set[str] | None:
        """The operation's declared 2xx response fields, or None.

        The snapshot carries a *rendered* path (`/accounts/1`), so the spec is
        looked up through the operation the sweep recorded it against.
        """
        if ctx.spec is None or snapshot.operation_id is None:
            return None
        op = op_by_id.get(snapshot.operation_id)
        if op is None:
            return None
        try:
            return declared_response_field_paths(ctx.spec, op.method, op.path)
        except Exception:  # noqa: BLE001 — a malformed spec must not fail a scan
            return None

    def _finding(
        self,
        issue_key: str,
        label: str,
        severity: Severity,
        why: str,
        fields: tuple[str, ...],
        seen: list[Observation],
        *,
        truncated: bool = False,
    ) -> EngineFinding:
        drift = issue_key == "undeclared"
        listed = ", ".join(f"'{f}'" for f in fields[:_MAX_LISTED])
        more = len(fields) - _MAX_LISTED
        if more > 0:
            listed += f" (+{more} more)"

        scope = seen[0].label if len(seen) == 1 else f"{len(seen)} endpoints"
        title = (
            f"Undeclared response fields on {scope}"
            if drift
            else f"Response exposes {label} on {scope}"
        )
        description = (
            f"{'Fields not in the declared response schema' if drift else 'Fields'} "
            f"returned by {scope}: {listed}. {why}"
            + (
                ""
                if drift
                else " Only the field names are reported here — this scanner "
                "never records the values."
            )
        )
        evidence: dict[str, Any] = {
            "issue": issue_key,
            "fields": list(fields[:_MAX_LISTED]),
            "field_count": len(fields),
            "endpoints": [s.label for s in seen[:_MAX_ENDPOINTS]],
            "endpoint_count": len(seen),
            # The route (spec template) for remediation, and what was
            # actually requested for reproduction.
            "path": seen[0].route,
            "probed_path": seen[0].probed_path,
            "method": seen[0].method,
            # Which identities saw it, when the trace supplied the row. An
            # exposure only the privileged identity sees is a different
            # problem from one an anonymous caller sees.
            "identities": sorted({s.identity for s in seen if s.identity}),
        }
        if truncated:
            # A depth/width/field bound cut one response short: what is listed
            # may be incomplete, not a clean answer.
            evidence["truncated"] = True
        return EngineFinding(
            check=self.key,
            owasp_id="API3:2023",
            severity=severity,
            # A sensitive field is *present* in the response — nothing is
            # inferred. Drift is a lead: the spec may simply be stale.
            confidence=Confidence.heuristic if drift else Confidence.verified,
            title=title[:255],
            description=description,
            evidence=evidence,
            operation_id=seen[0].operation_id if len(seen) == 1 else None,
        )
