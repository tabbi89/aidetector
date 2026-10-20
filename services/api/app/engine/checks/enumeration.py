"""Enumeration and rate-limit oracles — business-logic signals that need no
second identity.

Two probes, both deliberately small and bounded:

- **Missing rate limiting** (API4, low) — a short burst of identical requests
  at authentication-shaped endpoints (login/token/password/reset paths). If
  the burst mostly succeeds and nothing throttles (429), no rate limiting is
  observable from the outside. Read-friendly: candidates are chosen by path,
  and requests carry the scan's own credential.
- **Duplicate-create oracle** (API2, medium, mutate-only) — creates the same
  object twice with a unique natural-key value (email/imei/username-ish field).
  If the second attempt is rejected with a conflict-style response while the
  first succeeded, the API reveals whether a given identifier already exists
  — an account/record enumeration oracle (the pattern "second signup with the
  same email → 409"). The duplicate rejection is the signal; no data is
  harvested. Gated behind ``mutate: true`` because it creates an object.
"""
from __future__ import annotations

import re
import uuid

from app.domain.enums import Confidence, Severity
from app.engine.base import EngineFinding, ScanContext, method_is_allowed, render_path
from app.engine.resource_map import path_values
from app.engine.spec_values import base_value

_RATE_HINTS = re.compile(
    r"login|signin|sign-in|token|password|passwd|otp|reset|auth", re.I
)
_BURST = 6
_MAX_RATE_OPS = 2
_MAX_CREATE_OPS = 2
_MUTATING = ("POST", "PUT", "PATCH")
_NATURAL_KEY = re.compile(r"email|username|login|imei|phone|slug|user", re.I)
_DUPLICATE_BODY = re.compile(r"exist|duplicate|already|taken|in use", re.I)


class EnumerationCheck:
    key = "enumeration"

    def run(self, ctx: ScanContext) -> list[EngineFinding]:
        findings: list[EngineFinding] = []
        findings.extend(self._rate_limit(ctx))
        if ctx.allow_mutation:
            findings.extend(self._duplicate_create(ctx))
        return findings

    def _rate_limit(self, ctx: ScanContext) -> list[EngineFinding]:
        headers = ctx.primary_headers()
        candidates = [
            op for op in ctx.operations
            if _RATE_HINTS.search(op.path)
            and method_is_allowed(op.method, allow_mutation=ctx.allow_mutation)
        ][:_MAX_RATE_OPS]
        findings: list[EngineFinding] = []

        for op in candidates:
            url = render_path(op.path, path_values(op, ctx.resource_ids))
            params = {
                p["name"]: base_value(p.get("schema") or {})
                for p in op.params
                if p.get("in") == "query" and p.get("required")
            } or None
            body = None
            if op.method in _MUTATING and op.body_params:
                body = {
                    p["name"]: base_value(p.get("schema") or {})
                    for p in op.params
                    if p.get("in") == "body" and p.get("required")
                }
            statuses: list[int] = []
            throttled = False
            for _ in range(_BURST):
                r = ctx.probe.send(op.method, url, headers=headers, params=params, json=body)
                if r is None:
                    return findings  # budget spent
                statuses.append(r.status)
                throttled = throttled or r.was_throttled

            succeeded = sum(1 for s in statuses if s < 400)
            if throttled or succeeded * 2 < len(statuses):
                continue  # throttled, or the endpoint mostly rejects: no oracle
            findings.append(
                EngineFinding(
                    check=self.key,
                    confidence=Confidence.heuristic,
                    owasp_id="API4:2023",
                    severity=Severity.low,
                    title=f"No rate limiting observed on {op.method} {op.path}",
                    description=(
                        f"{_BURST} identical requests in quick succession all succeeded "
                        "without a throttle (429) response. Without rate limiting, "
                        "authentication-shaped endpoints are exposed to brute force, "
                        "credential stuffing, and enumeration at machine speed."
                    ),
                    evidence={
                        "method": op.method,
                        "path": op.path,
                        "requests": _BURST,
                        "statuses": statuses,
                    },
                    operation_id=op.id,
                )
            )
        return findings

    def _duplicate_create(self, ctx: ScanContext) -> list[EngineFinding]:
        headers = ctx.primary_headers()
        creates = [
            op for op in ctx.operations
            if op.method == "POST" and not op.path.rstrip("/").endswith("}")
            and op.body_params
        ][:_MAX_CREATE_OPS]
        findings: list[EngineFinding] = []

        for op in creates:
            body_params = [p for p in op.params if p.get("in") == "body" and p.get("name")]
            key = next(
                (p for p in body_params if _NATURAL_KEY.search(p["name"])),
                body_params[0],
            )
            token = uuid.uuid4().hex[:10]
            value = (
                f"aidx{token}@example.test"
                if "mail" in key["name"].lower()
                else f"aidx{token}"
            )
            body = {
                p["name"]: base_value(p.get("schema") or {})
                for p in body_params
                if p.get("required") and p["name"] != key["name"]
            }
            body[key["name"]] = value
            url = render_path(op.path, path_values(op, ctx.resource_ids))

            r1 = ctx.probe.send(op.method, url, headers=headers, json=body)
            if r1 is None:
                break
            if r1.status >= 400:
                continue  # the create itself failed: no oracle to test
            r2 = ctx.probe.send(op.method, url, headers=headers, json=body)
            if r2 is None:
                break
            duplicate = r2.status == 409 or (
                r2.status >= 400 and _DUPLICATE_BODY.search(r2.text or "")
            )
            if not duplicate:
                continue
            findings.append(
                EngineFinding(
                    check=self.key,
                    confidence=Confidence.verified,
                    owasp_id="API2:2023",
                    severity=Severity.medium,
                    title=f"Duplicate-create oracle on POST {op.path} ('{key['name']}')",
                    description=(
                        f"Creating the same object twice is answered differently: the "
                        f"first attempt returned {r1.status}, the identical second "
                        f"attempt {r2.status}. The distinct rejection reveals whether "
                        f"a given '{key['name']}' value already exists, which turns "
                        "the endpoint into an account/record enumeration oracle."
                    ),
                    evidence={
                        "method": op.method,
                        "path": op.path,
                        "field": key["name"],
                        "value": value,
                        "first_status": r1.status,
                        "second_status": r2.status,
                        "second_sample": (r2.text or "")[:400],
                    },
                    operation_id=op.id,
                )
            )
        return findings
