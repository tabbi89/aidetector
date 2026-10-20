"""Unrestricted access to sensitive business flows (API6).

BOLA, BOPLA and race conditions are object- and field-level weaknesses. API6 is
about a *flow*: a checkout, a signup, a coupon redemption, an invite — a
sequence the business assumes a human drives at human speed, exposed to a script
that drives it at machine speed. The abuse is not reading someone else's object;
it is buying out the inventory, farming every coupon, or manufacturing referral
credit, all with perfectly authorized requests.

From the outside the observable question is: can this flow be replayed rapidly
with no anti-automation control in the way? This probe drives a bounded,
identical-body burst at business-flow-shaped endpoints and flags one where every
attempt succeeds with no throttle (429) and no anti-automation signal
(a CAPTCHA/challenge, an idempotency requirement) anywhere in the responses.

Distinct from ``enumeration``'s rate probe on three axes: endpoint class
(business flows, not authentication endpoints), the ``mutate: true`` gate (it
drives a real write flow), and the anti-automation inspection on top of the
429 check. Bodies are identical, and the oracle is that they produce **distinct
created objects**: a flow that answers an identical replay with the *same*
object id is idempotent — protected against the double-spend abuse — and a flow
that demands an idempotency key or shows a challenge is protected too. Only a
flow that mints a new object for every identical replay, with no throttle, is
flagged. Heuristic: the absence of a control in a short burst is a lead, not
proof.
"""
from __future__ import annotations

import json
import re
from typing import Any

from app.domain.enums import Confidence, Severity
from app.engine.base import EngineFinding, ScanContext, render_path
from app.engine.resource_map import path_values
from app.engine.spec_values import base_value

#: Path fragments that name a sensitive business flow.
_FLOW_HINTS = re.compile(
    r"checkout|purchase|\border\b|orders|payment|\bpay\b|redeem|coupon|promo"
    r"|voucher|invite|referral|signup|sign-up|register|subscribe|booking|book"
    r"|reserve|reservation|transfer|withdraw|deposit|\bvote\b|apply|claim|gift",
    re.I,
)
#: Authentication-shaped flows are ``enumeration``'s territory — excluded here so
#: the two checks never both report the same endpoint.
_AUTH_EXCLUDE = re.compile(r"login|signin|sign-in|token|password|passwd|otp|reset|auth", re.I)
#: A response that shows an anti-automation control *is* in place: a human
#: challenge, or a demand for an idempotency/nonce key. Its presence means the
#: flow is protected, so the endpoint is not flagged.
_ANTI_AUTOMATION = re.compile(
    r"captcha|recaptcha|hcaptcha|challenge|are you human|verify you|prove you"
    r"|idempotenc|nonce required|too many|rate.?limit|throttl|slow down",
    re.I,
)

#: Response fields that identify a freshly-created object. Distinct values
#: across identical replays prove the flow made a new object each time.
_ID_KEYS = (
    "id", "order_id", "orderid", "uuid", "guid", "ref", "reference",
    "confirmation", "confirmation_number", "number", "receipt", "token",
)

_MUTATING = ("POST", "PUT", "PATCH")
_BURST = 5
_MAX_OPS = 2


def _created_id(text: str | None) -> str | None:
    """The identifier a create response returned, or None if unparseable."""
    try:
        body: Any = json.loads(text or "")
    except (ValueError, TypeError):
        return None
    if not isinstance(body, dict):
        return None
    for key in _ID_KEYS:
        if key in body and body[key] not in (None, "", 0):
            return f"{key}={body[key]}"
    return None


class BusinessFlowCheck:
    key = "business_flow"
    #: Drives a real write flow, so it is gated behind ``mutate: true`` and kept
    #: out of the parallel pool like every other state-changing probe.
    mutates = True

    def _flows(self, ctx: ScanContext) -> list:
        return [
            op
            for op in ctx.operations
            if op.method.upper() in _MUTATING
            and _FLOW_HINTS.search(op.path)
            and not _AUTH_EXCLUDE.search(op.path)
            and op.body_params
        ]

    def inapplicable(self, ctx: ScanContext) -> str | None:
        if not ctx.allow_mutation:
            return "writes to the target are off (turn on writes to run it)"
        from app.engine.business_state import configured

        if not self._flows(ctx) and not configured(ctx):
            return (
                "no sensitive business-flow endpoint (checkout/purchase/redeem/…) "
                "with a request body in the spec"
            )
        return None

    def run(self, ctx: ScanContext) -> list[EngineFinding]:
        if not ctx.allow_mutation:
            return []
        headers = ctx.primary_headers()
        from app.engine.business_state import run_workflows

        findings: list[EngineFinding] = run_workflows(ctx)

        for op in self._flows(ctx)[:_MAX_OPS]:
            with ctx.probe.test_case(_BURST, label=f"business-burst:{op.path}") as case:
                if case is None:
                    continue
                url = render_path(op.path, path_values(op, ctx.resource_ids))
                body = {
                    p["name"]: base_value(p.get("schema") or {})
                    for p in op.params
                    if p.get("in") == "body" and p.get("required")
                }

                statuses: list[int] = []
                created: set[str] = set()
                unidentifiable = False
                protected = False
                for _ in range(_BURST):
                    r = ctx.probe.send(op.method, url, headers=headers, json=body)
                    if r is None:
                        return findings  # budget spent
                    statuses.append(r.status)
                    if r.status == 429 or self._shows_control(r):
                        protected = True
                        break
                    if r.status < 400:
                        cid = _created_id(r.text)
                        if cid is None:
                            unidentifiable = True
                        else:
                            created.add(cid)

                if protected:
                    continue
                # Every attempt has to have gone through: a flow that rejects the
                # identical replay (a 409 dedup, a 4xx validation gate) already has a
                # control the burst cannot get past, so it is not unprotected.
                if sum(1 for s in statuses if s < 400) < len(statuses):
                    continue
                # The oracle: a new object per identical replay. If a response id
                # could not be read, do not guess — an idempotent flow returning the
                # same id must not be mistaken for an unprotected one.
                if unidentifiable or len(created) < len(statuses):
                    continue
                findings.append(self._finding(op, statuses, len(created)))

        return findings

    def _shows_control(self, result) -> bool:
        if _ANTI_AUTOMATION.search(result.text or ""):
            return True
        return any(_ANTI_AUTOMATION.search(v) for v in result.headers.values())

    def _finding(self, op, statuses: list[int], distinct: int) -> EngineFinding:
        return EngineFinding(
            check=self.key,
            confidence=Confidence.heuristic,
            owasp_id="API6:2023",
            severity=Severity.medium,
            title=f"Sensitive business flow without anti-automation on {op.method} {op.path}",
            description=(
                f"{_BURST} identical requests to this flow each created a distinct "
                f"object ({distinct} new) with no throttle (429), no idempotency "
                "and no anti-automation control (CAPTCHA/challenge) in any "
                "response. A flow the business assumes a human drives — checkout, "
                "redemption, signup, invite — that a script can replay at machine "
                "speed is exposed to the abuse API6 names: inventory hoarding, "
                "coupon farming, referral fraud."
            ),
            evidence={
                "method": op.method,
                "path": op.path,
                "requests": _BURST,
                "distinct_objects": distinct,
                "statuses": statuses,
            },
            operation_id=op.id,
        )
