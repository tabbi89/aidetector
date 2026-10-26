"""Reflected-injection leads.

Sends marker-carrying payloads from `app/engine/payloads.py` into each injection
point; a finding fires when a payload character the response's own context would
have to encode comes back intact beside the marker (``Attempt.injected``). That
proves attacker-controlled input is not neutralised — a *lead*, not proof of
execution (see `apps/web/lib/coverage.ts`).

Only the families this check can adjudicate are sent: ``reflection`` (XSS/SQLi,
whose metacharacters a correct response would encode) and ``header`` (CRLF,
confirmed only when the injected header comes back among the response headers).
The ``evaluate`` (SSTI) and ``oob`` (command/traversal) families prove nothing by
a bare echo and are confirmed by their own checks, so they are not sent here —
see ``app/engine/payloads.FAMILY_ORACLE``.

Draws a rotating payload set per scan (seeded), so repeated scans exercise
different payload variants over time. Injection is spec-shaped
(``app/engine/spec_values.py``): GET query + path params and POST/PUT/PATCH JSON
body fields are fuzzed, the payload value is kept type/enum/format-plausible, and
the operation's other required params are filled with spec-valid baselines so the
payload reaches the sink instead of being rejected up front.

**A reflection seen only in a 4xx is dropped.** Frameworks echo the request
path/params inside 400/422 error envelopes, so a marker reflected only in a
rejected request shows the error handler saw the input, not the parameter's
sink. A 5xx is kept — the payload got past validation and broke something.
"""
from __future__ import annotations

from app.domain.enums import Confidence, Severity
from app.engine.base import EngineFinding, ScanContext
from app.engine.evidence import injection_evidence
from app.engine.injection_probe import (
    Attempt,
    probe_body_point,
    probe_point,
    walk_points,
)
from app.engine.payloads import REFLECTION_ORACLES, Payload

# XSS-family reflections are high severity; other families reflecting the marker
# indicate an injection surface worth reporting at medium.
_HIGH_FAMILIES = {"xss"}


class ReflectedInjectionCheck:
    key = "reflected_injection"

    def run(self, ctx: ScanContext) -> list[EngineFinding]:
        headers = ctx.primary_headers()
        # Only the families this check can actually adjudicate — a reflected
        # metacharacter (``reflection``) or a split response header (``header``).
        # The ``evaluate`` (SSTI arithmetic) and ``oob`` (command/traversal)
        # families are confirmed by dedicated checks, so sending them here would
        # burn request budget on payloads that could never become a lead. Reflection
        # families go first so a tight per-endpoint budget hits the strongest probe.
        payloads = [p for p in ctx.reflection_payloads(per_family=1)
                    if p.oracle in REFLECTION_ORACLES]
        payloads.sort(key=lambda p: p.oracle != "reflection")
        from app.engine.independent_injection import confirm_independently

        findings: list[EngineFinding] = confirm_independently(ctx)

        writer = ctx.lowest_writer()
        for op, point in walk_points(ctx):
            if point.location == "body":
                if writer is None:
                    continue
                hit = self._scan(
                    probe_body_point(ctx, op, point, writer, [p.template for p in payloads]),
                    payloads,
                )
            else:
                hit = self._probe_point(ctx, op, point, headers, payloads)
            if hit:
                findings.append(hit)
        return findings

    def _scan(self, attempts, payloads: list[Payload]) -> EngineFinding | None:
        """Read reflections from an attempt stream (body points, already sent).

        The payload's :attr:`~app.engine.payloads.Payload.oracle` decides what
        counts: a ``reflection`` family needs a metacharacter the response
        context should have neutralised (``attempt.injected``); ``header`` (CRLF)
        needs the injected header name back among the response headers; and
        ``evaluate`` / ``oob`` families are confirmed elsewhere and never produce
        a lead from a bare echo here.
        """
        for attempt in attempts:
            payload = payloads[attempt.index]
            if payload.oracle == "header":
                if attempt.header_injected:
                    return self._header_finding(attempt, payload)
                continue
            if payload.oracle != "reflection":
                continue
            if not payload.reflect_marker or not attempt.injected:
                continue
            # A reflection seen only in a 4xx is the framework echoing the input
            # it rejected, not the parameter's sink — the same cut
            # ``signature_injection`` makes, and dropped rather than reported,
            # because such echoes are non-actionable and rotate with the payload
            # (a 422 envelope is JSON, so only some payloads carry a structural
            # character), which would churn the run-to-run diff. A 5xx is kept:
            # the payload got past validation and broke something.
            if 400 <= attempt.response.status < 500:
                continue
            return self._finding(attempt, payload, error_surface=False)
        return None

    def _probe_point(
        self, ctx, op, point, headers, payloads: list[Payload]
    ) -> EngineFinding | None:
        # The whole Attempt is kept — its path is the one this payload was sent
        # to, which for a `path` point differs from every other attempt's.
        return self._scan(
            probe_point(ctx, op, point, headers, [p.template for p in payloads]), payloads
        )

    def _finding(
        self, attempt: Attempt, payload: Payload, *, error_surface: bool = False
    ) -> EngineFinding:
        attempt.mark_finding()
        op, point, r = attempt.op, attempt.point, attempt.response
        high = payload.family in _HIGH_FAMILIES
        severity = Severity.high if high else Severity.medium
        description = (
            f"The '{point.name}' {point.location} parameter reflects a "
            f"{payload.family} payload into the response unescaped: a character "
            "the response's own context would have to encode came back intact, so "
            "attacker-controlled input is not neutralised."
        )
        return EngineFinding(
            check=self.key,
            owasp_id="CWE-74",
            severity=severity,
            title=(
                f"Reflected {payload.family.upper()} via {point.location} "
                f"'{point.name}' on {op.method} {op.path}"
            ),
            description=description,
            evidence=injection_evidence(
                request_method=op.method,
                variant=point.variant,
                family=payload.family,
                path=attempt.path,
                route=op.path,
                param=point.name,
                location=point.location,
                payload=attempt.value,
                status=r.status,
                reflected=True,
                response_sample=r.text,
                error_surface=error_surface,
            ),
            operation_id=op.id,
        )

    def _header_finding(self, attempt: Attempt, payload: Payload) -> EngineFinding:
        """A CRLF payload that produced a new *response header* — a verified split."""
        attempt.mark_finding()
        op, point, r = attempt.op, attempt.point, attempt.response
        return EngineFinding(
            check=self.key,
            owasp_id="CWE-74",
            severity=Severity.high,
            confidence=Confidence.verified,
            title=(
                f"CRLF response-header injection via {point.location} "
                f"'{point.name}' on {op.method} {op.path}"
            ),
            description=(
                f"A CRLF sequence in the '{point.name}' {point.location} parameter "
                "was reflected into the response as a new header, so the parameter "
                "can split the response and inject headers — not merely echo text."
            ),
            evidence=injection_evidence(
                request_method=op.method,
                variant=point.variant,
                family=payload.family,
                path=attempt.path,
                route=op.path,
                param=point.name,
                location=point.location,
                payload=attempt.value,
                status=r.status,
                reflected=True,
                response_sample=r.text,
                error_surface=False,
            ),
            operation_id=op.id,
        )
