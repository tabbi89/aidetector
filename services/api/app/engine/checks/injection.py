"""Reflected-injection leads.

Sends marker-carrying payloads from `app/engine/payloads.py` into each
injection point; a finding fires when the unique marker comes back verbatim in
the response body. That proves attacker-controlled input reaches the response —
a *lead*, not proof of execution (see `apps/web/lib/coverage.ts`).

Draws a rotating payload set per scan (seeded), so repeated scans exercise
different payload families and variants over time. Injection is spec-shaped
(``app/engine/spec_values.py``): GET query + path params and POST/PUT/PATCH JSON
body fields are fuzzed, the payload value is kept type/enum/format-plausible, and
the operation's other required params are filled with spec-valid baselines so the
payload reaches the sink instead of being rejected up front.

**Error-surface reflections are downgraded.** Frameworks commonly echo the
request path/params inside 404/400 error envelopes ("Cannot GET /…"), so a
marker reflected *only* in a >= 400 response proves the error handler saw the
input, not the parameter's sink. Such hits are reported at `info` with
``error_surface: true`` instead of the usual medium/high lead; a reflection on
a < 400 response always wins when both are seen for the same point.
"""
from __future__ import annotations

from app.domain.enums import Severity
from app.engine.base import EngineFinding, ScanContext
from app.engine.evidence import injection_evidence
from app.engine.injection_probe import (
    Attempt,
    probe_body_point,
    probe_point,
    walk_points,
)
from app.engine.payloads import Payload

# XSS-family reflections are high severity; other families reflecting the marker
# indicate an injection surface worth reporting at medium.
_HIGH_FAMILIES = {"xss"}

# Reflections seen only on error responses are a weaker signal: the marker may
# be echoed by the framework's error envelope rather than the parameter's sink.
_ERROR_SURFACE_SEVERITY = Severity.info


class ReflectedInjectionCheck:
    key = "reflected_injection"

    def run(self, ctx: ScanContext) -> list[EngineFinding]:
        headers = ctx.primary_headers()
        payloads = ctx.reflection_payloads(per_family=1)
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
        """Read reflections from an attempt stream (body points, already sent)."""
        fallback: tuple[Attempt, Payload] | None = None
        for attempt in attempts:
            payload = payloads[attempt.index]
            if not payload.reflect_marker or not attempt.reflected:
                continue
            if attempt.response.status < 400:
                return self._finding(attempt, payload, error_surface=False)
            if fallback is None:
                fallback = (attempt, payload)
        if fallback is not None:
            attempt, payload = fallback
            return self._finding(attempt, payload, error_surface=True)
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
        self, attempt: Attempt, payload: Payload, *, error_surface: bool
    ) -> EngineFinding:
        attempt.mark_finding()
        op, point, r = attempt.op, attempt.point, attempt.response
        if error_surface:
            severity = _ERROR_SURFACE_SEVERITY
            suffix = " (error surface)"
            description = (
                f"The '{point.name}' {point.location} parameter's payload was "
                f"reflected only in a {r.status} error response (framework error "
                "envelopes commonly echo the request path/params). This shows the "
                "input reaches the error handler, not that the parameter's sink "
                "processes it — informational until seen on a success response."
            )
        else:
            high = payload.family in _HIGH_FAMILIES
            severity = Severity.high if high else Severity.medium
            suffix = ""
            description = (
                f"The '{point.name}' {point.location} parameter reflects a "
                f"{payload.family} payload into the response unescaped: the "
                "injected marker came back verbatim, so attacker-controlled "
                "input is not neutralised."
            )
        return EngineFinding(
            check=self.key,
            owasp_id="CWE-74",
            severity=severity,
            title=(
                f"Reflected {payload.family.upper()} via {point.location} "
                f"'{point.name}' on {op.method} {op.path}{suffix}"
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
