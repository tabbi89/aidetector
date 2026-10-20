"""Second-tier injection leads: XPath / LDAP / NoSQL / SSI.

Same technique as ``ReflectedInjectionCheck`` — one marker-carrying payload per
class per scan (rotated by the per-scan seed), sent to the same spec-shaped sinks
(GET query + path params, POST/PUT/PATCH JSON body fields; see
``app/engine/spec_values.py``) — but with two detection signals instead of one:

1. **Error signature** (stronger): the response matches a known backend error
   regex for that class (``engine/signatures.py``). This evidences the payload
   was parsed by the target's query/interpreter layer, so it is reported at
   *medium*.
2. **Reflection** (weaker): the ``aidx<marker>`` needle comes back *with the
   payload's metacharacters intact* (see ``Attempt.reflected``). Reported at
   *low* — a lead that input reaches the response, nothing more.

Neither is exploitation: both are labelled "reflection leads" in the UI. The
corpora are public and permissive (PayloadsAllTheThings, FuzzDB signatures).

**Reflections seen only in a 4xx are dropped**, the same way
``ReflectedInjectionCheck`` downgrades them and for the same reason: a validation
envelope echoing the value it rejected ("Input should be a valid integer, unable
to parse ``<payload>``") shows the framework's error handler saw the input, not
that a query layer parsed it. Every well-behaved API does this on every typed
path parameter, so reporting it produced more findings than the rest of the
engine combined.

The cut is at 4xx, not at "any error": a **5xx** means the payload got past
validation and broke something server-side, which is the opposite of a
well-handled rejection and worth the lead. And an *error signature* counts at any
status — that is the signal this check exists for, and a backend error is a
backend error whatever wraps it.
"""
from __future__ import annotations

import random
import re

from app.domain.enums import Severity
from app.engine.base import EngineFinding, ScanContext
from app.engine.evidence import injection_evidence
from app.engine.injection_probe import (
    Attempt,
    probe_body_point,
    probe_point,
    walk_points,
)
from app.engine.signatures import SIGNATURE_CLASSES, SignatureClass

#: How close (in characters) the injected marker must sit to a matched error
#: signature for the match to count as *strong* evidence. A loose signature such
#: as "CastError" can appear in a response for reasons unrelated to the payload;
#: when the unique marker is beside it, the error is the backend answering this
#: payload.
_MARKER_COLOCATION_CHARS = 400


def _marker_near(match: re.Match[str], text: str, needle: str) -> bool:
    """Whether ``needle`` appears within ``_MARKER_COLOCATION_CHARS`` of ``match``."""
    lo = max(0, match.start() - _MARKER_COLOCATION_CHARS)
    hi = min(len(text), match.end() + _MARKER_COLOCATION_CHARS)
    return needle.lower() in text[lo:hi].lower()


class SignatureInjectionCheck:
    key = "signature_injection"

    def run(self, ctx: ScanContext) -> list[EngineFinding]:
        headers = ctx.primary_headers()
        # Rotate one payload per class per scan, deterministic in the seed.
        rng = random.Random(ctx.seed ^ 0x51C6)
        selection = {sc.family: rng.choice(sc.payloads) for sc in SIGNATURE_CLASSES}
        findings: list[EngineFinding] = []

        writer = ctx.lowest_writer()
        for op, point in walk_points(ctx):
            is_body = point.location == "body"
            if is_body and writer is None:
                continue
            for sc in SIGNATURE_CLASSES:
                stream = (
                    probe_body_point(ctx, op, point, writer, [selection[sc.family]])
                    if is_body
                    else probe_point(ctx, op, point, headers, [selection[sc.family]])
                )
                for attempt in stream:
                    hit = self._judge(attempt, sc)
                    if hit:
                        findings.append(hit)
        return findings

    def _judge(self, attempt: Attempt, sc: SignatureClass) -> EngineFinding | None:
        r = attempt.response
        # Find the first error-signature match, retaining the pattern string for
        # evidence. ``confirmed`` upgrades it when our marker sits beside it.
        matched: re.Match[str] | None = None
        matched_pattern: str | None = None
        for pattern in sc.error_signatures:
            match = pattern.search(r.text)
            if match is not None:
                matched = match
                matched_pattern = pattern.pattern
                break
        # A reflection inside a 4xx is the framework echoing what it rejected;
        # a 5xx means it got through. See the module docstring.
        reflected = attempt.reflected and not (400 <= r.status < 500)
        if matched is None and not reflected:
            return None

        confirmed = matched is not None and _marker_near(matched, r.text, attempt.needle)
        if confirmed:
            severity = Severity.medium
            why = (
                f"A {sc.label} error signature was returned beside the injected "
                f"marker, so the payload reached the target's query/interpreter "
                f"layer (matched: {matched_pattern!r})."
            )
        elif matched is not None:
            severity = Severity.low
            why = (
                f"A {sc.label} error signature was returned, but the injected "
                f"marker was not beside it, so the error may be unrelated to the "
                f"payload (matched: {matched_pattern!r})."
            )
        else:
            severity = Severity.low
            why = (
                f"The {sc.label} payload marker was reflected verbatim; input reaches "
                "the response but no backend error was observed."
            )

        attempt.mark_finding()
        op, point = attempt.op, attempt.point
        return EngineFinding(
            check=self.key,
            owasp_id=sc.owasp_id,
            severity=severity,
            title=(
                f"{sc.label} lead via {point.location} '{point.name}' "
                f"on {op.method} {op.path}"
            ),
            description=(
                f"The '{point.name}' {point.location} parameter is a {sc.label} "
                f"candidate. {why} This is a reflection lead, not a confirmed "
                "vulnerability — confirm by hand."
            ),
            evidence=injection_evidence(
                request_method=op.method,
                variant=point.variant,
                family=sc.family,
                path=attempt.path,
                route=op.path,
                param=point.name,
                location=point.location,
                payload=attempt.value,
                status=r.status,
                reflected=reflected,
                response_sample=r.text,
                error_signature=matched_pattern,
                confirmed=confirmed,
            ),
            operation_id=op.id,
        )
