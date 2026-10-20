"""Security misconfiguration (API8) — a per-endpoint response-header sweep.

Every safe endpoint in the spec is probed **once** (one GET, carrying a
throwaway ``Origin`` so the same request also exposes CORS behaviour) and its
response headers are scored by ``app/engine/header_policy.py``. Both checks here
read that one sweep, so adding the second one costs no extra requests.

Per-endpoint rather than one representative request, because header policy is
routinely *not* uniform: a gateway sets the hardening headers, one service
behind it doesn't; a legacy route reflects any Origin while the rest don't.
Those divergences are exactly the interesting ones and a single sample misses
them.

Reporting groups endpoints that share an issue profile, so a uniformly
unhardened API is still one finding per severity tier, while an endpoint that
differs from its neighbours gets a finding of its own (with ``operation_id`` set
so the UI can link it).

- ``security_headers`` — missing *and* weak hardening headers, permissive CORS,
  insecure cookie attributes.
- ``info_disclosure`` — debug/trace correlation ids, stack version banners, and
  redirect targets naming an internal host, address or port. The last one also
  spends **one** request of its own: the first swept route with its trailing
  slash toggled, because the framework's slash redirect is where a server most
  often writes its upstream host or port into ``Location``.
"""
from __future__ import annotations

from collections.abc import Callable

from app.domain.enums import SEVERITY_RANK, Confidence, Severity
from app.engine.base import (
    EngineFinding,
    HeaderSnapshot,
    ScanContext,
    TargetOperation,
    render_path,
)
from app.engine.header_policy import (
    HeaderIssue,
    analyze_disclosure_headers,
    analyze_headers,
    analyze_redirect_headers,
)
from app.engine.resource_map import path_values

# Cap on endpoints probed by the sweep. One request each, taken out of the
# scan's 750-request budget — enough to cover a mid-size API without crowding
# out the checks that need many requests per endpoint.
MAX_HEADER_ENDPOINTS = 40

# Only ever probed with methods that cannot change target state.
_SAFE_METHODS = ("GET", "HEAD")

# Endpoints listed per finding before the evidence is truncated.
_MAX_LISTED = 20

# Body kept per swept endpoint, for `data_exposure`. Generous enough to reach the
# field names of a real collection response, bounded so a scan of a large API
# cannot hold megabytes of target data in memory.
BODY_SAMPLE_CHARS = 40_000


def probe_origin(ctx: ScanContext) -> str:
    """A throwaway Origin no target can legitimately have allow-listed.

    Seeded from the scan so it rotates per run but stays reproducible within one.
    """
    return f"https://aidx-{ctx.seed & 0xFFFFFFFF:08x}.example"


def _sweep_targets(ctx: ScanContext) -> list[TargetOperation]:
    """Pick the endpoints to probe, spreading the cap across path families.

    Round-robin over the first path segment so a spec with 200 ``/orders/*``
    routes and three ``/admin/*`` ones still samples ``/admin``.
    """
    safe = [o for o in ctx.operations if o.method.upper() in _SAFE_METHODS]
    buckets: dict[str, list[TargetOperation]] = {}
    for op in safe:
        segment = op.path.strip("/").split("/")[0] or "/"
        buckets.setdefault(segment, []).append(op)

    picked: list[TargetOperation] = []
    while len(picked) < MAX_HEADER_ENDPOINTS and any(buckets.values()):
        for ops in buckets.values():
            if not ops:
                continue
            picked.append(ops.pop(0))
            if len(picked) >= MAX_HEADER_ENDPOINTS:
                break
    return picked


def sweep_headers(ctx: ScanContext) -> list[HeaderSnapshot]:
    """Probe each endpoint once and memoise its response headers on the context.

    Memoised under ``ctx.header_lock`` because the engine runs checks
    concurrently — the second header-based check to arrive reuses the sweep
    instead of re-probing. A ``None`` probe result (budget exhausted) drops that
    endpoint rather than aborting: reporting on what was reached beats reporting
    nothing.

    The status code is recorded but not gated on: a target that rejects the
    foreign ``Origin`` outright still answers with the hardening headers its
    middleware sets, which is what we are reading.

    A truncated body sample rides along for ``data_exposure`` and
    ``potential_secrets``, so those checks read what each endpoint returns
    without spending a request of their own.
    """
    with ctx.header_lock:
        if ctx.header_sweep is not None:
            return ctx.header_sweep

        headers = {**ctx.primary_headers(), "Origin": probe_origin(ctx)}
        targets = _sweep_targets(ctx)
        snapshots: list[HeaderSnapshot] = []

        if not targets:
            # An all-POST spec still runs behind a server whose headers we can
            # read; the root is the only path we can safely assume.
            r = ctx.probe.send("GET", "/", headers=headers)
            if r is not None:
                snapshots.append(
                    HeaderSnapshot(
                        None, "GET", "/", r.status, r.headers, r.text[:BODY_SAMPLE_CHARS]
                    )
                )
        for op in targets:
            path = render_path(op.path, path_values(op, ctx.resource_ids))
            method = op.method.upper()
            r = ctx.probe.send(method, path, headers=headers)
            if r is None:
                continue
            snapshots.append(
                HeaderSnapshot(
                    op.id, method, path, r.status, r.headers, r.text[:BODY_SAMPLE_CHARS]
                )
            )

        ctx.header_sweep = snapshots
        return snapshots


# ---- Grouping -----------------------------------------------------------------

_Group = tuple[list[HeaderSnapshot], list[HeaderIssue]]


def _group(
    snapshots: list[HeaderSnapshot],
    analyse: Callable[[HeaderSnapshot], list[HeaderIssue]],
    *,
    partition: str,
) -> list[_Group]:
    """Bucket endpoints that share an identical issue profile.

    ``partition`` selects the secondary key ("severity" or "kind") so a medium
    hardening gap and a low hygiene gap on the same endpoint stay separate
    findings, as they were before this check went per-endpoint.

    Endpoints bucket by *which* headers are at fault, not by the values behind
    them, so the issue detail carried into the finding is the first member's.
    """
    buckets: dict[tuple, list[HeaderSnapshot]] = {}
    issues_for: dict[tuple, list[HeaderIssue]] = {}
    for snap in snapshots:
        by_part: dict[object, list[HeaderIssue]] = {}
        for issue in analyse(snap):
            by_part.setdefault(getattr(issue, partition), []).append(issue)
        for part, group in by_part.items():
            key = (
                part.value if isinstance(part, Severity) else part,
                tuple(sorted(f"{i.header}:{i.kind}" for i in group)),
            )
            buckets.setdefault(key, []).append(snap)
            issues_for.setdefault(key, group)
    return [(snaps, issues_for[key]) for key, snaps in buckets.items()]


def _scope(affected: int, total: int) -> str:
    if affected >= total:
        return "all endpoints" if total > 1 else "the probed endpoint"
    return f"{affected}/{total} endpoints"


def _evidence(
    snaps: list[HeaderSnapshot], issues: list[HeaderIssue], total: int
) -> dict[str, object]:
    return {
        "probed_endpoints": total,
        "affected_endpoints": [s.label for s in snaps[:_MAX_LISTED]],
        "missing": {i.header: i.detail for i in issues if i.kind == "missing"},
        "weak": {
            i.header: {"observed": i.observed, "problem": i.detail}
            for i in issues
            if i.kind not in ("missing", "debug", "banner")
        },
        "present": sorted(snaps[0].headers),
    }


_VERB = {"missing": "Missing", "weak": "Weak", "permissive": "Permissive", "cookie": "Insecure"}


class SecurityHeadersCheck:
    """Hardening headers, CORS and cookie flags, on every endpoint (API8)."""

    key = "security_headers"

    def run(self, ctx: ScanContext) -> list[EngineFinding]:
        snapshots = sweep_headers(ctx)
        if not snapshots:
            return []
        https = ctx.base_url.lower().startswith("https")
        origin = probe_origin(ctx)
        total = len(snapshots)

        groups = _group(
            snapshots,
            lambda s: analyze_headers(s.headers, https=https, probe_origin=origin),
            partition="severity",
        )
        groups.sort(
            key=lambda g: (-SEVERITY_RANK[g[1][0].severity], -len(g[0]), g[1][0].header)
        )

        findings: list[EngineFinding] = []
        for snaps, issues in groups:
            findings.append(
                EngineFinding(
                    check=self.key,
                    confidence=Confidence.verified,
                    owasp_id="API8:2023",
                    severity=issues[0].severity,
                    title=self._title(issues, len(snaps), total),
                    description=self._description(issues, len(snaps), total),
                    evidence=_evidence(snaps, issues, total),
                    operation_id=snaps[0].operation_id if len(snaps) == 1 else None,
                )
            )
        return findings

    @staticmethod
    def _title(issues: list[HeaderIssue], affected: int, total: int) -> str:
        scope = _scope(affected, total)
        if len(issues) == 1:
            issue = issues[0]
            return f"{_VERB.get(issue.kind, 'Insecure')} {issue.header} on {scope}"
        kinds = {i.kind for i in issues}
        if kinds == {"missing"}:
            # The low tier is the browser-hardening set; naming it keeps the two
            # missing-header findings on an API distinguishable at a glance.
            noun = "hygiene" if issues[0].severity == Severity.low else "security"
            return f"Missing {noun} headers ({len(issues)}) on {scope}"
        if "missing" not in kinds:
            return f"Weak security header values ({len(issues)}) on {scope}"
        return f"Security header gaps ({len(issues)}) on {scope}"

    @staticmethod
    def _description(issues: list[HeaderIssue], affected: int, total: int) -> str:
        lines = [f"- {i.header}: {i.detail}" for i in issues]
        where = (
            f"All {total} probed endpoints respond"
            if affected >= total
            else f"{affected} of {total} probed endpoints respond"
        )
        return f"{where} with the following header problems:\n" + "\n".join(lines)


_REDIRECT_REMEDIATION = (
    "Build redirect URLs from the public origin, not the server's own view of the "
    "request: have the proxy forward Host and X-Forwarded-Proto/-Port and configure "
    "the application to trust them (Uvicorn/Gunicorn --forwarded-allow-ips, Django "
    "USE_X_FORWARDED_HOST, Express trust proxy), or emit relative Location headers. "
    "On nginx, `absolute_redirect off` (or `port_in_redirect off`) stops the upstream "
    "port reaching the client."
)


def _slash_redirect(ctx: ScanContext, snapshots: list[HeaderSnapshot]) -> HeaderSnapshot | None:
    """The first working GET route with its trailing slash toggled — one request.

    Kept only when it redirects; any other answer has no ``Location`` to read.
    """
    seed = next(
        (s for s in snapshots if s.method == "GET" and 200 <= s.status < 300 and s.path != "/"),
        None,
    )
    if seed is None:
        return None
    path = seed.path.rstrip("/") if seed.path.endswith("/") else seed.path + "/"
    r = ctx.probe.send("GET", path, headers=ctx.primary_headers())
    if r is None or not 300 <= r.status < 400:
        return None
    return HeaderSnapshot(seed.operation_id, "GET", path, r.status, r.headers)


class InfoDisclosureCheck:
    """Debug/trace identifiers, version banners and internal redirect targets (low)."""

    key = "info_disclosure"

    def run(self, ctx: ScanContext) -> list[EngineFinding]:
        snapshots = sweep_headers(ctx)
        if not snapshots:
            return []
        findings = self._disclosure(snapshots)
        redirected = _slash_redirect(ctx, snapshots)
        findings.extend(
            self._redirects(ctx, snapshots + ([redirected] if redirected else []))
        )
        return findings

    def _redirects(
        self, ctx: ScanContext, snapshots: list[HeaderSnapshot]
    ) -> list[EngineFinding]:
        total = len(snapshots)
        groups = _group(
            snapshots,
            lambda s: analyze_redirect_headers(s.headers, ctx.base_url),
            partition="kind",
        )
        findings: list[EngineFinding] = []
        for snaps, issues in groups:
            scope = _scope(len(snaps), total)
            targets = ", ".join(f"{i.header}: {i.observed}" for i in issues)
            findings.append(
                EngineFinding(
                    check=self.key,
                    confidence=Confidence.verified,
                    owasp_id="API8:2023",
                    severity=Severity.low,
                    title=f"Internal address disclosed in redirect target on {scope}",
                    description=(
                        f"Redirects on {scope} ({len(snaps)} of {total} probed) point at "
                        f"{targets}. {issues[0].detail[0].upper()}{issues[0].detail[1:]}; "
                        "it maps the network behind the edge for an attacker, and a "
                        "client that follows the redirect fails or leaves the TLS origin."
                    ),
                    evidence={
                        "probed_endpoints": total,
                        "affected_endpoints": [s.label for s in snaps[:_MAX_LISTED]],
                        "headers": {i.header: i.observed for i in issues},
                    },
                    operation_id=snaps[0].operation_id if len(snaps) == 1 else None,
                    remediation=_REDIRECT_REMEDIATION,
                )
            )
        return findings

    def _disclosure(self, snapshots: list[HeaderSnapshot]) -> list[EngineFinding]:
        total = len(snapshots)

        groups = _group(
            snapshots,
            lambda s: analyze_disclosure_headers(s.headers),
            partition="kind",
        )
        groups.sort(key=lambda g: (g[1][0].kind, -len(g[0])))

        findings: list[EngineFinding] = []
        for snaps, issues in groups:
            kind = issues[0].kind
            names = sorted(i.header for i in issues)
            scope = _scope(len(snaps), total)
            if kind == "debug":
                title = f"Debug/trace identifiers disclosed in response headers ({len(names)})"
                why = (
                    "They correlate a request across backend services and help an "
                    "attacker trace requests through the stack; they belong in "
                    "server-side logs, not responses."
                )
            else:
                title = f"Server/framework version disclosed in response headers ({len(names)})"
                why = (
                    "A named component and version narrows an attacker's search for "
                    "known CVEs against this stack."
                )
            findings.append(
                EngineFinding(
                    check=self.key,
                    confidence=Confidence.verified,
                    owasp_id="API8:2023",
                    severity=Severity.low,
                    title=f"{title} on {scope}",
                    description=(
                        f"Responses carry {', '.join(names)} on {scope} "
                        f"({len(snaps)} of {total} probed). {why}"
                    ),
                    evidence={
                        "probed_endpoints": total,
                        "affected_endpoints": [s.label for s in snaps[:_MAX_LISTED]],
                        "headers": {i.header: i.observed for i in issues},
                    },
                    operation_id=snaps[0].operation_id if len(snaps) == 1 else None,
                )
            )
        return findings
