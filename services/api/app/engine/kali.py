"""Kali adjunct service — opt-in nuclei templates, discovery and breadth passes.

A separate container (``services/kali``, built ``FROM kalilinux/kali-rolling``
with a curated toolset) exposes a small job API over HTTP; this module drives
it the way ``zap.py`` drives the ZAP daemon. Six passes:

- **nuclei** — community template scan (CVEs, exposures, misconfigs). Template
  matches are strong signals, mapped as findings with the template, its CVE/CWE
  ids and references as evidence; info-level (fingerprint) matches are graded
  heuristic.
- **discovery** (ffuf) and **crawl** (katana) — paths the uploaded spec never
  mentioned (shadow/undocumented endpoints), reported as low-severity findings.
  Neither mutates the scan's Operation set.
- **params** (Arjun) — hidden query parameters on the base target.
- **nikto** — web-server misconfig / known-file leads.
- **whatweb** — one informational technology fingerprint.

Two things make this deliberately a *side path*, not a check in ``ALL_CHECKS``:

- **It ignores the engine's 750-request budget and cooperative cancellation.**
  The tools fire on their own schedule; the sidecar bounds them with
  rate limits and a wall-clock timeout. So the pass is gated behind an explicit
  per-run opt-in (``kali: true``), like ZAP.
- It **degrades gracefully**, like the AI cascade, ZAP and OAST: any failure
  (service down, API error, timeout) logs and returns no findings.

The mappers are pure and unit-tested; the network dance is thin around them.
"""
from __future__ import annotations

import logging
import re
from collections.abc import Callable, Iterable, Sequence
from typing import Any, Protocol

from app.domain.enums import Confidence, Severity
from app.engine.base import EngineFinding

log = logging.getLogger("runpentests.kali")

# Cap on extra operation URLs passed to the tool passes, so a huge spec cannot
# multiply the sidecar's workload unboundedly.
_MAX_EXTRA_TARGETS = 15

# nuclei severity strings → our ladder (nuclei uses the exact names below).
_NUCLEI_SEVERITY = {
    "critical": Severity.critical,
    "high": Severity.high,
    "medium": Severity.medium,
    "low": Severity.low,
    "info": Severity.info,
}


class KaliHttp(Protocol):
    """Minimal transport contract (an ``httpx.Client`` satisfies it)."""

    def get(self, url: Any, **kwargs: Any) -> Any: ...

    def post(self, url: Any, **kwargs: Any) -> Any: ...


def map_nuclei_findings(rows: list[dict[str, Any]]) -> list[EngineFinding]:
    """Map normalized nuclei results from the sidecar. Pure — no I/O."""
    findings: list[EngineFinding] = []
    for r in rows:
        severity = _NUCLEI_SEVERITY.get(str(r.get("severity", "")).lower(), Severity.info)
        name = str(r.get("name") or r.get("template_id") or "nuclei match")
        url = r.get("url") or r.get("host")
        cve_ids = _str_list(r.get("cve_ids"))
        findings.append(
            EngineFinding(
                check="kali_nuclei",
                # Info-level templates are tech-detect/fingerprint matches: they
                # say a component is present, not that it is exploitable, so
                # they must not rank beside proof or reach SARIF `error`.
                confidence=(
                    Confidence.heuristic if severity is Severity.info else Confidence.verified
                ),
                owasp_id=None,
                severity=severity,
                title=f"nuclei: {name}"[:255],
                description=(
                    f"nuclei template '{r.get('template_id', '?')}' matched at "
                    f"{r.get('matched_at') or url or 'the target'}"
                    + (f" ({', '.join(cve_ids)})" if cve_ids else "")
                    + "."
                ),
                # Templates may define their own remediation; it beats a generic
                # "read the template" line when present.
                remediation=str(r.get("remediation") or "").strip()[:2000],
                evidence={
                    "template_id": r.get("template_id"),
                    "url": url,
                    "matched_at": r.get("matched_at"),
                    "type": r.get("type"),
                    "tags": r.get("tags"),
                    "nuclei_severity": str(r.get("severity", "")).lower(),
                    "cve_ids": cve_ids,
                    "cwe_ids": _str_list(r.get("cwe_ids")),
                    "references": _str_list(r.get("references")),
                    "source": "nuclei",
                },
            )
        )
    return findings


def _str_list(value: Any) -> list[str]:
    """A list-of-strings field from the sidecar, tolerating absent or bad shapes."""
    if not isinstance(value, list):
        return []
    return [str(v) for v in value if v is not None and str(v)]


def _spec_path_pattern(path: str) -> re.Pattern[str]:
    """Compile an OpenAPI path template to a matcher ({var} → any segment)."""
    segs = [
        r"[^/]+" if seg.startswith("{") and seg.endswith("}") else re.escape(seg)
        for seg in path.strip("/").split("/")
    ]
    return re.compile("^/" + "/".join(segs) + "/?$")


def filter_known_paths(
    rows: list[dict[str, Any]], spec_paths: Iterable[str]
) -> list[dict[str, Any]]:
    """Drop discovered paths the uploaded spec already documents.

    The sidecar cannot know the spec, so the filtering happens here: a
    discovery is only interesting when the spec does not mention the path.
    """
    patterns = [_spec_path_pattern(p) for p in spec_paths if p]
    if not patterns:
        return rows
    return [
        r
        for r in rows
        if not any(p.match(str(r.get("path") or "")) for p in patterns)
    ]


# A host behind a WAF/edge proxy often answers *every* unknown path with the
# same deny/blanket status instead of 404. ffuf only filters 404, so such a
# target turns the whole wordlist into "discovered" paths (all identical
# status) — pure noise. When one deny-style status dominates the result set we
# treat it as that wildcard baseline and drop it. Real signal (2xx/3xx/5xx, or a
# deny status on just a handful of paths) is left untouched.
_WILDCARD_STATUSES = frozenset({401, 403, 405, 429})
_WILDCARD_MIN_COUNT = 10
_WILDCARD_FRACTION = 0.5


def calibrate_discovered_paths(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Drop paths sharing a dominant deny-style status (a wildcard baseline).

    Only fires when a single ``_WILDCARD_STATUSES`` code covers both at least
    ``_WILDCARD_MIN_COUNT`` paths and ``_WILDCARD_FRACTION`` of the rows, so a
    lone 403 on a real shadow endpoint survives.
    """
    if len(rows) < _WILDCARD_MIN_COUNT:
        return rows
    counts: dict[Any, int] = {}
    for r in rows:
        counts[r.get("status")] = counts.get(r.get("status"), 0) + 1
    total = len(rows)
    baseline = {
        status
        for status, n in counts.items()
        if status in _WILDCARD_STATUSES
        and n >= _WILDCARD_MIN_COUNT
        and n / total >= _WILDCARD_FRACTION
    }
    if not baseline:
        return rows
    kept = [r for r in rows if r.get("status") not in baseline]
    log.info(
        "kali discovery: dropped %d path(s) matching wildcard status %s",
        total - len(kept),
        sorted(baseline),
    )
    return kept


def map_discovered_paths(rows: list[dict[str, Any]]) -> list[EngineFinding]:
    """Map ffuf-discovered paths (absent from the spec) into findings."""
    findings: list[EngineFinding] = []
    for r in rows:
        path = str(r.get("path") or "")
        if not path:
            continue
        status = r.get("status")
        findings.append(
            EngineFinding(
                check="kali_discovery",
                confidence=Confidence.verified,
                owasp_id=None,
                severity=Severity.low,
                title=f"Undocumented path: {path} (HTTP {status})"[:255],
                description=(
                    f"Content discovery found '{path}' with status {status}, but the "
                    "uploaded spec does not mention it. Undocumented (shadow) "
                    "endpoints often miss the authz hardening of spec'd ones — "
                    "worth a manual look."
                ),
                evidence={
                    "path": path,
                    "status": status,
                    "url": r.get("url"),
                    "source": "ffuf",
                },
            )
        )
    return findings


def map_nikto_findings(rows: list[dict[str, Any]]) -> list[EngineFinding]:
    """Map nikto vulnerability rows into low-severity misconfig findings.

    nikto's basic JSON carries no severity, and many items are existence/known-
    file facts rather than proven exploits, so these are reported low — a lead to
    triage, consistent with how discovery is graded.
    """
    findings: list[EngineFinding] = []
    for r in rows:
        msg = str(r.get("message") or "nikto finding")
        url = r.get("url")
        findings.append(
            EngineFinding(
                check="kali_nikto",
                confidence=Confidence.heuristic,
                owasp_id="API8:2023",
                severity=Severity.low,
                title=f"nikto: {msg}"[:255],
                description=(
                    f"nikto reported '{msg}'"
                    + (f" at {url}" if url else "")
                    + ". nikto flags server misconfigurations and known/interesting "
                    "files; treat as a lead to verify manually."
                ),
                evidence={
                    "nikto_id": r.get("id"),
                    "method": r.get("method"),
                    "url": url,
                    "message": msg,
                    "references": r.get("references"),
                    "source": "nikto",
                },
            )
        )
    return findings


def map_whatweb_findings(rows: list[dict[str, Any]]) -> list[EngineFinding]:
    """Summarize whatweb plugin hits into a single informational fingerprint."""
    plugins = [
        str(r.get("plugin"))
        + (f" ({r.get('value')})" if r.get("value") else "")
        for r in rows
        if r.get("plugin")
    ]
    if not plugins:
        return []
    return [
        EngineFinding(
            check="kali_whatweb",
            confidence=Confidence.verified,
            owasp_id=None,
            severity=Severity.info,
            title=f"Technology fingerprint: {len(plugins)} component(s) detected"[:255],
            description=(
                "whatweb fingerprinted the target's technology stack: "
                + ", ".join(plugins[:40])
                + ". Informational — knowing the stack focuses which CVEs and "
                "misconfigurations to check."
            ),
            evidence={"plugins": plugins[:80], "source": "whatweb"},
        )
    ]


def map_crawled_paths(rows: list[dict[str, Any]]) -> list[EngineFinding]:
    """Map katana-crawled paths (absent from the spec) into low findings."""
    findings: list[EngineFinding] = []
    for r in rows:
        path = str(r.get("path") or "")
        if not path:
            continue
        findings.append(
            EngineFinding(
                check="kali_crawl",
                confidence=Confidence.verified,
                owasp_id=None,
                severity=Severity.low,
                title=f"Crawled endpoint: {path}"[:255],
                description=(
                    f"katana crawled '{path}' (including endpoints referenced from "
                    "JavaScript), but the uploaded spec does not mention it. "
                    "Undocumented endpoints often miss the authz hardening of "
                    "spec'd ones — worth a manual look."
                ),
                evidence={
                    "path": path,
                    "url": r.get("url"),
                    "source": "katana",
                },
            )
        )
    return findings


def map_param_findings(rows: list[dict[str, Any]]) -> list[EngineFinding]:
    """Map Arjun-discovered hidden parameters into low findings."""
    findings: list[EngineFinding] = []
    for r in rows:
        params = r.get("params")
        params = [str(p) for p in params] if isinstance(params, list) else []
        if not params:
            continue
        url = r.get("url")
        findings.append(
            EngineFinding(
                check="kali_params",
                confidence=Confidence.verified,
                owasp_id=None,
                severity=Severity.low,
                title=f"Hidden parameter(s): {', '.join(params[:8])}"[:255],
                description=(
                    "Arjun found HTTP parameter(s) the endpoint accepts but the "
                    f"spec never documents: {', '.join(params)}"
                    + (f" (at {url})" if url else "")
                    + ". Undocumented parameters are a common home for injection "
                    "and authorization bugs — worth fuzzing by hand."
                ),
                evidence={
                    "url": url,
                    "method": r.get("method"),
                    "params": params,
                    "source": "arjun",
                },
            )
        )
    return findings


class KaliScanner:
    """Drives the Kali adjunct service: nuclei, discovery, nikto, whatweb,
    katana crawl and Arjun parameter passes.

    ``http`` is any client exposing ``.post(url, json=...).json()``. Each pass is
    independently best-effort: a tool missing from the image (the service 503s)
    or a single pass erroring never drops the results of the others.
    """

    def __init__(
        self,
        base_url: str,
        *,
        api_key: str = "",
        http: KaliHttp,
        timeout_seconds: int = 900,
        rate_limit: int = 10,
    ) -> None:
        self._base = base_url.rstrip("/")
        self._key = api_key
        self._http = http
        self._timeout = timeout_seconds
        # Set when a run failed rather than found nothing (see ZapScanner.error),
        # and the tool endpoints that did not answer on a run that otherwise did.
        self.error: str | None = None
        self.failed_passes: list[str] = []
        self._rate_limit = min(100, max(1, rate_limit))

    def _headers(self) -> dict[str, str]:
        return {"X-API-Key": self._key} if self._key else {}

    def _post(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        r = self._http.post(
            f"{self._base}{path}",
            json=payload,
            headers=self._headers(),
            timeout=self._timeout + 30,
        )
        if getattr(r, "status_code", 200) >= 400:
            raise RuntimeError(f"Kali API {path} -> {r.status_code}")
        data = r.json()
        return data if isinstance(data, dict) else {}

    def _safe_post(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        """`_post` that swallows errors so one pass never drops the others.

        A tool missing from the image makes the service 503; that (or any
        transport error) must not lose the results of the passes that did run.
        """
        try:
            return self._post(path, payload)
        except Exception:  # noqa: BLE001 — one pass failing is not the scan failing
            log.info("Kali pass %s unavailable; skipping it", path, exc_info=True)
            self.failed_passes.append(path.rsplit("/", 1)[-1])
            return {}

    def run(
        self,
        target_url: str,
        spec_paths: Iterable[str] = (),
        spec_urls: Sequence[str] = (),
        *,
        should_stop: Callable[[], bool] | None = None,
    ) -> list[EngineFinding]:
        """Run the passes against ``target_url`` and map the results.

        ``spec_paths`` are the uploaded spec's path templates; discovered
        paths that match them are dropped (they are documented, not shadow).
        ``spec_urls`` are the scan's rendered operation URLs; they ride along
        as ``extra_targets`` on the scanner passes (nuclei/nikto/whatweb/
        katana) so the tools cover the documented API paths, not only the base
        URL — an API root usually exposes nothing to crawl. Discovery (ffuf)
        and hidden-parameter (Arjun) passes stay on the base target to keep
        their bounded fuzzing from multiplying per operation.
        Best-effort: on any error returns ``[]`` so the scan still completes.
        """
        try:
            extras = list(
                dict.fromkeys(u for u in spec_urls if u and u != target_url)
            )[:_MAX_EXTRA_TARGETS]
            short: dict[str, Any] = {
                "target": target_url,
                "timeout_seconds": min(self._timeout, 300),
                "rate_limit": self._rate_limit,
            }
            full: dict[str, Any] = {
                "target": target_url,
                "timeout_seconds": self._timeout,
                "rate_limit": self._rate_limit,
            }
            if extras:
                short = {**short, "extra_targets": extras}
                full = {**full, "extra_targets": extras}
            base_short = {
                "target": target_url,
                "timeout_seconds": min(self._timeout, 300),
                "rate_limit": self._rate_limit,
            }

            if should_stop and should_stop():
                return []
            nuclei = self._safe_post("/run/nuclei", full)
            if should_stop and should_stop():
                return []
            discover = self._safe_post("/run/discover", base_short)
            if should_stop and should_stop():
                return []
            nikto = self._safe_post("/run/nikto", full)
            if should_stop and should_stop():
                return []
            whatweb = self._safe_post("/run/whatweb", short)
            if should_stop and should_stop():
                return []
            crawl = self._safe_post("/run/crawl", short)
            if should_stop and should_stop():
                return []
            params = self._safe_post("/run/params", base_short)

            def _rows(d: dict[str, Any], key: str) -> list[dict[str, Any]]:
                v = d.get(key)
                return v if isinstance(v, list) else []

            # Both discovery (ffuf) and crawl (katana) report paths; drop the
            # spec-documented ones, and calibrate ffuf's against WAF wildcards.
            discovered = calibrate_discovered_paths(
                filter_known_paths(_rows(discover, "paths"), spec_paths)
            )
            crawled = filter_known_paths(_rows(crawl, "paths"), spec_paths)

            return (
                map_nuclei_findings(_rows(nuclei, "findings"))
                + map_discovered_paths(discovered)
                + map_nikto_findings(_rows(nikto, "findings"))
                + map_whatweb_findings(_rows(whatweb, "plugins"))
                + map_crawled_paths(crawled)
                + map_param_findings(_rows(params, "results"))
            )
        except Exception as exc:  # noqa: BLE001 — Kali is optional; never fail a scan
            log.warning("Kali pass failed; continuing without it", exc_info=True)
            self.error = f"{type(exc).__name__}: {exc}"
            return []
