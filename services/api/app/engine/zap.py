"""OWASP ZAP integration — an opt-in, heavier parallel active scanner.

ZAP runs as a separate daemon (see ``docker-compose.yml``, ``zap`` profile) and
is driven over its JSON REST API: spider the target, run the active scanner,
then pull alerts and map them into :class:`EngineFinding`.

Spidering starts from the base URL **and** the scan's rendered operation URLs
(``spec_urls``): an API's base URL usually links to nothing, so without the
spec's paths ZAP's Sites tree — and therefore its active scan — would cover
only the root, robots.txt and sitemap, never the documented endpoints.

Two things make this deliberately a *side path*, not a check in ``ALL_CHECKS``:

- **ZAP ignores the engine's 750-request budget and cooperative cancellation.**
  Its active scanner floods the target on its own schedule; we can only bound it
  with a wall-clock timeout. So a ZAP pass is gated behind an explicit opt-in and
  documented as operating outside the engine's rate-safety guarantees.
- It **degrades gracefully**, like the AI cascade and OOB: any failure (daemon
  down, API error, timeout) logs and returns no findings, never failing a scan.

``map_alerts`` is pure and unit-tested; the network dance is thin around it.
"""
from __future__ import annotations

import logging
import time
from collections.abc import Sequence
from typing import Any, Protocol
from urllib.parse import urlsplit, urlunsplit

from app.domain.enums import Confidence, Severity
from app.engine.base import EngineFinding

log = logging.getLogger("aidetector.zap")

# Cap on seeded operation URLs so a huge spec cannot queue unbounded spiders.
_MAX_SEED_URLS = 20

# ZAP "risk" strings → our severity ladder.
_RISK_TO_SEVERITY = {
    "high": Severity.high,
    "medium": Severity.medium,
    "low": Severity.low,
    "informational": Severity.info,
    "info": Severity.info,
}


class ZapHttp(Protocol):
    """Minimal transport contract (an ``httpx.Client`` satisfies it)."""

    def get(self, url: Any, **kwargs: Any) -> Any: ...


def alert_location(url: str) -> str:
    """The part of an alert's URL that identifies *where*, not *what was sent*.

    ``ZapScanner`` runs an **active** scan, so an alert's URL carries the
    payload that triggered it: ``/items?id=1%27+OR+1%3D1``. Keeping the query
    would make every re-run report the same alert as fixed-and-new, because the
    payload rotates — exactly the churn ``engine/fingerprint`` exists to
    prevent. Scheme, host and path are what a person means by "where".
    """
    try:
        parts = urlsplit(url)
    except ValueError:
        return url[:500]
    if not parts.scheme and not parts.netloc:
        return url.split("?", 1)[0][:500]
    return urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))[:500]


def map_alerts(alerts: list[dict[str, Any]]) -> list[EngineFinding]:
    """Map ZAP alert records into engine findings. Pure — no I/O.

    ZAP re-reports the same alert once per payload it tried — the passive "User
    Agent Fuzzer" plugin alone returns a dozen per URL, and the active scanner
    reports one per injected value, each with a *different* URL. One finding per
    alert-name/location/param is the right granularity for a findings list, so
    duplicates sharing that triple collapse to the first. Collapsing on the
    location rather than the raw URL is what makes this work for the active
    scan: those duplicates differ only in the query string.
    """
    findings: list[EngineFinding] = []
    seen: set[tuple[str, str, str]] = set()
    for a in alerts:
        risk = str(a.get("risk", "")).strip().lower()
        # ZAP sometimes returns "High (Medium)" confidence-annotated strings.
        risk = risk.split(" ", 1)[0]
        severity = _RISK_TO_SEVERITY.get(risk, Severity.info)
        name = str(a.get("alert") or a.get("name") or "ZAP alert")
        url = str(a.get("url") or "")
        location = alert_location(url)
        param = str(a.get("param") or "")
        identity = (name, location, param)
        if identity in seen:
            continue
        seen.add(identity)
        cwe = a.get("cweid")
        findings.append(
            EngineFinding(
                check="zap",
                confidence=Confidence.verified,
                owasp_id=f"CWE-{cwe}" if cwe and str(cwe) != "-1" else None,
                severity=severity,
                title=f"ZAP: {name}",
                description=(
                    str(a.get("description", "")).strip()
                    or "Reported by the OWASP ZAP active scanner."
                ),
                # ZAP's own solution is alert-specific — better than anything the
                # catalogue can say about "a ZAP alert" in general. Falls back to
                # the catalogue entry when the alert carries none.
                remediation=str(a.get("solution", "")).strip()[:2000],
                evidence={
                    # `name` is part of the finding's identity: two alerts that
                    # share a location and param but not a plugin are different
                    # bugs. `location` is identity; `url` is the full attacked
                    # URL, kept for the reader and deliberately *not* identity —
                    # it carries the payload.
                    "name": name,
                    "location": location,
                    "url": url,
                    "param": param,
                    "attack": a.get("attack"),
                    "evidence": a.get("evidence"),
                    "plugin_id": a.get("pluginId"),
                    "cweid": cwe,
                    "wascid": a.get("wascid"),
                    "solution": str(a.get("solution", ""))[:1000],
                    "source": "zap",
                },
            )
        )
    return findings


class ZapScanner:
    """Drives a ZAP daemon through spider → active-scan → alerts.

    ``http`` is any client exposing ``.get(url).json()`` / ``.status_code``.
    """

    def __init__(
        self,
        base_url: str,
        *,
        api_key: str = "",
        http: ZapHttp,
        timeout_seconds: int = 600,
        poll_seconds: float = 3.0,
    ) -> None:
        self._base = base_url.rstrip("/")
        self._key = api_key
        self._http = http
        self._timeout = timeout_seconds
        # Why the last run returned nothing, when it failed rather than found
        # nothing. The caller reports it: an empty list alone reads as clean.
        self.error: str | None = None
        self._poll = poll_seconds

    def _api(self, path: str, **params: Any) -> dict[str, Any]:
        if self._key:
            params.setdefault("apikey", self._key)
        r = self._http.get(f"{self._base}{path}", params=params)
        if getattr(r, "status_code", 200) >= 400:
            raise RuntimeError(f"ZAP API {path} -> {r.status_code}")
        return r.json()

    def _await_scan(self, status_path: str, scan_id: str, deadline: float) -> None:
        while time.monotonic() < deadline:
            status = self._api(status_path, scanId=scan_id).get("status", "0")
            if str(status) == "100":
                return
            time.sleep(self._poll)
        raise TimeoutError("ZAP scan did not finish within the timeout")

    def run(
        self, target_url: str, *, spec_urls: Sequence[str] = ()
    ) -> list[EngineFinding]:
        """Spider + active-scan ``target_url``; return mapped findings.

        ``spec_urls`` are the scan's rendered operation URLs; each is added as
        a spider seed so the active scan reaches the API paths the spec
        documents (an API's base URL typically links to nothing).

        Best-effort: on any error returns ``[]`` so the scan still completes.
        """
        deadline = time.monotonic() + self._timeout
        try:
            spider_id = str(self._api("/JSON/spider/action/scan/", url=target_url).get("scan", "0"))
            self._await_scan("/JSON/spider/view/status/", spider_id, deadline)

            seen = {target_url}
            seeds = 0
            for url in spec_urls:
                if seeds >= _MAX_SEED_URLS:
                    break
                if not url or url in seen:
                    continue
                seen.add(url)
                seeds += 1
                seed_id = str(self._api("/JSON/spider/action/scan/", url=url).get("scan", "0"))
                self._await_scan("/JSON/spider/view/status/", seed_id, deadline)

            ascan_id = str(self._api("/JSON/ascan/action/scan/", url=target_url).get("scan", "0"))
            self._await_scan("/JSON/ascan/view/status/", ascan_id, deadline)

            alerts = self._api("/JSON/core/view/alerts/", baseurl=target_url).get("alerts", [])
            return map_alerts(alerts if isinstance(alerts, list) else [])
        except Exception as exc:  # noqa: BLE001 — ZAP is optional; never fail a scan
            log.warning("ZAP pass failed; continuing without ZAP findings", exc_info=True)
            self.error = f"{type(exc).__name__}: {exc}"
            return []
