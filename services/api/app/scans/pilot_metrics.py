"""Value-free pilot metrics derived from rows the scanner already keeps.

The pilot asks five questions, and each has a precise definition here:

- **Setup complete** — a spec was uploaded, at least two non-anonymous identities
  exist, and a run started. ``setup_seconds`` is scan creation → first run.
- **Time to first useful finding** — scan creation → the first finding at or above
  ``min_severity`` (default medium) with verified evidence. If a re-run replaced
  the live findings, the finish of the first run whose snapshot had one is used
  as the honest upper bound.
- **False-positive rate** — dismissed ÷ (dismissed + confirmed) over the scan's
  remembered triage. A verified-only rate is reported separately.
- **Exercised endpoint coverage** — the latest run's enabled operations with at
  least one request, as a percentage.
- **Fixes verified** — findings resolved between the last two completed runs,
  excluding dismissed findings and rows a newer run could not have re-tested
  (a dropped pass, a narrowed check scope, or a spent tool/request budget).

Nothing here reads an evidence body, target URL, finding title or credential
material. The output is safe to share outside the deployment.
"""
from __future__ import annotations

import csv
import io
import json
from collections.abc import Callable, Iterable, Sequence
from dataclasses import asdict, dataclass
from datetime import UTC, date, datetime, time
from statistics import median
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from app.domain.enums import SEVERITY_RANK, AuthType, Confidence, Severity, Verdict
from app.models.finding import Finding
from app.models.scan import Scan, ScanRun
from app.scans.diff import diff_snapshots
from app.scans.run_options import (
    RunOptions,
    descoped,
    dropped_passes,
    required_passes,
    snapshot_signal,
    unperformed,
)


@dataclass(frozen=True)
class ScanMetrics:
    """One scan's contribution to the pilot report."""

    scan_id: str
    tenant_id: str
    status: str
    created_at: str
    spec_uploaded_at: str | None
    identities: int
    runs: int
    first_run_at: str | None
    setup_complete: bool
    setup_seconds: float | None
    first_useful_finding_at: str | None
    time_to_first_useful_seconds: float | None
    live_findings: int
    verified_findings: int
    triaged: int
    dismissed: int
    false_positive_rate: float | None
    verified_triaged: int
    verified_dismissed: int
    verified_false_positive_rate: float | None
    coverage_pct: float | None
    enabled_coverage_pct: float | None
    fixes_verified: int


@dataclass(frozen=True)
class PilotReport:
    """Aggregate plus per-scan rows for one tenant."""

    tenant_id: str
    since: str | None
    generated_at: str
    scans: int
    setup_complete: int
    setup_complete_rate: float | None
    setup_seconds_median: float | None
    time_to_first_useful_seconds_median: float | None
    triaged: int
    dismissed: int
    false_positive_rate: float | None
    verified_triaged: int
    verified_dismissed: int
    verified_false_positive_rate: float | None
    enabled_coverage_pct_median: float | None
    fixes_verified: int
    per_scan: list[ScanMetrics]


def _as_utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


def _iso(value: datetime | None) -> str | None:
    value = _as_utc(value)
    return value.isoformat() if value is not None else None


def _seconds(later: datetime | None, earlier: datetime | None) -> float | None:
    later, earlier = _as_utc(later), _as_utc(earlier)
    if later is None or earlier is None:
        return None
    return max(0.0, (later - earlier).total_seconds())


def _median(values: Iterable[float | None]) -> float | None:
    present = [value for value in values if value is not None]
    return median(present) if present else None


def _ordered_runs(scan: Scan) -> list[ScanRun]:
    return sorted(
        scan.runs,
        key=lambda run: (
            run.run_number,
            _as_utc(run.started_at) or datetime.min.replace(tzinfo=UTC),
        ),
    )


def _finding_is_useful(
    finding: Finding, min_severity: Severity, verified_only: bool
) -> bool:
    if SEVERITY_RANK[finding.severity] < SEVERITY_RANK[min_severity]:
        return False
    return not verified_only or finding.confidence is Confidence.verified


def _snapshot_is_useful(
    row: dict[str, Any], min_severity: Severity, verified_only: bool
) -> bool:
    try:
        severity = Severity(str(row.get("severity")))
    except ValueError:
        return False
    if SEVERITY_RANK[severity] < SEVERITY_RANK[min_severity]:
        return False
    if not verified_only:
        return True
    try:
        confidence = Confidence(
            str(row.get("confidence") or Confidence.heuristic.value)
        )
    except ValueError:
        return False
    return confidence is Confidence.verified


def _first_useful_finding_at(
    scan: Scan, min_severity: Severity, verified_only: bool
) -> datetime | None:
    # A live finding's created_at is exact. An archived snapshot bounds the
    # discovery from above (found at or before its run finished). A re-run
    # replaces live rows, so the *earliest* supported evidence can be in the
    # archive — considering only live rows reported a rerun's later timestamp.
    candidates = [
        finding.created_at
        for finding in scan.findings
        if _finding_is_useful(finding, min_severity, verified_only)
    ]
    for run in _ordered_runs(scan):
        if any(
            _snapshot_is_useful(row, min_severity, verified_only)
            for row in (run.findings_snapshot or [])
        ):
            candidates.append(run.finished_at or run.started_at)
    return min(candidates) if candidates else None


def _confidence_index(scan: Scan) -> dict[str, Confidence]:
    """Fingerprint → the newest confidence seen for it, snapshots then live rows."""
    index: dict[str, Confidence] = {}
    for run in _ordered_runs(scan):
        for row in run.findings_snapshot or []:
            fingerprint = str(row.get("fingerprint") or "")
            if not fingerprint:
                continue
            try:
                index[fingerprint] = Confidence(
                    str(row.get("confidence") or Confidence.heuristic.value)
                )
            except ValueError:
                index[fingerprint] = Confidence.heuristic
    for finding in scan.findings:
        if finding.fingerprint:
            index[finding.fingerprint] = finding.confidence
    return index


def _triage_metrics(scan: Scan) -> dict[str, int | float | None]:
    triage = {str(key): str(value) for key, value in (scan.triage or {}).items()}
    dismissed = sum(1 for value in triage.values() if value == Verdict.dismissed.value)
    confirmed = sum(1 for value in triage.values() if value == Verdict.confirmed.value)
    triaged = dismissed + confirmed

    verified = {
        fingerprint
        for fingerprint, confidence in _confidence_index(scan).items()
        if confidence is Confidence.verified
    }
    verified_dismissed = sum(
        1
        for fingerprint, value in triage.items()
        if fingerprint in verified and value == Verdict.dismissed.value
    )
    verified_confirmed = sum(
        1
        for fingerprint, value in triage.items()
        if fingerprint in verified and value == Verdict.confirmed.value
    )
    verified_triaged = verified_dismissed + verified_confirmed
    return {
        "triaged": triaged,
        "dismissed": dismissed,
        "false_positive_rate": dismissed / triaged if triaged else None,
        "verified_triaged": verified_triaged,
        "verified_dismissed": verified_dismissed,
        "verified_false_positive_rate": (
            verified_dismissed / verified_triaged if verified_triaged else None
        ),
    }


def _coverage_metrics(scan: Scan) -> tuple[float | None, float | None]:
    runs = _ordered_runs(scan)
    if not runs:
        return None, None
    rows = runs[-1].coverage or []
    if not rows:
        return None, None
    exercised = sum(1 for row in rows if int(row.get("requests") or 0) > 0)
    enabled = [row for row in rows if bool(row.get("enabled", True))]
    enabled_exercised = sum(
        1 for row in enabled if int(row.get("requests") or 0) > 0
    )
    return (
        100.0 * exercised / len(rows),
        100.0 * enabled_exercised / len(enabled) if enabled else None,
    )


def _fixes_verified(scan: Scan) -> int:
    runs = [run for run in _ordered_runs(scan) if run.status == "completed"]
    if len(runs) < 2:
        return 0
    older, newer = runs[-2], runs[-1]
    dropped = dropped_passes(older.options, newer.options)
    scoped = bool(RunOptions.from_dict(newer.options).checks)
    gaps = newer.gaps or {}
    predicate: Callable[[dict[str, Any]], bool] | None = None
    if dropped or scoped or gaps:

        def _not_retested(row: dict[str, Any]) -> bool:
            check = str(row.get("check") or "")
            return (
                bool(required_passes(check, row.get("method"), snapshot_signal(row)) & dropped)
                or descoped(check, older.options, newer.options)
                or unperformed(check, gaps)
            )

        predicate = _not_retested

    result = diff_snapshots(
        older.findings_snapshot or [],
        newer.findings_snapshot or [],
        not_retested=predicate,
    )
    triage = scan.triage or {}
    return sum(
        1
        for row in result.resolved
        if row.get("fingerprint")
        and triage.get(str(row["fingerprint"])) != Verdict.dismissed.value
    )


def summarize_scan(
    scan: Scan,
    *,
    min_severity: Severity = Severity.medium,
    verified_only: bool = True,
) -> ScanMetrics:
    """Derive one scan's pilot metrics. Expects its relationships loaded."""
    created = _as_utc(scan.created_at)
    runs = _ordered_runs(scan)
    first_run = _as_utc(runs[0].started_at) if runs else None
    identities = sum(
        1
        for profile in scan.credential_profiles
        if profile.auth_type is not AuthType.none
    )
    spec = _as_utc(scan.spec_uploaded_at)
    setup_complete = bool(spec and identities >= 2 and first_run)
    useful = _first_useful_finding_at(scan, min_severity, verified_only)
    triage = _triage_metrics(scan)
    coverage, enabled_coverage = _coverage_metrics(scan)
    status = getattr(scan.status, "value", str(scan.status))
    return ScanMetrics(
        scan_id=str(scan.id),
        tenant_id=scan.tenant_id,
        status=str(status),
        created_at=_iso(created) or "",
        spec_uploaded_at=_iso(spec),
        identities=identities,
        runs=len(runs),
        first_run_at=_iso(first_run),
        setup_complete=setup_complete,
        setup_seconds=_seconds(first_run, created) if setup_complete else None,
        first_useful_finding_at=_iso(useful),
        time_to_first_useful_seconds=_seconds(useful, created),
        live_findings=len(scan.findings),
        verified_findings=sum(
            1
            for finding in scan.findings
            if finding.confidence is Confidence.verified
        ),
        triaged=int(triage["triaged"] or 0),
        dismissed=int(triage["dismissed"] or 0),
        false_positive_rate=(
            float(triage["false_positive_rate"])
            if triage["false_positive_rate"] is not None
            else None
        ),
        verified_triaged=int(triage["verified_triaged"] or 0),
        verified_dismissed=int(triage["verified_dismissed"] or 0),
        verified_false_positive_rate=(
            float(triage["verified_false_positive_rate"])
            if triage["verified_false_positive_rate"] is not None
            else None
        ),
        coverage_pct=coverage,
        enabled_coverage_pct=enabled_coverage,
        fixes_verified=_fixes_verified(scan),
    )


def summarize(
    scans: Sequence[Scan],
    tenant_id: str,
    since: date | None = None,
    *,
    min_severity: Severity = Severity.medium,
    verified_only: bool = True,
) -> PilotReport:
    """Aggregate the per-scan metrics for one tenant."""
    per_scan = [
        summarize_scan(scan, min_severity=min_severity, verified_only=verified_only)
        for scan in scans
    ]
    total = len(per_scan)
    complete = sum(1 for metrics in per_scan if metrics.setup_complete)
    triaged = sum(metrics.triaged for metrics in per_scan)
    dismissed = sum(metrics.dismissed for metrics in per_scan)
    verified_triaged = sum(metrics.verified_triaged for metrics in per_scan)
    verified_dismissed = sum(metrics.verified_dismissed for metrics in per_scan)
    return PilotReport(
        tenant_id=tenant_id,
        since=since.isoformat() if since else None,
        generated_at=datetime.now(UTC).isoformat(),
        scans=total,
        setup_complete=complete,
        setup_complete_rate=complete / total if total else None,
        setup_seconds_median=_median(
            metrics.setup_seconds for metrics in per_scan
        ),
        time_to_first_useful_seconds_median=_median(
            metrics.time_to_first_useful_seconds for metrics in per_scan
        ),
        triaged=triaged,
        dismissed=dismissed,
        false_positive_rate=dismissed / triaged if triaged else None,
        verified_triaged=verified_triaged,
        verified_dismissed=verified_dismissed,
        verified_false_positive_rate=(
            verified_dismissed / verified_triaged if verified_triaged else None
        ),
        enabled_coverage_pct_median=_median(
            metrics.enabled_coverage_pct for metrics in per_scan
        ),
        fixes_verified=sum(metrics.fixes_verified for metrics in per_scan),
        per_scan=per_scan,
    )


def load_scans(
    db: Session, tenant_id: str, since: date | None = None
) -> list[Scan]:
    """Load one tenant's scans with everything the metrics read. Read-only."""
    stmt = (
        select(Scan)
        .where(Scan.tenant_id == tenant_id)
        .options(
            selectinload(Scan.runs),
            selectinload(Scan.findings),
            selectinload(Scan.credential_profiles),
        )
        .order_by(Scan.created_at)
    )
    if since is not None:
        stmt = stmt.where(
            Scan.created_at >= datetime.combine(since, time.min, tzinfo=UTC)
        )
    return list(db.scalars(stmt).all())


def render_json(report: PilotReport) -> str:
    return json.dumps(asdict(report), indent=2, sort_keys=True)


def render_csv(report: PilotReport) -> str:
    """One row per scan. Use JSON when the aggregate figures are wanted."""
    out = io.StringIO()
    fields = list(ScanMetrics.__dataclass_fields__)
    writer = csv.DictWriter(out, fieldnames=fields)
    writer.writeheader()
    for metrics in report.per_scan:
        writer.writerow(asdict(metrics))
    return out.getvalue()
