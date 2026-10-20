"""Persisting what a run did: findings, the run archive, and per-endpoint coverage.

Re-running a scan *replaces* its live findings and events, so each run archives
a snapshot here to keep past results inspectable.
"""
from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Any

from app.core.jsonsafe import jsonb_safe
from app.core.redact import Redactor
from app.domain.enums import Confidence, Verdict
from app.engine.contracts import EngineFinding
from app.engine.fingerprint import fingerprint
from app.engine.probe import HttpProbe
from app.engine.remediation import remediate
from app.models.finding import Finding
from app.models.scan import Scan, ScanRun

#: How many trace sequence numbers a finding carries. A reviewer needs the calls
#: that made the case, not every request the check ever sent.
_MAX_TRACE_LINKS = 20


def _trace_links(
    trace: Sequence[dict[str, Any]] | None, ef: EngineFinding, evidence: dict[str, Any]
) -> list[int]:
    """Sequence numbers of the trace rows that produced this finding.

    Matching is by check *and* route, which is the finest attribution the probe
    records: a row knows which check was running (``check_context``) and which
    operation it hit. Without this a reviewer reading "BOLA on /orders/{id}" has
    to scroll a 600-row log looking for the two requests that prove it.

    Deliberately computed *after* the fingerprint, and deliberately not a
    fingerprint key: these numbers change every run, and identity must not.
    """
    if not trace:
        return []
    route = str(evidence.get("route") or evidence.get("path") or "")
    links = [
        int(row.get("sequence", 0))
        for row in trace
        if row.get("check") == ef.check and (not route or row.get("route") == route)
    ]
    return links[:_MAX_TRACE_LINKS]


def append_finding(
    scan: Scan,
    ef: EngineFinding,
    redactor: Redactor | None = None,
    trace: Sequence[dict[str, Any]] | None = None,
) -> None:
    """Persist one EngineFinding onto the scan, redacting secrets/PII first.

    Redaction is central here so no individual check has to remember it: the
    target's own reflected secrets and users' PII never reach the DB, run
    snapshots, or the PDF report. Remediation is filled here for the same
    reason — one place, from the per-check catalogue, shaped by the finding's
    (already redacted) evidence, so no check has to carry advice around.

    ``trace`` is the run's request trace so far (the probe's rows, or a local
    run's uploaded rows), used only to link the finding to the rows behind it;
    without one the finding records no links.
    """
    description = ef.description
    evidence = ef.evidence
    if redactor is not None:
        description = redactor.text(description)
        evidence = redactor.evidence(evidence)
    # Evidence quotes the target and the fuzzer; a NUL in either fails the
    # insert (text and jsonb columns both refuse it) and with it the whole run.
    title = jsonb_safe(ef.title)
    description = jsonb_safe(description)
    evidence = jsonb_safe(evidence)
    catalogue_text, references = remediate(ef.check, evidence)
    # A check that supplied its own text knows something the catalogue does not.
    remediation = ef.remediation or catalogue_text
    identity = fingerprint(ef.check, ef.owasp_id, title, evidence)
    # The discovery pass can encounter the same weakness through more than one
    # source. Keep one live/report row per stable identity; run diffs already
    # use this same key and should not be the first place duplicates disappear.
    if any(existing.fingerprint == identity for existing in scan.findings):
        return
    # After the fingerprint, never before: trace numbers are per-run.
    links = _trace_links(trace, ef, evidence)
    if links:
        evidence = {**evidence, "trace": links}
    scan.findings.append(
        Finding(
            operation_id=ef.operation_id,
            check=ef.check,
            fingerprint=identity,
            owasp_id=ef.owasp_id,
            severity=ef.severity,
            confidence=ef.confidence,
            title=title,
            description=description,
            evidence=evidence,
            remediation=remediation,
            references=references,
        )
    )


def record_triage(scan: Scan, finding: Finding, verdict: Verdict) -> None:
    """Remember a human's verdict against the finding's identity, not its row.

    The row is deleted on the next run; the fingerprint is not. Called from the
    triage endpoint so a dismissed false positive stays dismissed.
    """
    if not finding.fingerprint:
        return
    triage = dict(scan.triage or {})
    if verdict is Verdict.unreviewed:
        triage.pop(finding.fingerprint, None)
    else:
        triage[finding.fingerprint] = verdict.value
    scan.triage = triage


def apply_triage(scan: Scan) -> int:
    """Re-apply remembered verdicts to this run's findings. Returns how many.

    Runs *after* AI adjudication so a human's judgement outranks the model's on
    a finding both have looked at. A verdict remembered for a fingerprint this
    run did not produce is kept, not discarded: the finding may return when the
    endpoint is back in scope.
    """
    remembered = scan.triage or {}
    if not remembered:
        return 0
    applied = 0
    for f in scan.findings:
        raw = remembered.get(f.fingerprint or "")
        if raw is None:
            continue
        try:
            f.verdict = Verdict(raw)
        except ValueError:  # a verdict this version no longer knows
            continue
        applied += 1
    return applied


def finish_run(run: ScanRun, status: str, scan: Scan, probe: HttpProbe) -> None:
    """Archive the run: status, counts, a findings snapshot, and coverage."""
    run.status = status
    run.finished_at = datetime.now(UTC)
    # Includes passes that ran on their own budget and were merged in
    # (``HttpProbe.absorb``), so the reported count matches the request log.
    run.requests = probe.count + probe.secondary_requests
    run.findings_count = len(scan.findings)
    run.findings_snapshot = build_findings_snapshot(scan)
    run.coverage = build_coverage(scan, probe)
    run.mutations = list(probe.mutations)
    from app.engine.methodology import finish_manifest

    run.manifest = finish_manifest(probe)


def build_findings_snapshot(scan: Scan) -> list[dict[str, Any]]:
    """The archived per-finding snapshot a diff matches on. Shared by the server
    runner (``finish_run``) and the local-runner ingest, so both archive the
    same shape."""
    # The operation's method lets the diff tell a body-sink injection finding
    # (mutate-only) from a GET one sharing its check key. Discovered findings
    # have no operation and record none.
    methods = {str(op.id): op.method for op in scan.operations}
    return [
        {
            "check": f.check,
            "method": methods.get(str(f.operation_id)) if f.operation_id else None,
            # The identity a diff matches on; empty for rows from before it.
            "fingerprint": f.fingerprint or "",
            "severity": f.severity.value,
            # Column defaults are not on the in-memory object until a refresh,
            # so fall back the same way ``verdict`` does below.
            "confidence": (f.confidence or Confidence.heuristic).value,
            "title": f.title,
            "owasp_id": f.owasp_id,
            # verdict is a column default: not present on the in-memory
            # object until a refresh, so fall back for fresh findings.
            "verdict": (f.verdict or Verdict.unreviewed).value,
        }
        for f in scan.findings
    ]


def build_coverage(scan: Scan, probe: HttpProbe) -> list[dict[str, Any]]:
    """One row per operation: what the engine did to it this run.

    Covers *every* operation (enabled or not) so the report distinguishes
    "tested, nothing found" from "excluded from the run". ``requests`` and
    ``checks`` come from the probe's per-operation attribution; ``findings`` is
    the count of this run's findings attributed to the operation. Adjunct passes
    (ZAP/Kali/sqlmap) run outside the probe, so they are not reflected here.
    """
    finding_counts: dict[str, int] = {}
    for f in scan.findings:
        if f.operation_id is not None:
            oid = str(f.operation_id)
            finding_counts[oid] = finding_counts.get(oid, 0) + 1

    rows: list[dict[str, Any]] = []
    for op in scan.operations:
        oid = str(op.id)
        per_check = probe.coverage.get(oid, {})
        rows.append(
            {
                "operation_id": oid,
                "method": op.method,
                "path": op.path,
                "enabled": op.enabled,
                "requests": sum(per_check.values()),
                "checks": sorted(per_check),
                "findings": finding_counts.get(oid, 0),
            }
        )
    return rows
