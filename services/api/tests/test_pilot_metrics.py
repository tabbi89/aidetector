"""The pilot metrics are derived, value-free and stable enough to test."""
from __future__ import annotations

import csv
import io
import json
import uuid
from datetime import UTC, datetime, timedelta

import pytest

from app.domain.enums import AuthType, Confidence, Severity, Verdict
from app.models.credential import CredentialProfile
from app.models.finding import Finding
from app.models.scan import Scan, ScanRun, ScanStatus
from app.scans.pilot_metrics import (
    render_csv,
    render_json,
    summarize,
    summarize_scan,
)


def _at(minute: int, hour: int = 10) -> datetime:
    return datetime(2026, 1, 1, hour, minute, tzinfo=UTC)


def _scan(
    *,
    identities: int = 2,
    spec: bool = True,
    triage: dict[str, str] | None = None,
    findings: tuple[Finding, ...] = (),
    runs: tuple[ScanRun, ...] = (),
) -> Scan:
    scan = Scan(
        id=uuid.uuid4(),
        tenant_id="acme",
        target_base_url="http://target.test",
        status=ScanStatus.completed,
        created_at=_at(0),
        spec_uploaded_at=_at(5) if spec else None,
        triage=dict(triage or {}),
    )
    scan.credential_profiles = [
        CredentialProfile(
            name=f"user{i}",
            role="user",
            auth_type=AuthType.header,
            secret_ref="x",
        )
        for i in range(identities)
    ]
    scan.findings = list(findings)
    scan.runs = list(runs)
    return scan


def _finding(
    fingerprint: str,
    severity: Severity,
    confidence: Confidence,
    minute: int,
) -> Finding:
    return Finding(
        id=uuid.uuid4(),
        scan_id=uuid.uuid4(),
        check="bola",
        fingerprint=fingerprint,
        severity=severity,
        confidence=confidence,
        title="Fixture finding",
        created_at=_at(minute),
    )


def _run(
    number: int,
    started: int,
    *,
    finished: int | None = None,
    snapshot: tuple[dict, ...] = (),
    coverage: tuple[dict, ...] = (),
    options: dict | None = None,
    gaps: dict | None = None,
    status: str = "completed",
) -> ScanRun:
    return ScanRun(
        id=uuid.uuid4(),
        scan_id=uuid.uuid4(),
        run_number=number,
        status=status,
        started_at=_at(started),
        finished_at=_at(finished) if finished is not None else None,
        findings_snapshot=list(snapshot),
        coverage=list(coverage),
        options=dict(options or {}),
        gaps=dict(gaps or {}),
    )


def test_setup_funnel_and_time_to_first_useful_finding():
    scan = _scan(
        findings=(
            _finding("low", Severity.low, Confidence.verified, 10),
            _finding("heuristic", Severity.medium, Confidence.heuristic, 30),
            _finding("useful", Severity.medium, Confidence.verified, 45),
        ),
        runs=(_run(1, 20, finished=50),),
    )

    metrics = summarize_scan(scan)

    assert metrics.setup_complete is True
    assert metrics.setup_seconds == 20 * 60
    assert metrics.first_useful_finding_at == "2026-01-01T10:45:00+00:00"
    assert metrics.time_to_first_useful_seconds == 45 * 60


def test_setup_needs_two_non_anonymous_identities():
    scan = _scan(identities=1, runs=(_run(1, 20),))

    metrics = summarize_scan(scan)

    assert metrics.identities == 1
    assert metrics.setup_complete is False
    assert metrics.setup_seconds is None
    assert metrics.first_run_at == "2026-01-01T10:20:00+00:00"


def test_false_positive_rate_uses_remembered_triage():
    scan = _scan(
        triage={"a": "dismissed", "b": "confirmed", "c": "dismissed"},
        findings=(
            _finding("a", Severity.high, Confidence.verified, 10),
            _finding("b", Severity.high, Confidence.heuristic, 12),
            _finding("c", Severity.low, Confidence.verified, 14),
        ),
        runs=(_run(1, 20),),
    )

    metrics = summarize_scan(scan)

    assert (metrics.triaged, metrics.dismissed) == (3, 2)
    assert metrics.false_positive_rate == pytest.approx(2 / 3)
    assert (metrics.verified_triaged, metrics.verified_dismissed) == (2, 2)
    assert metrics.verified_false_positive_rate == 1.0


def test_coverage_separates_all_endpoints_from_enabled_ones():
    scan = _scan(
        runs=(
            _run(
                1,
                20,
                coverage=(
                    {"requests": 2, "enabled": True},
                    {"requests": 0, "enabled": True},
                    {"requests": 1, "enabled": False},
                ),
            ),
        ),
    )

    metrics = summarize_scan(scan)

    assert metrics.coverage_pct == pytest.approx(200 / 3)
    assert metrics.enabled_coverage_pct == 50.0


def test_a_resolved_finding_counts_as_a_verified_fix():
    older = _run(
        1,
        20,
        snapshot=(
            {
                "fingerprint": "a",
                "check": "bola",
                "severity": "high",
                "confidence": "verified",
            },
            {
                "fingerprint": "b",
                "check": "bola",
                "severity": "high",
                "confidence": "verified",
            },
        ),
    )
    newer = _run(
        2,
        40,
        snapshot=(
            {
                "fingerprint": "b",
                "check": "bola",
                "severity": "high",
                "confidence": "verified",
            },
        ),
    )

    assert summarize_scan(_scan(runs=(older, newer))).fixes_verified == 1
    assert (
        summarize_scan(_scan(runs=(older, newer), triage={"a": "dismissed"}))
        .fixes_verified
        == 0
    )


def test_a_pass_the_newer_run_dropped_is_not_a_fix():
    older = _run(
        1,
        20,
        snapshot=(
            {
                "fingerprint": "a",
                "check": "write_authz",
                "method": "PUT",
                "severity": "high",
                "confidence": "verified",
            },
        ),
        options={"mutate": True},
    )
    newer = _run(2, 40, options={})

    assert summarize_scan(_scan(runs=(older, newer))).fixes_verified == 0


def test_aggregate_and_rendering_are_value_free():
    complete = _scan(runs=(_run(1, 20),))
    incomplete = _scan(identities=1, spec=False)

    report = summarize([complete, incomplete], "acme")

    assert report.scans == 2
    assert report.setup_complete == 1
    assert report.setup_complete_rate == 0.5
    assert report.setup_seconds_median == 20 * 60

    payload = render_json(report)
    assert json.loads(payload)["tenant_id"] == "acme"
    assert "target.test" not in payload
    assert "Fixture finding" not in payload
    assert "evidence" not in payload

    rows = list(csv.DictReader(io.StringIO(render_csv(report))))
    assert len(rows) == 2
    assert rows[0]["scan_id"] == str(complete.id)


def test_setup_timestamps_are_written(client, db_session, scan_with_spec):
    sid = scan_with_spec()
    db_session.expire_all()
    scan = db_session.get(Scan, uuid.UUID(sid))
    assert scan is not None
    assert scan.spec_uploaded_at is not None

    response = client.post(
        f"/scans/{sid}/credentials",
        json={
            "name": "alice",
            "role": "user",
            "auth_type": "bearer",
            "secret": "alice-token",
        },
    )
    assert response.status_code == 201, response.text
    credential = db_session.get(
        CredentialProfile, uuid.UUID(response.json()["id"])
    )
    assert credential is not None
    assert credential.created_at is not None


def test_first_useful_finding_uses_the_earliest_supported_evidence():
    start = datetime(2026, 1, 1, 10, 0, tzinfo=UTC)
    scan = Scan(
        id=uuid.uuid4(),
        tenant_id="default",
        target_base_url="http://unused.test",
        status=ScanStatus.completed,
        created_at=start,
        triage={},
    )
    scan.credential_profiles = []
    scan.findings = [
        Finding(
            id=uuid.uuid4(),
            check="bola",
            title="fixture",
            fingerprint="same",
            severity=Severity.medium,
            confidence=Confidence.verified,
            created_at=start + timedelta(hours=1),
            verdict=Verdict.unreviewed,
        )
    ]
    scan.runs = [
        ScanRun(
            id=uuid.uuid4(),
            run_number=1,
            status="completed",
            started_at=start + timedelta(minutes=5),
            finished_at=start + timedelta(minutes=15),
            findings_snapshot=[
                {
                    "fingerprint": "same",
                    "check": "bola",
                    "severity": "medium",
                    "confidence": "verified",
                }
            ],
            coverage=[],
            options={},
            gaps={},
        )
    ]
    result = summarize_scan(scan)
    assert result.time_to_first_useful_seconds == 900
