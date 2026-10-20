"""Server-side finding filters: severity, check, verdict, confidence, search."""
from __future__ import annotations

from app.domain.enums import Confidence, Severity, Verdict
from app.models.finding import Finding


def _finding(
    scan_id,
    fingerprint: str,
    *,
    severity: Severity,
    check: str,
    title: str,
    confidence: Confidence = Confidence.verified,
    verdict: Verdict = Verdict.unreviewed,
) -> Finding:
    return Finding(
        scan_id=scan_id,
        check=check,
        severity=severity,
        confidence=confidence,
        title=title,
        fingerprint=fingerprint,
        verdict=verdict,
    )


def test_findings_filters_run_in_the_query(client, db_session, make_scan):
    scan = make_scan()
    db_session.add_all(
        [
            _finding(
                scan.id,
                "high",
                severity=Severity.high,
                check="bola",
                title="BOLA account",
            ),
            _finding(
                scan.id,
                "low",
                severity=Severity.low,
                check="security_headers",
                title="Missing headers",
                confidence=Confidence.heuristic,
                verdict=Verdict.dismissed,
            ),
            _finding(
                scan.id,
                "medium",
                severity=Severity.medium,
                check="bfla",
                title="Admin role accepted",
            ),
        ]
    )
    db_session.commit()
    base = f"/scans/{scan.id}/findings"

    assert [
        row["fingerprint"]
        for row in client.get(f"{base}?severity=high").json()
    ] == ["high"]
    assert [
        row["fingerprint"] for row in client.get(f"{base}?check=bfla").json()
    ] == ["medium"]
    assert [
        row["fingerprint"]
        for row in client.get(f"{base}?confidence=verified").json()
    ] == ["high", "medium"]
    assert [
        row["fingerprint"]
        for row in client.get(f"{base}?verdict=dismissed").json()
    ] == ["low"]
    assert [
        row["fingerprint"]
        for row in client.get(f"{base}?q=admin").json()
    ] == ["medium"]
    assert len(client.get(f"{base}?include_dismissed=false").json()) == 2
    assert len(client.get(f"{base}?limit=1&offset=1").json()) == 1

    assert client.get(f"{base}/summary").json() == {
        "total": 3,
        "active": 2,
        "dismissed": 1,
        "verified_critical": 0,
        "verified_high": 1,
        "severity": {"high": 1, "medium": 1},
    }


def test_endpoint_text_search_matches_the_operation_path(
    client, db_session, make_scan
):
    scan = make_scan()
    operation = scan.operations[0]
    db_session.add(
        Finding(
            scan_id=scan.id,
            operation_id=operation.id,
            check="bola",
            title="Generic test",
            description="Fixture",
            severity=Severity.high,
            confidence=Confidence.verified,
        )
    )
    db_session.commit()
    rows = client.get(
        f"/scans/{scan.id}/findings", params={"q": operation.path}
    ).json()
    assert len(rows) == 1
    assert rows[0]["title"] == "Generic test"


def test_endpoint_search_matches_the_rendered_label(client, db_session, make_scan):
    scan = make_scan()
    operation = scan.operations[0]
    db_session.add_all([
        Finding(
            scan_id=scan.id,
            operation_id=operation.id,
            check="bola",
            title="Operation finding",
            description="Fixture",
            severity=Severity.high,
            confidence=Confidence.verified,
        ),
        # An adjunct finding: no operation, only what its evidence hit.
        Finding(
            scan_id=scan.id,
            check="zap",
            title="Evidence finding",
            description="Fixture",
            severity=Severity.low,
            confidence=Confidence.heuristic,
            evidence={"method": "post", "path": "/shadow/admin"},
        ),
    ])
    db_session.commit()

    def search(q: str) -> list[str]:
        rows = client.get(f"/scans/{scan.id}/findings", params={"q": q}).json()
        return sorted(row["title"] for row in rows)

    label = f"{operation.method.upper()} {operation.path}"
    assert search(label) == ["Operation finding"]
    assert search(label.lower()) == ["Operation finding"]
    assert search("POST /shadow/admin") == ["Evidence finding"]
    assert search("/shadow") == ["Evidence finding"]

    def by_endpoint(label: str) -> list[str]:
        rows = client.get(
            f"/scans/{scan.id}/findings", params={"endpoint": label}
        ).json()
        return sorted(row["title"] for row in rows)

    # Selecting an endpoint filters on the label itself, so an evidence-only
    # endpoint (no operation id to send) narrows the list too.
    assert by_endpoint(label) == ["Operation finding"]
    assert by_endpoint("POST /shadow/admin") == ["Evidence finding"]
    assert by_endpoint("GET /nowhere") == []


def test_findings_pages_do_not_overlap_on_ties(client, db_session, make_scan):
    scan = make_scan()
    db_session.add_all(
        [
            Finding(
                scan_id=scan.id,
                check="bola",
                title=f"Tied {i}",
                severity=Severity.high,
                confidence=Confidence.verified,
            )
            for i in range(6)
        ]
    )
    db_session.commit()
    base = f"/scans/{scan.id}/findings"
    first = client.get(base, params={"limit": 3, "offset": 0}).json()
    second = client.get(base, params={"limit": 3, "offset": 3}).json()
    ids = [row["id"] for row in first + second]
    assert len(ids) == 6
    assert len(set(ids)) == 6
