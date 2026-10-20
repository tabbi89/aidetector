"""Opaque active-run correlation: references enrich, never promote, evidence."""

from __future__ import annotations

import hashlib
import hmac
import secrets

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.monitoring import InfrastructureMonitor
from app.models.scan import Scan, ScanRun
from app.monitoring.service import _monitoring_salt
from app.monitoring.waf import NormalizedWafEvent


def configure_probe(db: Session, scan: Scan, probe) -> None:
    linked = db.scalar(
        select(InfrastructureMonitor.id)
        .where(
            InfrastructureMonitor.scan_id == scan.id,
            InfrastructureMonitor.tenant_id == scan.tenant_id,
            InfrastructureMonitor.status == "active",
        )
        .limit(1)
    )
    if linked is None:
        return
    token = secrets.token_hex(16)
    probe.set_correlation_id(token)
    probe.manifest["monitoring_correlation_hash"] = hmac.new(
        _monitoring_salt(scan.tenant_id), token.encode(), hashlib.sha256
    ).hexdigest()


def correlate(
    db: Session, monitor: InfrastructureMonitor, events: list[NormalizedWafEvent]
) -> list[dict]:
    if not monitor.scan_id or not events:
        return []
    scan = db.get(Scan, monitor.scan_id)
    if scan is None or scan.tenant_id != monitor.tenant_id:
        return []
    hashes = {event.correlation_hash for event in events if event.correlation_hash}
    results = []
    for run in db.scalars(
        select(ScanRun)
        .where(ScanRun.scan_id == scan.id)
        .order_by(ScanRun.run_number.desc())
        .limit(30)
    ):
        if run.manifest.get("monitoring_correlation_hash") not in hashes:
            continue
        results.append(
            {
                "scan_id": str(scan.id),
                "run_number": run.run_number,
                "match": "exact_run_token",
                "findings": [
                    {
                        "fingerprint": finding.get("fingerprint"),
                        "check": finding.get("check"),
                        "confidence": finding.get("confidence", "heuristic"),
                    }
                    for finding in run.findings_snapshot[:200]
                ],
            }
        )
    return results
