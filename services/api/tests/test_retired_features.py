"""Retiring telemetry removes its public and scheduled execution paths."""
from __future__ import annotations

from app.main import app
from app.models import Base
from app.notifications.events import KNOWN_EVENTS
from app.workers.celery_app import celery


def test_infrastructure_monitoring_is_no_longer_exposed_or_scheduled(client):
    assert not any(path.startswith("/monitoring") for path in app.openapi()["paths"])
    assert client.get("/monitoring").status_code == 404
    assert client.post("/monitoring/setup", json={}).status_code == 404
    assert client.post("/monitoring/mcp", json={}).status_code == 404
    assert not any("monitoring" in name for name in celery.conf.beat_schedule)
    assert not any("monitoring" in name for name in celery.tasks)
    assert not {"monitor.alert", "monitor.recovered"} & KNOWN_EVENTS
    assert not {
        "infrastructure_monitors", "monitoring_runs", "monitoring_rapid_runs",
        "monitoring_alerts", "evidence_sources", "evidence_audit",
    } & set(Base.metadata.tables)
