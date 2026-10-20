"""Project-file config: which settings aidetector.yml owns, and where a run's came from."""
from __future__ import annotations

import pytest

from app.core.config import settings

DIGEST = "a" * 64
OTHER_DIGEST = "b" * 64


def _managed(**over):
    body = {
        "path": "aidetector.yml",
        "digest": DIGEST,
        "commit": "0123abc",
        "fields": ["target", "spec", "identities"],
        "identities": ["alice", "admin"],
    }
    return {**body, **over}


def test_a_new_scan_is_owned_by_the_web(client, new_scan):
    sid = new_scan()
    assert client.get(f"/scans/{sid}").json()["managed_config"] == {}


def test_managed_config_round_trips_and_clears(client, new_scan):
    sid = new_scan()
    r = client.put(f"/scans/{sid}/managed-config", json=_managed())
    assert r.status_code == 200, r.text
    got = client.get(f"/scans/{sid}").json()["managed_config"]
    assert got["fields"] == ["target", "spec", "identities"]
    assert got["identities"] == ["alice", "admin"]
    assert got["digest"] == DIGEST and got["commit"] == "0123abc"
    assert got["updated_at"]

    assert client.delete(f"/scans/{sid}/managed-config").status_code == 200
    assert client.get(f"/scans/{sid}").json()["managed_config"] == {}


@pytest.mark.parametrize(
    "bad",
    [
        {"digest": "not-a-digest"},
        {"fields": ["target", "authorized"]},  # consent is never a managed field
        {"commit": "zzz"},
        {"path": ""},
    ],
)
def test_managed_config_rejects_what_it_does_not_describe(client, new_scan, bad):
    sid = new_scan()
    assert client.put(f"/scans/{sid}/managed-config", json=_managed(**bad)).status_code == 422


def test_run_forwards_the_config_source_to_the_worker(client, scan_with_spec, monkeypatch):
    from app.api.routes import scans as routes

    sent: list[tuple[tuple, dict]] = []
    monkeypatch.setattr(
        routes.run_scan_task, "delay", lambda *a, **kw: sent.append((a, kw))
    )
    sid = scan_with_spec()
    source = {"path": "aidetector.yml", "digest": DIGEST, "commit": None}
    r = client.post(f"/scans/{sid}/run", json={"authorized": True, "config_source": source})
    assert r.status_code == 202, r.text
    assert sent[0][0] == (sid,) and set(sent[0][1]) == {"options"}
    assert sent[0][1]["options"]["config_source"] == source


def test_a_worker_that_predates_config_source_still_runs_the_scan():
    """Rolling deploys: a new API can enqueue for an old worker."""
    from app.scans.run_options import RunOptions

    message = {"mutate": True, "config_source": {"path": "aidetector.yml", "digest": DIGEST}}
    opts = RunOptions.from_dict(message)
    assert opts.mutate is True
    # Never archived as an option: the run records it in its own column.
    assert "config_source" not in opts.to_dict()


def test_the_worker_hands_the_config_source_to_the_run(db_session, make_scan, monkeypatch):
    from app.models.scan import ScanStatus
    from app.workers import tasks

    scan = make_scan()
    scan.status = ScanStatus.queued
    db_session.commit()
    seen: dict = {}

    def fake_run(db, claimed, *, options, config_source=None):
        seen["options"], seen["config_source"] = options, config_source
        return []

    monkeypatch.setattr(tasks, "run_scan", fake_run)
    source = {"path": "aidetector.yml", "digest": DIGEST, "commit": None}
    tasks.run_scan_task(str(scan.id), options={"fuzz": True, "config_source": source})
    assert seen["config_source"] == source
    assert seen["options"].fuzz is True


def test_a_web_run_sends_no_config_source(client, scan_with_spec, monkeypatch):
    from app.api.routes import scans as routes

    sent: list[dict] = []
    monkeypatch.setattr(routes.run_scan_task, "delay", lambda *a, **kw: sent.append(kw))
    sid = scan_with_spec()
    assert client.post(f"/scans/{sid}/run", json={"authorized": True}).status_code == 202
    assert "config_source" not in sent[0]["options"]


def test_config_source_is_still_behind_the_authorization_gate(client, scan_with_spec):
    sid = scan_with_spec()
    source = {"path": "aidetector.yml", "digest": DIGEST}
    r = client.post(f"/scans/{sid}/run", json={"authorized": False, "config_source": source})
    assert r.status_code == 403


def test_run_archives_its_config_source_and_the_diff_notices_a_change(
    client, db_session, make_scan, engine_client
):
    from app.engine.runner import run_scan

    scan = make_scan()
    source = {"path": "aidetector.yml", "digest": DIGEST, "commit": "0123abc"}
    run_scan(db_session, scan, client=engine_client, config_source=source)
    # Same file, a different commit: settings did not change.
    run_scan(
        db_session, scan, client=engine_client, config_source={**source, "commit": "4567def"}
    )
    runs = client.get(f"/scans/{scan.id}/runs").json()  # newest first
    assert runs[1]["config_source"] == source
    assert client.get(f"/scans/{scan.id}/diff").json()["config_changed"] is False

    # The file itself changed.
    run_scan(
        db_session, scan, client=engine_client, config_source={**source, "digest": OTHER_DIGEST}
    )
    assert client.get(f"/scans/{scan.id}/diff").json()["config_changed"] is True

    # Back to the web: also a change of source.
    run_scan(db_session, scan, client=engine_client)
    body = client.get(f"/scans/{scan.id}/diff").json()
    assert body["config_changed"] is True
    assert client.get(f"/scans/{scan.id}/runs").json()[0]["config_source"] == {}


def test_local_claim_archives_the_config_source(client, scan_with_spec, monkeypatch, db_session):
    from app.models.scan import Scan

    monkeypatch.setattr(settings, "local_runner_enabled", True)
    sid = scan_with_spec("http://127.0.0.1")
    source = {"path": "aidetector.yml", "digest": DIGEST, "commit": None}
    r = client.post(
        f"/scans/{sid}/local-runs", json={"authorized": True, "config_source": source}
    )
    assert r.status_code == 201, r.text
    db_session.expire_all()
    scan = db_session.get(Scan, sid)
    assert scan.runs[-1].config_source == source
    assert "config_source" not in scan.runs[-1].options
