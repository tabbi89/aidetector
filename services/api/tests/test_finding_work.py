"""Finding work items and comments — the premium team-triage workflow.

A work item is keyed by the finding's fingerprint, not its row: a re-run replaces
the rows and the owner/due date/discussion must follow the weakness. These tests
pin that identity, the partial-update semantics, tenant scoping through the scan,
and the cascade that keeps orphan rows out of the database.
"""
from __future__ import annotations

import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select

from app.domain.enums import Severity
from app.models.finding import Finding
from app.models.finding_work import FindingComment, FindingWork


@pytest.fixture
def live_finding(db_session, new_scan):
    """A scan with one current finding; returns (scan id, fingerprint)."""

    def _make(fingerprint: str = "fp-bola-1") -> tuple[str, str]:
        sid = new_scan()
        db_session.add(
            Finding(
                scan_id=uuid.UUID(sid),
                check="bola",
                severity=Severity.high,
                title="object read across tenants",
                description="d",
                evidence={},
                fingerprint=fingerprint,
            )
        )
        db_session.commit()
        return sid, fingerprint

    return _make


def test_work_item_round_trip(client: TestClient, live_finding):
    sid, fp = live_finding()

    created = client.put(
        f"/scans/{sid}/findings/{fp}/work",
        json={"owner": "alice", "due_date": "2026-11-01", "status": "in_progress"},
    )
    assert created.status_code == 200, created.text
    item = created.json()
    assert item["owner"] == "alice"
    assert item["due_date"] == "2026-11-01"
    assert item["status"] == "in_progress"
    assert item["comments"] == []

    listed = client.get(f"/scans/{sid}/work")
    assert listed.status_code == 200
    assert [(row["fingerprint"], row["owner"]) for row in listed.json()] == [(fp, "alice")]


def test_an_omitted_field_is_unchanged_and_null_clears(client: TestClient, live_finding):
    sid, fp = live_finding()
    client.put(
        f"/scans/{sid}/findings/{fp}/work",
        json={"owner": "alice", "due_date": "2026-11-01", "status": "open"},
    )

    # Owner only: the other two keep their values.
    partial = client.put(f"/scans/{sid}/findings/{fp}/work", json={"owner": "bob"}).json()
    assert (partial["owner"], partial["due_date"], partial["status"]) == (
        "bob",
        "2026-11-01",
        "open",
    )

    # Explicit null clears the assignment, but status is not nullable.
    cleared = client.put(
        f"/scans/{sid}/findings/{fp}/work", json={"owner": None, "due_date": None}
    ).json()
    assert (cleared["owner"], cleared["due_date"], cleared["status"]) == (None, None, "open")


def test_work_is_only_accepted_for_a_live_finding(client: TestClient, live_finding):
    sid, _ = live_finding()

    r = client.put(f"/scans/{sid}/findings/no-such-fingerprint/work", json={"owner": "x"})

    assert r.status_code == 404
    assert r.json()["detail"] == "finding not found"


def test_work_list_hides_items_whose_finding_is_gone(client: TestClient, live_finding, db_session):
    sid, fp = live_finding()
    client.put(f"/scans/{sid}/findings/{fp}/work", json={"owner": "alice"})
    db_session.execute(
        Finding.__table__.delete().where(Finding.scan_id == uuid.UUID(sid))
    )
    db_session.commit()

    assert client.get(f"/scans/{sid}/work").json() == []


def test_a_discussion_without_an_assignment_is_listed(client: TestClient, live_finding):
    """Commenting before anyone is assigned must not lose the comment.

    A discussion is independent of an assignment: the API returns a synthetic
    unassigned "open" item so the UI can read back what it just wrote.
    """
    sid, fp = live_finding()

    comment = client.post(
        f"/scans/{sid}/findings/{fp}/comments", json={"body": "Seen on staging."}
    )
    assert comment.status_code == 201

    items = client.get(f"/scans/{sid}/work").json()
    assert len(items) == 1
    assert items[0]["fingerprint"] == fp
    assert items[0]["owner"] is None
    assert items[0]["status"] == "open"
    assert [c["body"] for c in items[0]["comments"]] == ["Seen on staging."]


def test_clearing_the_assignment_keeps_the_discussion(client: TestClient, live_finding):
    """DELETE /work removes the assignment, not the conversation."""
    sid, fp = live_finding()
    client.put(f"/scans/{sid}/findings/{fp}/work", json={"owner": "alice"})
    client.post(f"/scans/{sid}/findings/{fp}/comments", json={"body": "Still open."})

    assert client.delete(f"/scans/{sid}/findings/{fp}/work").status_code == 200

    items = client.get(f"/scans/{sid}/work").json()
    assert [item["fingerprint"] for item in items] == [fp]
    assert items[0]["owner"] is None
    assert [c["body"] for c in items[0]["comments"]] == ["Still open."]


def test_collaboration_is_refused_on_the_free_plan(
    client: TestClient, live_finding, monkeypatch
):
    """The API, not the hidden UI control, is the entitlement boundary."""
    from app.core.config import settings

    monkeypatch.setattr(settings, "premium_tenants", "someone-else")
    sid, fp = live_finding()

    assert client.get(f"/scans/{sid}/work").status_code == 402
    assert client.put(f"/scans/{sid}/findings/{fp}/work", json={}).status_code == 402
    assert client.delete(f"/scans/{sid}/findings/{fp}/work").status_code == 402
    assert (
        client.post(
            f"/scans/{sid}/findings/{fp}/comments", json={"body": "nope"}
        ).status_code
        == 402
    )
    assert (
        client.delete(f"/scans/{sid}/comments/00000000-0000-4000-8000-000000000000").status_code
        == 402
    )


def test_comments_are_listed_with_the_work_item(client: TestClient, live_finding):
    sid, fp = live_finding()
    client.put(f"/scans/{sid}/findings/{fp}/work", json={"owner": "alice"})

    created = client.post(
        f"/scans/{sid}/findings/{fp}/comments", json={"body": "Reproduced on staging."}
    )
    assert created.status_code == 201, created.text
    comment = created.json()
    assert comment["author"] == "default"  # auth is off, so the tenant is "default"
    assert comment["body"] == "Reproduced on staging."

    item = client.get(f"/scans/{sid}/work").json()[0]
    assert [c["id"] for c in item["comments"]] == [comment["id"]]

    deleted = client.delete(f"/scans/{sid}/comments/{comment['id']}")
    assert deleted.status_code == 200
    assert client.get(f"/scans/{sid}/work").json()[0]["comments"] == []


def test_a_comment_needs_a_live_finding(client: TestClient, live_finding):
    sid, _ = live_finding()

    r = client.post(f"/scans/{sid}/findings/nope/comments", json={"body": "hi"})

    assert r.status_code == 404


def test_deleting_the_scan_removes_work_and_comments(
    client: TestClient, live_finding, db_session
):
    sid, fp = live_finding()
    client.put(f"/scans/{sid}/findings/{fp}/work", json={"owner": "alice"})
    client.post(f"/scans/{sid}/findings/{fp}/comments", json={"body": "note"})

    assert client.delete(f"/scans/{sid}").status_code == 200

    # The FK cascade lives in the database, not in the API handler.
    db_session.expire_all()
    work = db_session.scalar(select(func.count()).select_from(FindingWork))
    comments = db_session.scalar(select(func.count()).select_from(FindingComment))
    assert (work, comments) == (0, 0)
