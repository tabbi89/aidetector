"""Naming the run: a gate judges one run, and compares it with one baseline.

"The latest run" and "the run before it" move whenever someone else scans the
same target, so a pipeline that asked about its own run must be able to say
which one — and a missing finding must not read as fixed when the newer run
never got a 2xx from its endpoint.
"""
from __future__ import annotations

from sqlalchemy.orm.attributes import flag_modified


def _three_runs(db_session, make_scan, engine_client):
    from app.engine.runner import run_scan

    scan = make_scan()
    for _ in range(3):
        run_scan(db_session, scan, client=engine_client)
    return scan


def test_one_run_is_fetched_by_its_number(client, db_session, make_scan, engine_client):
    scan = _three_runs(db_session, make_scan, engine_client)
    r = client.get(f"/scans/{scan.id}/runs/2")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["run_number"] == 2
    assert body["coverage"], "the run carries its own coverage"
    assert "trace_count" in body
    assert client.get(f"/scans/{scan.id}/runs/9").status_code == 404


def test_coverage_answers_for_a_named_run(client, db_session, make_scan, engine_client):
    scan = _three_runs(db_session, make_scan, engine_client)
    run1 = next(r for r in scan.runs if r.run_number == 1)
    run1.coverage = [{**run1.coverage[0], "requests": 4242}]
    flag_modified(run1, "coverage")
    db_session.commit()

    named = client.get(f"/scans/{scan.id}/coverage?run=1").json()
    assert [row["requests"] for row in named] == [4242]
    latest = client.get(f"/scans/{scan.id}/coverage").json()
    assert all(row["requests"] != 4242 for row in latest)
    assert client.get(f"/scans/{scan.id}/coverage?run=9").status_code == 404


def test_a_row_from_before_response_outcomes_is_unknown_not_unanswered(
    client, db_session, make_scan, engine_client
):
    from app.engine.runner import run_scan

    scan = make_scan()
    run_scan(db_session, scan, client=engine_client)
    run = scan.runs[0]
    run.coverage = [
        {k: v for k, v in row.items() if k not in {"responses", "ok", "exercised"}}
        for row in run.coverage
    ]
    flag_modified(run, "coverage")
    db_session.commit()

    rows = client.get(f"/scans/{scan.id}/coverage").json()
    assert rows and all(
        row["responses"] is None and row["ok"] is None and row["exercised"] is None
        for row in rows
    )


def test_diff_to_a_named_run_compares_with_the_run_before_it(
    client, db_session, make_scan, engine_client
):
    scan = _three_runs(db_session, make_scan, engine_client)
    body = client.get(f"/scans/{scan.id}/diff?to_run=2").json()
    # Not "the second newest" (2 itself), which would be refused as reversed.
    assert (body["from_run"], body["to_run"]) == (1, 2)

    first = client.get(f"/scans/{scan.id}/diff?to_run=1")
    assert first.status_code == 409
    assert "first run" in first.json()["detail"]


def _with_finding_dropped(db_session, scan, *, exercised, refusal=False, answered=True):
    """Make run 2 miss one of run 1's findings, its endpoint marked as given.

    ``refusal`` picks an authorization finding (whose fix is a 401/403);
    ``answered=False`` makes the endpoint get no response at all.
    """
    from app.scans.diff import REFUSAL_IS_AN_ANSWER

    run1, run2 = sorted(scan.runs, key=lambda r: r.run_number)[:2]
    row = next(
        r for r in run1.findings_snapshot
        if r.get("operation_id") and (r["check"] in REFUSAL_IS_AN_ANSWER) == refusal
    )
    run2.findings_snapshot = [
        r for r in run2.findings_snapshot if r["fingerprint"] != row["fingerprint"]
    ]
    coverage = []
    for cov in run2.coverage:
        cov = dict(cov)
        if cov["operation_id"] == row["operation_id"]:
            if exercised is None:
                for key in ("responses", "ok", "exercised"):
                    cov.pop(key, None)
            else:
                cov["exercised"] = exercised
                cov["requests"] = cov.get("requests") or 1
                cov["responses"] = max(int(cov.get("responses") or 0), 1) if answered else 0
                # A refusal (401/403), not a 404: what a fixed authz endpoint answers.
                cov["denied"] = cov["responses"] if refusal else 0
        coverage.append(cov)
    run2.coverage = coverage
    flag_modified(run2, "findings_snapshot")
    flag_modified(run2, "coverage")
    db_session.commit()
    return row["fingerprint"]


def test_a_finding_on_an_endpoint_the_newer_run_never_exercised_is_not_fixed(
    client, db_session, make_scan, engine_client
):
    from app.engine.runner import run_scan

    scan = make_scan()
    run_scan(db_session, scan, client=engine_client)
    run_scan(db_session, scan, client=engine_client)
    fp = _with_finding_dropped(db_session, scan, exercised=False)

    body = client.get(f"/scans/{scan.id}/diff").json()
    assert fp in {r["fingerprint"] for r in body["not_retested"]}
    assert fp not in {r["fingerprint"] for r in body["resolved"]}


def test_an_authorization_fix_that_now_refuses_reads_as_fixed(
    client, db_session, make_scan, engine_client
):
    from app.engine.runner import run_scan

    scan = make_scan()
    run_scan(db_session, scan, client=engine_client)
    run_scan(db_session, scan, client=engine_client)
    fp = _with_finding_dropped(db_session, scan, exercised=False, refusal=True)
    assert fp in {r["fingerprint"] for r in client.get(f"/scans/{scan.id}/diff").json()["resolved"]}

    # ...but an endpoint that answered nothing proves nothing, even for authz.
    scan = make_scan()
    run_scan(db_session, scan, client=engine_client)
    run_scan(db_session, scan, client=engine_client)
    fp = _with_finding_dropped(db_session, scan, exercised=False, refusal=True, answered=False)
    body = client.get(f"/scans/{scan.id}/diff").json()
    assert fp in {r["fingerprint"] for r in body["not_retested"]}


def test_an_exercised_or_unknown_endpoint_still_reports_a_fix(
    client, db_session, make_scan, engine_client
):
    from app.engine.runner import run_scan

    for exercised in (True, None):
        scan = make_scan()
        run_scan(db_session, scan, client=engine_client)
        run_scan(db_session, scan, client=engine_client)
        fp = _with_finding_dropped(db_session, scan, exercised=exercised)
        body = client.get(f"/scans/{scan.id}/diff").json()
        assert fp in {r["fingerprint"] for r in body["resolved"]}, exercised


def test_unexercised_operations_needs_an_explicit_false():
    from app.scans.diff import unexercised_operations

    rows = [
        {"operation_id": "a", "enabled": True, "exercised": False, "requests": 3, "responses": 3},
        {"operation_id": "r", "enabled": True, "exercised": False, "requests": 3, "responses": 3,
         "denied": 3},
        {"operation_id": "e", "enabled": True, "exercised": False, "requests": 3, "responses": 0},
        {"operation_id": "b", "enabled": True, "exercised": True},
        {"operation_id": "c", "enabled": True},  # before the field: unknown
        {"operation_id": "d", "enabled": False, "exercised": False},
        {"operation_id": None, "enabled": True, "exercised": False},
    ]
    u = unexercised_operations(rows, frozenset({"a", "b", "c", "d", "e", "r", "gone"}))
    assert u.no_success == frozenset({"a", "r"}) and u.refused == frozenset({"r"})
    # Excluded, unanswered, and an operation the run left out entirely.
    assert u.unanswered == frozenset({"e", "d", "gone"})
    assert u.any_exercised


def test_a_refusal_is_the_answer_only_for_a_refusal_fix_in_a_run_that_worked():
    """broken_auth fixed: the endpoint now refuses the caller — that is fixed."""
    from app.scans.diff import Unexercised

    u = Unexercised(
        unanswered=frozenset({"down"}),
        no_success=frozenset({"refusing", "missing"}),
        refused=frozenset({"refusing"}),
        any_exercised=True,
    )
    assert not u.hides("broken_auth", "refusing")
    # A 404 is not a refusal, and BOLA/BFLA keep an owner reference that must succeed.
    assert u.hides("broken_auth", "missing")
    assert u.hides("bola", "refusing") and u.hides("bfla", "refusing")
    assert u.hides("reflected_injection", "refusing")
    # No answer at all proves nothing for any check.
    assert u.hides("broken_auth", "down")


def test_an_all_401_run_never_calls_an_authorization_finding_fixed():
    """Every key expired: nothing got a 2xx, so no refusal is an answer."""
    from app.scans.diff import unexercised_operations

    rows = [
        {"operation_id": op, "enabled": True, "exercised": False, "requests": 4,
         "responses": 4, "denied": 4}
        for op in ("accounts", "admin")
    ]
    u = unexercised_operations(rows)
    assert not u.any_exercised
    for check in ("bola", "bfla", "broken_auth", "write_authz", "seeded_bola"):
        assert u.hides(check, "accounts"), check


def test_refusal_checks_are_registered():
    from app.engine.checks import ALL_CHECKS
    from app.scans.diff import REFUSAL_IS_AN_ANSWER

    assert REFUSAL_IS_AN_ANSWER <= {c.key for c in ALL_CHECKS}
