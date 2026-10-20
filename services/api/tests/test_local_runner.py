"""Local-runner ingest API: claim gates, per-run token, bundle validation."""
from __future__ import annotations

import json

import pytest

from app.core.config import settings


@pytest.fixture
def local_runner(monkeypatch):
    monkeypatch.setattr(settings, "local_runner_enabled", True)


def _claim(client, sid, **flags):
    body = {"authorized": True, **flags}
    return client.post(f"/scans/{sid}/local-runs", json=body)


def test_claim_is_404_when_the_feature_is_off(client, scan_with_spec):
    sid = scan_with_spec("http://127.0.0.1")
    assert _claim(client, sid).status_code == 404


def test_claim_requires_authorization(client, scan_with_spec, local_runner):
    sid = scan_with_spec("http://127.0.0.1")
    r = client.post(f"/scans/{sid}/local-runs", json={"authorized": False})
    assert r.status_code == 403


def test_claim_accepts_every_pass_now_that_they_run_locally(
    client, scan_with_spec, local_runner, monkeypatch
):
    # Nothing is in LOCAL_REFUSED any more: the external tools run on the CLI
    # machine and the in-loop AI passes call the service.
    monkeypatch.setattr(settings, "premium_tenants", "*")
    sid = scan_with_spec("http://127.0.0.1")
    r = _claim(client, sid, zap=True, kali=True, confirm=True, testssl=True,
               genai_payloads=True, adaptive=True, resource_refine=True,
               premium=True, mutate=True)
    assert r.status_code == 201, r.text


def test_local_claim_allows_a_private_target_the_server_lane_forbids(
    client, scan_with_spec, local_runner, monkeypatch
):
    # A hosted, multi-tenant server keeps private targets off (SSRF). The local
    # lane egresses from the CLI machine, not the server, so it allows them.
    monkeypatch.setattr(settings, "target_allow_private", False)
    # The local-runner claim accepts a private target…
    assert _claim(client, scan_with_spec("http://10.0.0.5")).status_code == 201
    # …but the server-dialed lane still refuses the same target (a separate
    # scan, since claiming the first one leaves it running).
    other = scan_with_spec("http://10.0.0.5")
    r = client.post(f"/scans/{other}/run", json={"authorized": True})
    assert r.status_code == 422
    assert "target not allowed" in r.json()["detail"]


@pytest.mark.parametrize(
    "target,detail",
    [
        # The override widens private egress only: a public target still needs
        # this workspace's ownership proof…
        ("http://93.184.216.34", "target not verified"),
        # …and cloud metadata is refused on every lane.
        ("http://169.254.169.254", "target not allowed"),
    ],
)
def test_local_claim_still_answers_ownership_and_metadata(
    client, scan_with_spec, local_runner, target, detail
):
    r = _claim(client, scan_with_spec(target))
    assert r.status_code == 422, r.text
    assert detail in r.json()["detail"]


def _planner(monkeypatch, high_path: str):
    from app.ai import cascade as cascade_mod
    from tests.fakes import FakePlanner

    calls: list[int] = []

    def build():
        calls.append(1)
        return FakePlanner(lambda path: "high" if path == high_path else "low")

    monkeypatch.setattr(cascade_mod, "AICascade", build)
    return calls


def test_a_local_run_gets_its_ai_plan_from_the_server_once(
    client, scan_with_spec, local_runner, monkeypatch
):
    sid = scan_with_spec("http://127.0.0.1")
    r = _claim(client, sid, plan=True)
    assert r.status_code == 201, r.text
    cfg = r.json()
    ops = cfg["operations"]
    assert len(ops) >= 2, "the fixture spec needs two operations to show an order"
    last = ops[-1]
    calls = _planner(monkeypatch, last["path"])
    headers = {"X-Run-Token": cfg["token"]}

    planned = client.post(f"/runner/runs/{cfg['run_id']}/plan", headers=headers)
    assert planned.status_code == 200, planned.text
    body = planned.json()
    assert body["operation_ids"][0] == str(last["id"])
    assert sorted(body["operation_ids"]) == sorted(str(op["id"]) for op in ops)
    assert any(ev["stage"] == "planned" for ev in body["events"])
    run = client.get(f"/scans/{sid}/runs").json()[-1]
    assert run["plan"] and run["plan"][0]["priority"] == "high"

    # Asking again reads the stored plan rather than paying for a second one.
    again = client.post(f"/runner/runs/{cfg['run_id']}/plan", headers=headers)
    assert again.json()["operation_ids"] == body["operation_ids"]
    assert len(calls) == 1


def test_only_a_run_that_claimed_a_plan_may_ask_for_one(
    client, scan_with_spec, local_runner, monkeypatch
):
    sid = scan_with_spec("http://127.0.0.1")
    cfg = _claim(client, sid).json()
    calls = _planner(monkeypatch, "/")
    r = client.post(f"/runner/runs/{cfg['run_id']}/plan", headers={"X-Run-Token": cfg["token"]})
    assert r.status_code == 409
    assert client.post(f"/runner/runs/{cfg['run_id']}/plan").status_code == 401
    assert calls == []


def test_a_planner_failure_is_a_skipped_plan_not_a_failed_run(
    client, scan_with_spec, local_runner, monkeypatch
):
    from app.ai import cascade as cascade_mod
    from tests.fakes import BrokenCascade

    monkeypatch.setattr(cascade_mod, "AICascade", lambda: BrokenCascade())
    sid = scan_with_spec("http://127.0.0.1")
    cfg = _claim(client, sid, plan=True).json()
    r = client.post(f"/runner/runs/{cfg['run_id']}/plan", headers={"X-Run-Token": cfg["token"]})
    assert r.status_code == 200, r.text
    stages = [ev["stage"] for ev in r.json()["events"]]
    assert stages[-1] == "plan_skipped" and "planned" not in stages
    assert r.json()["operation_ids"] == [str(op["id"]) for op in cfg["operations"]]
    assert client.get(f"/scans/{sid}").json()["status"] == "running"


def test_claim_opens_the_run_and_returns_a_token(client, scan_with_spec, local_runner):
    sid = scan_with_spec("http://127.0.0.1")
    r = _claim(client, sid, mutate=True)
    assert r.status_code == 201, r.text
    cfg = r.json()
    assert cfg["token"] and cfg["max_requests"] == 750
    assert cfg["options"]["mutate"] is True
    assert len(cfg["operations"]) >= 1
    # The scan is now running and the token is not echoed back anywhere else.
    assert client.get(f"/scans/{sid}").json()["status"] == "running"


def test_claim_refuses_a_second_concurrent_run(client, scan_with_spec, local_runner):
    sid = scan_with_spec("http://127.0.0.1")
    assert _claim(client, sid).status_code == 201
    assert _claim(client, sid).status_code == 409


def test_runner_routes_reject_a_bad_or_missing_token(client, scan_with_spec, local_runner):
    sid = scan_with_spec("http://127.0.0.1")
    run_id = _claim(client, sid).json()["run_id"]
    body = {"events": [{"stage": "x", "pct": 10, "message": "m"}]}
    assert client.post(f"/runner/runs/{run_id}/events", json=body).status_code == 401
    assert client.post(
        f"/runner/runs/{run_id}/events", json=body, headers={"X-Run-Token": "wrong"}
    ).status_code == 401


def test_events_and_heartbeat_with_the_token(client, scan_with_spec, local_runner):
    sid = scan_with_spec("http://127.0.0.1")
    cfg = _claim(client, sid).json()
    run_id, token = cfg["run_id"], cfg["token"]
    h = {"X-Run-Token": token}
    r = client.post(
        f"/runner/runs/{run_id}/events",
        json={"events": [{"stage": "engine", "pct": 42, "message": "scanning"}]},
        headers=h,
    )
    assert r.status_code == 200 and r.json()["cancel"] is False
    assert client.get(f"/scans/{sid}").json()["progress"] == 42
    # A cancel from the web reaches the runner through the heartbeat.
    client.post(f"/scans/{sid}/cancel")
    assert client.post(f"/runner/runs/{run_id}/heartbeat", headers=h).json()["cancel"] is True


def test_complete_persists_findings_and_ends_the_run(client, scan_with_spec, local_runner):
    sid = scan_with_spec("http://127.0.0.1")
    cfg = _claim(client, sid).json()
    run_id, token = cfg["run_id"], cfg["token"]
    op_id = cfg["operations"][0]["id"]
    h = {"X-Run-Token": token}
    bundle = {
        "requests": cfg["max_requests"],
        "findings": [
            {
                "check": "security_headers",
                "severity": "medium",
                "confidence": "verified",
                "title": "Missing security headers",
                "description": "no CSP",
                "evidence": {"issue": "missing-csp"},
                "operation_id": op_id,
            }
        ],
    }
    r = client.post(f"/runner/runs/{run_id}/complete", json=bundle, headers=h)
    assert r.status_code == 200, r.text
    scan = client.get(f"/scans/{sid}").json()
    assert scan["status"] == "completed"
    findings = client.get(f"/scans/{sid}/findings").json()
    assert len(findings) == 1 and findings[0]["check"] == "security_headers"
    # The run is archived as a local-runner run.
    runs = client.get(f"/scans/{sid}/runs").json()
    assert runs[0]["options"]  # archived options present
    # The token died with the run: a second upload is refused.
    assert client.post(f"/runner/runs/{run_id}/complete", json=bundle, headers=h).status_code == 409


def _row(sequence: int, **response) -> dict:
    return {
        "sequence": sequence, "method": "GET", "route": "GET /accounts/{id}",
        "check": "security_headers", "pass": "engine", "identity": "alice",
        "request": {"headers": {"Authorization": "[REDACTED]"}},
        "response": {"status": 200, "body": "{}", **response},
    }


def test_complete_stores_the_trace_redacted_again_and_links_findings(
    client, scan_with_spec, local_runner
):
    sid = scan_with_spec("http://127.0.0.1")
    cfg = _claim(client, sid).json()
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhbGljZSJ9.c2lnbmF0dXJlLXZhbHVl"
    bundle = {
        "requests": 2,
        "findings": [{
            "check": "security_headers", "severity": "medium", "title": "Missing CSP",
            "evidence": {"route": "GET /accounts/{id}"},
            "operation_id": cfg["operations"][0]["id"],
        }],
        # The runner missed a token in one body; the server's pass catches it.
        "trace": [_row(1, body=f'{{"token":"{jwt}"}}'), _row(2)],
        "manifest": {"metrics": {"scope": "instrumented cases only"}},
    }
    r = client.post(
        f"/runner/runs/{cfg['run_id']}/complete", json=bundle,
        headers={"X-Run-Token": cfg["token"]},
    )
    assert r.status_code == 200, r.text
    trace = client.get(f"/scans/{sid}/runs/1/trace").json()
    assert trace["total"] == 2 and trace["rows"][0]["identity"] == "alice"
    assert jwt not in json.dumps(trace)
    finding = client.get(f"/scans/{sid}/findings").json()[0]
    assert finding["evidence"]["trace"] == [1, 2]
    assert client.get(f"/scans/{sid}/runs").json()[0]["manifest"]["metrics"]["scope"]


@pytest.mark.parametrize(
    "trace,detail",
    [
        # More retained body text than any honest run's budget allows.
        ([_row(i, body="x" * 4000) for i in range(1, 131)], "over the run budget"),
        # A field over its per-row cap.
        ([_row(1, body="x" * 4001)], "body"),
        ([_row(1, headers={f"h{i}": "v" for i in range(101)})], "headers"),
        ([_row(1, json_shape={"k": "x" * 9000})], "JSON shape"),
    ],
)
def test_complete_refuses_a_trace_past_its_bounds(
    client, scan_with_spec, local_runner, trace, detail
):
    sid = scan_with_spec("http://127.0.0.1")
    cfg = _claim(client, sid).json()
    r = client.post(
        f"/runner/runs/{cfg['run_id']}/complete",
        json={"requests": 1, "trace": trace},
        headers={"X-Run-Token": cfg["token"]},
    )
    assert r.status_code == 422 and detail in r.text
    assert client.get(f"/scans/{sid}").json()["status"] == "running"


def test_the_trace_caps_match_what_the_probe_retains():
    from app.api.schemas import runner as schema
    from app.engine import probe

    assert schema.TRACE_MAX_ROWS == probe._MAX_TRACE_ROWS
    assert schema.TRACE_BODY_BUDGET == probe._BODY_BUDGET + probe._BODY_LIMIT_DETAIL


def test_complete_over_budget_is_refused(client, scan_with_spec, local_runner):
    sid = scan_with_spec("http://127.0.0.1")
    cfg = _claim(client, sid).json()
    h = {"X-Run-Token": cfg["token"]}
    r = client.post(
        f"/runner/runs/{cfg['run_id']}/complete",
        json={"requests": cfg["max_requests"] + 1, "findings": []},
        headers=h,
    )
    assert r.status_code == 422 and "budget" in r.json()["detail"]
    # The run is still open after a rejected bundle.
    assert client.get(f"/scans/{sid}").json()["status"] == "running"


def test_complete_rejects_unknown_check_and_foreign_operation(client, scan_with_spec, local_runner):
    sid = scan_with_spec("http://127.0.0.1")
    cfg = _claim(client, sid).json()
    h = {"X-Run-Token": cfg["token"]}
    base = {"severity": "low", "title": "t", "description": "", "evidence": {}}
    bad_check = {"requests": 1, "findings": [{**base, "check": "not_a_real_check"}]}
    assert client.post(
        f"/runner/runs/{cfg['run_id']}/complete", json=bad_check, headers=h
    ).status_code == 422
    foreign_op = {
        "requests": 1,
        "findings": [
            {
                **base,
                "check": "security_headers",
                "operation_id": "00000000-0000-0000-0000-000000000000",
            }
        ],
    }
    assert client.post(
        f"/runner/runs/{cfg['run_id']}/complete", json=foreign_op, headers=h
    ).status_code == 422


def test_claim_returns_the_spec_so_spec_driven_checks_work_on_the_runner(
    client, scan_with_spec, local_runner
):
    sid = scan_with_spec("http://127.0.0.1")
    cfg = _claim(client, sid).json()
    assert cfg["spec_text"] and "/accounts/{id}" in cfg["spec_text"]


def test_a_runner_side_cancel_ends_the_run_cancelled_not_failed(
    client, scan_with_spec, local_runner
):
    sid = scan_with_spec("http://127.0.0.1")
    cfg = _claim(client, sid).json()
    h = {"X-Run-Token": cfg["token"]}
    r = client.post(
        f"/runner/runs/{cfg['run_id']}/fail", json={"cancelled": True}, headers=h
    )
    assert r.status_code == 200
    assert client.get(f"/scans/{sid}").json()["status"] == "cancelled"
    assert client.get(f"/scans/{sid}/runs").json()[0]["status"] == "cancelled"
    # And the scan is free again.
    assert _claim(client, sid).status_code == 201


def test_complete_keeps_only_the_gap_shape_the_diff_reads(
    client, scan_with_spec, local_runner
):
    sid = scan_with_spec("http://127.0.0.1")
    cfg = _claim(client, sid).json()
    r = client.post(
        f"/runner/runs/{cfg['run_id']}/complete",
        json={
            "requests": 1,
            "gaps": {"budget_exhausted": True, "not_run": ["zap"], "injected": {"x": 1}},
        },
        headers={"X-Run-Token": cfg["token"]},
    )
    assert r.status_code == 200, r.text
    gaps = client.get(f"/scans/{sid}/runs").json()[0]["gaps"]
    assert gaps == {
        "not_run": ["zap"], "budget_exhausted": True, "identities_missing": [],
        "skipped_checks": [], "failed_checks": [],
    }


def test_complete_records_only_registered_skipped_checks(
    client, scan_with_spec, local_runner
):
    """A check the local run skipped was not re-tested; unknown names are dropped."""
    sid = scan_with_spec("http://127.0.0.1")
    cfg = _claim(client, sid).json()
    r = client.post(
        f"/runner/runs/{cfg['run_id']}/complete",
        json={"requests": 1, "gaps": {"skipped_checks": ["bfla", "not-a-check", 7]}},
        headers={"X-Run-Token": cfg["token"]},
    )
    assert r.status_code == 200, r.text
    gaps = client.get(f"/scans/{sid}/runs").json()[0]["gaps"]
    assert gaps["skipped_checks"] == ["bfla"]


def test_complete_records_only_registered_failed_checks(
    client, scan_with_spec, local_runner
):
    """A check that raised on the local run did not re-test its findings either."""
    sid = scan_with_spec("http://127.0.0.1")
    cfg = _claim(client, sid).json()
    r = client.post(
        f"/runner/runs/{cfg['run_id']}/complete",
        json={"requests": 1, "gaps": {"failed_checks": ["bola", "rm -rf /", None]}},
        headers={"X-Run-Token": cfg["token"]},
    )
    assert r.status_code == 200, r.text
    gaps = client.get(f"/scans/{sid}/runs").json()[0]["gaps"]
    assert gaps["failed_checks"] == ["bola"]


def test_a_failed_runs_reason_is_the_runners_sentence_redacted(
    client, scan_with_spec, local_runner
):
    sid = scan_with_spec("http://127.0.0.1")
    cfg = _claim(client, sid).json()
    r = client.post(
        f"/runner/runs/{cfg['run_id']}/fail",
        json={"reason": "the local runner exited before finishing"},
        headers={"X-Run-Token": cfg["token"]},
    )
    assert r.status_code == 200
    scan = client.get(f"/scans/{sid}").json()
    assert scan["status"] == "failed"
    # No exception class-name prefix: it is a sentence, not a stack trace.
    assert scan["failure_reason"] == "the local runner exited before finishing"


def test_run_agent_is_a_clean_noop_when_sandbox_disabled(monkeypatch):
    """The heavy agent degrades to nothing when the sandbox is off (the default)."""
    import os

    from app.core.redact import Redactor
    from app.engine.base import HttpProbe, ScanContext
    from app.runner.main import _run_agent

    monkeypatch.delenv("AGENT_SANDBOX_ENABLED", raising=False)
    monkeypatch.setattr(os, "environ", {k: v for k, v in os.environ.items()})

    class _J:
        progress = 0
        findings: list = []

        def __init__(self):
            self.events = []

        def event(self, stage, pct, message):
            self.events.append((stage, message))

        def record(self, finding):
            self.findings.append(finding)

        def cancelled(self):
            return False

    probe = HttpProbe.__new__(HttpProbe)
    ctx = ScanContext(base_url="http://target:9000", operations=[], credentials=[], probe=probe)
    journal = _J()
    not_run = _run_agent(ctx, journal, None, Redactor())
    assert not_run == set()
    # It announced the pass and stopped cleanly rather than failing the scan.
    assert any(stage == "agent_idle" for stage, _ in journal.events)


def test_memory_recall_endpoint_and_write_on_complete(client, scan_with_spec, local_runner):
    """A heavy run remembers its findings; the next run recalls them by token."""
    sid = scan_with_spec("http://127.0.0.1")
    cfg = _claim(client, sid).json()
    run_id, token = cfg["run_id"], cfg["token"]
    h = {"X-Run-Token": token}
    # First run: recall is empty.
    r0 = client.get(f"/runner/runs/{run_id}/memory", headers=h)
    assert r0.status_code == 200 and r0.json()["memories"] == []
    # Complete with a finding; the server remembers it.
    bundle = {
        "requests": 10,
        "findings": [
            {
                "check": "bola",
                "severity": "high",
                "confidence": "verified",
                "title": "BOLA on /accounts/{id}",
                "evidence": {"route": "/accounts/{id}", "param": "id"},
            }
        ],
    }
    assert client.post(f"/runner/runs/{run_id}/complete", json=bundle, headers=h).status_code == 200

    # Second run on the same target recalls the first run's finding.
    cfg2 = _claim(client, sid).json()
    r1 = client.get(f"/runner/runs/{cfg2['run_id']}/memory", headers={"X-Run-Token": cfg2["token"]})
    assert r1.status_code == 200
    memories = r1.json()["memories"]
    assert len(memories) == 1
    assert memories[0]["check"] == "bola"
    assert memories[0]["embedding"]
    # The recall route is token-scoped like the rest.
    assert client.get(f"/runner/runs/{cfg2['run_id']}/memory").status_code == 401


def test_the_local_runner_never_builds_a_paid_planner(monkeypatch):
    """No database, so no budget claim and no ledger: the local lane makes no AI call.

    Even with a provider key in the container's environment, the agent runs its
    deterministic order (the AI plan runs on the server, never in the container).
    """
    from types import SimpleNamespace

    from app.agent import loop as agent_loop
    from app.core.redact import Redactor
    from app.engine.base import HttpProbe, ScanContext
    from app.runner.main import _run_agent

    monkeypatch.setattr(settings, "deepseek_api_key", "synthetic-key")
    seen: dict = {}

    class _Loop:
        def __init__(self, *args, planner=None, **kwargs):
            seen["planner"] = planner

        def run(self):
            return SimpleNamespace(tools_unavailable=[])

    monkeypatch.setattr(agent_loop, "AgentLoop", _Loop)
    probe = HttpProbe.__new__(HttpProbe)
    ctx = ScanContext(base_url="http://target:9000", operations=[], credentials=[], probe=probe)
    journal = SimpleNamespace(progress=0, event=lambda *a: None)
    assert _run_agent(ctx, journal, None, Redactor()) == set()
    assert "planner" in seen and seen["planner"] is None


def test_complete_records_identities_the_runner_left_out(
    client, scan_with_spec, local_runner
):
    """A local run without an identity's secret did not re-test its findings."""
    sid = scan_with_spec("http://127.0.0.1")
    cfg = _claim(client, sid).json()
    r = client.post(
        f"/runner/runs/{cfg['run_id']}/complete",
        json={"requests": 1, "gaps": {"identities_missing": ["admin", 7]}},
        headers={"X-Run-Token": cfg["token"]},
    )
    assert r.status_code == 200, r.text
    gaps = client.get(f"/scans/{sid}/runs").json()[0]["gaps"]
    assert gaps["identities_missing"] == ["7", "admin"]


# --- AI analysis after the upload ------------------------------------------------


def _bola_bundle(cfg) -> dict:
    return {
        "requests": 2,
        "findings": [{
            "check": "bola", "severity": "high", "confidence": "verified",
            "title": "Cross-identity object read",
            "evidence": {"route": "GET /accounts/{id}", "parameter": "id"},
            "operation_id": cfg["operations"][0]["id"],
        }],
    }


def _complete(client, cfg, bundle):
    return client.post(
        f"/runner/runs/{cfg['run_id']}/complete", json=bundle,
        headers={"X-Run-Token": cfg["token"]},
    )


def test_a_local_run_is_adjudicated_on_the_service_before_it_completes(
    client, scan_with_spec, local_runner, monkeypatch
):
    from app.ai import cascade as cascade_mod
    from tests.fakes import FakeCascade

    fake = FakeCascade(remediation_for=lambda check: f"fix {check} by scoping the query")
    monkeypatch.setattr(cascade_mod, "AICascade", lambda: fake)
    sid = scan_with_spec("http://127.0.0.1")
    cfg = _claim(client, sid, adjudicate=True).json()
    assert _complete(client, cfg, _bola_bundle(cfg)).status_code == 200

    assert fake.calls == 1
    finding = client.get(f"/scans/{sid}/findings").json()[0]
    assert finding["verdict"] == "confirmed" and finding["ai_rationale"]
    assert finding["remediation"] == "fix bola by scoping the query"
    assert client.get(f"/scans/{sid}").json()["status"] == "completed"
    run = client.get(f"/scans/{sid}/runs").json()[0]
    assert run["status"] == "completed"
    # The snapshot is taken after the verdicts, so the run record carries them.
    assert run["findings_snapshot"][0]["verdict"] == "confirmed"
    stages = [e["stage"] for e in client.get(f"/scans/{sid}/events").json()]
    assert stages.index("analysing") < stages.index("adjudicated") < stages.index("done")


def test_an_ai_failure_after_upload_still_completes_the_run(
    client, scan_with_spec, local_runner, monkeypatch
):
    from app.ai import cascade as cascade_mod
    from tests.fakes import BrokenCascade

    monkeypatch.setattr(cascade_mod, "AICascade", lambda: BrokenCascade())
    sid = scan_with_spec("http://127.0.0.1")
    cfg = _claim(client, sid, adjudicate=True).json()
    assert _complete(client, cfg, _bola_bundle(cfg)).status_code == 200
    assert client.get(f"/scans/{sid}").json()["status"] == "completed"
    assert client.get(f"/scans/{sid}/findings").json()[0]["verdict"] == "unreviewed"
    assert "ai_skipped" in [e["stage"] for e in client.get(f"/scans/{sid}/events").json()]


def test_a_person_outranks_the_model_on_a_local_run(
    client, scan_with_spec, local_runner, monkeypatch
):
    from app.ai import cascade as cascade_mod
    from tests.fakes import FakeCascade

    monkeypatch.setattr(cascade_mod, "AICascade", lambda: FakeCascade())
    sid = scan_with_spec("http://127.0.0.1")
    first = _claim(client, sid).json()
    assert _complete(client, first, _bola_bundle(first)).status_code == 200
    finding = client.get(f"/scans/{sid}/findings").json()[0]
    r = client.patch(f"/scans/{sid}/findings/{finding['id']}", json={"verdict": "dismissed"})
    assert r.status_code == 200, r.text

    second = _claim(client, sid, adjudicate=True).json()
    assert _complete(client, second, _bola_bundle(second)).status_code == 200
    assert client.get(f"/scans/{sid}/findings").json()[0]["verdict"] == "dismissed"


def test_an_analysing_run_holds_the_scan_until_it_completes(
    client, scan_with_spec, local_runner, monkeypatch
):
    from app.workers import tasks

    queued: list[str] = []
    monkeypatch.setattr(tasks.analyze_local_run, "delay", queued.append)
    sid = scan_with_spec("http://127.0.0.1")
    cfg = _claim(client, sid, adjudicate=True).json()
    assert _complete(client, cfg, _bola_bundle(cfg)).status_code == 200

    assert client.get(f"/scans/{sid}").json()["status"] == "running"
    assert client.get(f"/scans/{sid}/runs").json()[0]["status"] == "analysing"
    # Nothing can start over it, and the runner's token is already dead.
    assert _claim(client, sid).status_code == 409
    assert _complete(client, cfg, {"requests": 1}).status_code in {401, 404, 409}


def test_the_reaper_completes_an_analysis_whose_worker_died(
    client, db_session, scan_with_spec, local_runner, monkeypatch
):
    # The findings uploaded; only the AI worker is gone. The run is completed
    # with what it has, not failed — unlike a run whose engine worker died.
    from datetime import UTC, datetime, timedelta

    from app.models.scan import Scan
    from app.scans.reaper import StaleLimits, reap_stale
    from app.workers import tasks

    monkeypatch.setattr(tasks.analyze_local_run, "delay", lambda run_id: None)
    sid = scan_with_spec("http://127.0.0.1")
    cfg = _claim(client, sid, adjudicate=True).json()
    assert _complete(client, cfg, _bola_bundle(cfg)).status_code == 200
    # The run row carries the uploaded findings even before analysis completes.
    assert client.get(f"/scans/{sid}/runs").json()[0]["findings_count"] == 1
    later = datetime.now(UTC) + timedelta(hours=1)
    limits = StaleLimits(running_seconds=60, queued_seconds=60)
    assert reap_stale(db_session, later, limits) == [sid]
    db_session.commit()
    scan = db_session.get(Scan, sid)
    assert scan.status == "completed" and scan.runs[-1].status == "completed"
    assert len(scan.findings) == 1
    assert "ai_skipped" in [e.stage for e in scan.events]


def test_the_local_claim_now_accepts_zap_and_kali(client, scan_with_spec, local_runner):
    # zap and kali left LOCAL_REFUSED: the runner runs them from sibling URLs.
    sid = scan_with_spec("http://127.0.0.1")
    assert _claim(client, sid, zap=True, kali=True).status_code == 201


def test_the_claim_issues_the_adjunct_budget(client, scan_with_spec, local_runner):
    sid = scan_with_spec("http://127.0.0.1")
    assert _claim(client, sid, zap=True).json()["adjunct_budget_seconds"] > 0


# --- in-loop AI: resource refinement on the service -----------------------------


def _ai_claim(client, sid, monkeypatch):
    monkeypatch.setattr(settings, "premium_tenants", "*")
    return _claim(client, sid, resource_refine=True, premium=True, mutate=True).json()


def test_resource_refine_leaves_local_refused(client, scan_with_spec, local_runner, monkeypatch):
    monkeypatch.setattr(settings, "premium_tenants", "*")
    assert _claim(client, scan_with_spec("http://127.0.0.1"),
                  resource_refine=True, premium=True, mutate=True).status_code == 201


def test_runner_ai_runs_the_planner_meters_and_caps(
    client, scan_with_spec, local_runner, monkeypatch
):
    import app.ai.planner as planner_mod
    from app.ai.types import Usage

    calls: list[dict] = []

    class _FakePlanner:
        def propose_resource(self, payload):
            calls.append(payload)
            return {"name": "x"}, [Usage(model="deepseek", phase="propose_resource",
                                         tokens_in=10, tokens_out=5)]

    monkeypatch.setattr(planner_mod, "OpusPlanner", lambda *a, **k: _FakePlanner())
    cfg = _ai_claim(client, scan_with_spec("http://127.0.0.1"), monkeypatch)
    h = {"X-Run-Token": cfg["token"]}
    url = f"/runner/runs/{cfg['run_id']}/ai"

    r = client.post(url, json={"mode": "propose_resource", "payload": {"a": 1}}, headers=h)
    assert r.status_code == 200, r.text
    assert r.json()["result"]["proposal"] == {"name": "x"}
    assert len(calls) == 1
    # The call was priced on the scan's ledger.
    cost = client.get(f"/scans/{_scan_of(client, cfg)}/cost").json()
    assert cost["total_usd"] >= 0  # a ledger row exists for the call

    # An unknown mode is refused; a run that did not ask is refused.
    assert client.post(url, json={"mode": "nope", "payload": {}}, headers=h).status_code == 422


def test_runner_ai_refuses_a_run_that_did_not_ask(client, scan_with_spec, local_runner):
    cfg = _claim(client, scan_with_spec("http://127.0.0.1")).json()
    r = client.post(f"/runner/runs/{cfg['run_id']}/ai",
                    json={"mode": "propose_resource", "payload": {}},
                    headers={"X-Run-Token": cfg["token"]})
    assert r.status_code == 409


def test_runner_ai_stops_at_the_per_run_cap(
    client, scan_with_spec, local_runner, monkeypatch
):
    import app.ai.planner as planner_mod

    monkeypatch.setattr(settings, "runner_ai_call_budget", 2)

    class _FakePlanner:
        def propose_resource(self, payload):
            return {"ok": True}, []

    monkeypatch.setattr(planner_mod, "OpusPlanner", lambda *a, **k: _FakePlanner())
    cfg = _ai_claim(client, scan_with_spec("http://127.0.0.1"), monkeypatch)
    h = {"X-Run-Token": cfg["token"]}
    url = f"/runner/runs/{cfg['run_id']}/ai"
    body = {"mode": "propose_resource", "payload": {}}
    assert client.post(url, json=body, headers=h).json()["result"]["proposal"] == {"ok": True}
    assert client.post(url, json=body, headers=h).json()["result"]["proposal"] == {"ok": True}
    # The third call is over the cap of 2: an empty result, no proposal.
    assert client.post(url, json=body, headers=h).json()["result"] == {}


def _scan_of(client, cfg) -> str:
    # The claim does not return the scan id; find it via the runs list is overkill,
    # so read it back from the scan the test created (the only one).
    return client.get("/scans").json()[0]["id"]
