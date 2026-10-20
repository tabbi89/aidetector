"""The local runner, end to end against the real ingest API and the vulnerable app.

The server is the test client (a real FastAPI app on a real database); the target
is the in-process vulnerable app behind the real async transport. So these tests
exercise claim → run → redact → upload → persist for real, with no network.
"""
from __future__ import annotations

import io
import json
from types import SimpleNamespace

import httpx
import pytest

from app.core.config import settings
from app.core.redact import Redactor
from app.core.target_guard import TargetNotAllowed
from app.domain.enums import Confidence, Severity
from app.engine.base import EngineFinding
from app.engine.transport import AsyncHttpClientBridge
from app.runner import main as runner
from app.runner.main import (
    EXIT_BAD_INPUT,
    EXIT_CANCELLED,
    EXIT_FAILED,
    EXIT_OK,
    HttpRunJournal,
    ServerLink,
    _bind_credentials,
    execute,
)

SECRETS = {"alice": {"secret": "alice-token"}, "admin": {"secret": "admin-token"}}


@pytest.fixture(autouse=True)
def _enabled(monkeypatch):
    monkeypatch.setattr(settings, "local_runner_enabled", True)


@pytest.fixture
def bridges(monkeypatch):
    """Bind the runner's real async transport to the in-process target."""
    from tests.vulnapp import vulnapp

    made: list[str] = []

    def factory(base_url, **kwargs):
        made.append(base_url)
        return AsyncHttpClientBridge(
            base_url,
            **{
                **kwargs,
                "requests_per_second": 10000,
                # Replaces the pinned network transport: the target is in-process.
                "transport": httpx.ASGITransport(app=vulnapp),
            },
        )

    monkeypatch.setattr(runner, "AsyncHttpClientBridge", factory)
    return made


def _claim(client, scan, **flags):
    r = client.post(f"/scans/{scan.id}/local-runs", json={"authorized": True, **flags})
    assert r.status_code == 201, r.text
    return r.json()


def _cfg(claim, secrets=SECRETS):
    return {"server": "http://testserver", "run": claim, "secrets": secrets, "runner_version": "t1"}


def _go(client, claim, secrets=SECRETS, **patch):
    cfg = _cfg(claim, secrets)
    cfg["run"].update(patch)
    link = ServerLink("http://testserver", claim["run_id"], claim["token"], client=client)
    out = io.StringIO()
    return execute(cfg, link, out=out), out.getvalue()


def test_a_local_run_uploads_graded_findings_the_server_persists(
    client, make_scan, bridges
):
    scan = make_scan(target_base_url="http://127.0.0.1")
    claim = _claim(client, scan)
    code, log = _go(client, claim)
    assert code == EXIT_OK, log

    assert client.get(f"/scans/{scan.id}").json()["status"] == "completed"
    findings = client.get(f"/scans/{scan.id}/findings").json()
    bola = [f for f in findings if f["check"] == "bola"]
    assert bola and all(f["confidence"] == "verified" for f in bola)
    # Fingerprint and remediation are the server's, not the runner's.
    assert all(f["fingerprint"] and f["remediation"] for f in findings)

    run = client.get(f"/scans/{scan.id}/runs").json()[0]
    assert run["status"] == "completed"
    assert run["executor"]["kind"] == "local_runner" and run["executor"]["version"] == "t1"
    assert run["executor"]["engine_digest"]
    assert 0 < run["requests"] <= claim["max_requests"]
    assert run["coverage"] and any(row["requests"] for row in run["coverage"])
    # The token died with the run.
    link = ServerLink("http://testserver", claim["run_id"], claim["token"], client=client)
    assert link.post("/heartbeat", {}).status_code == 409


def test_a_local_run_is_recorded_like_a_server_run(client, make_scan, bridges):
    scan = make_scan(target_base_url="http://127.0.0.1")
    claim = _claim(client, scan)
    code, log = _go(client, claim)
    assert code == EXIT_OK, log

    run = client.get(f"/scans/{scan.id}/runs").json()[0]
    trace = client.get(f"/scans/{scan.id}/runs/{run['run_number']}/trace?limit=500").json()
    # Every request the runner made is in the trace, numbered in order.
    assert run["trace_count"] == trace["total"] == run["requests"]
    assert [row["sequence"] for row in trace["rows"]] == list(range(1, len(trace["rows"]) + 1))
    assert {row["identity"] for row in trace["rows"]} >= {"alice", "admin"}
    # A finding links to the rows that produced it, as on a server run.
    sequences = {row["sequence"] for row in trace["rows"]}
    bola = [f for f in client.get(f"/scans/{scan.id}/findings").json() if f["check"] == "bola"]
    assert bola and all(f["evidence"]["trace"] for f in bola)
    assert all(set(f["evidence"]["trace"]) <= sequences for f in bola)
    # The methodology manifest came with it.
    exported = client.get(f"/scans/{scan.id}/runs").json()[0]
    assert exported["manifest"]["metrics"]["scope"]


def test_a_local_run_finds_what_a_server_run_finds(
    client, db_session, make_scan, engine_client, bridges
):
    """Same scan, two executors: the findings' identities must agree."""
    from app.engine.runner import run_scan

    server_scan = make_scan(target_base_url="http://127.0.0.1")
    run_scan(db_session, server_scan, client=engine_client)
    expected = {f.fingerprint for f in server_scan.findings}
    assert expected, "the server run should have found something"

    local_scan = make_scan(target_base_url="http://127.0.0.1")
    code, log = _go(client, _claim(client, local_scan))
    assert code == EXIT_OK, log
    got = {f["fingerprint"] for f in client.get(f"/scans/{local_scan.id}/findings").json()}

    assert got == expected, (
        f"only on the server run: {sorted(expected - got)}\n"
        f"only on the local run: {sorted(got - expected)}"
    )


def test_no_secret_ever_reaches_the_server(client, make_scan, bridges):
    scan = make_scan(target_base_url="http://127.0.0.1")
    claim = _claim(client, scan)
    token = claim["token"]
    code, log = _go(client, claim)
    assert code == EXIT_OK, log

    everything = json.dumps(
        {
            "scan": client.get(f"/scans/{scan.id}").json(),
            "findings": client.get(f"/scans/{scan.id}/findings").json(),
            "events": client.get(f"/scans/{scan.id}/events").json(),
            "runs": client.get(f"/scans/{scan.id}/runs").json(),
            "trace": client.get(f"/scans/{scan.id}/runs/1/trace?limit=500").json(),
            "export": client.get(f"/scans/{scan.id}/export").json(),
        }
    )
    for secret in ("alice-token", "admin-token", token):
        assert secret not in everything, f"{secret!r} reached the server's stored data"
        assert secret not in log, f"{secret!r} was printed by the runner"


def test_a_missing_secret_drops_that_identity_with_a_reason(client, make_scan, bridges):
    scan = make_scan(target_base_url="http://127.0.0.1")
    code, log = _go(client, _claim(client, scan), secrets={"alice": {"secret": "alice-token"}})
    assert code == EXIT_OK, log
    assert "no secret was supplied for credential 'admin'" in log
    events = client.get(f"/scans/{scan.id}/events").json()
    assert any(e["stage"] == "credential_missing" for e in events)
    assert any(e["stage"] == "identities_unavailable" for e in events)
    # ...and the run says so, so a later diff cannot call admin's findings fixed.
    gaps = client.get(f"/scans/{scan.id}/runs").json()[0]["gaps"]
    assert gaps["identities_missing"] == ["admin"]


def _shape(name: str, role: str) -> dict:
    return {
        "name": name,
        "role": role,
        "auth_type": "header",
        "header_name": "Authorization",
    }


def test_two_identities_with_the_same_role_keep_distinct_secrets():
    run = {"credentials": [_shape("alice", "user"), _shape("bob", "user")]}
    creds, events, sensitive = runner._bind_credentials(
        run, {"alice": {"secret": "alice-token"}, "bob": {"secret": "bob-token"}}
    )
    assert [(c.name, c.secret) for c in creds] == [
        ("alice", "alice-token"),
        ("bob", "bob-token"),
    ]
    assert events == []
    assert set(sensitive) == {"alice-token", "bob-token"}


def test_a_role_key_is_refused_when_two_identities_share_the_role():
    run = {"credentials": [_shape("alice", "user"), _shape("bob", "user")]}
    creds, events, _ = runner._bind_credentials(run, {"user": {"secret": "one-token"}})
    assert creds == []
    assert [stage for stage, _ in events] == [
        "credential_ambiguous",
        "credential_ambiguous",
    ]
    assert "'user'" in events[0][1] and "key it by name" in events[0][1]


def test_a_role_key_still_binds_when_the_role_is_unique():
    run = {"credentials": [_shape("alice", "user"), _shape("admin", "admin")]}
    creds, events, _ = runner._bind_credentials(
        run,
        {"user": {"secret": "alice-token"}, "admin": {"secret": "admin-token"}},
    )
    assert [(c.name, c.secret) for c in creds] == [
        ("alice", "alice-token"),
        ("admin", "admin-token"),
    ]
    assert events == []


def test_a_web_cancel_stops_the_run_as_cancelled(client, make_scan, bridges):
    scan = make_scan(target_base_url="http://127.0.0.1")
    claim = _claim(client, scan)
    assert client.post(f"/scans/{scan.id}/cancel").status_code == 200
    code, log = _go(client, claim)
    assert code == EXIT_CANCELLED, log
    assert client.get(f"/scans/{scan.id}").json()["status"] == "cancelled"
    assert client.get(f"/scans/{scan.id}/runs").json()[0]["status"] == "cancelled"


def test_the_request_budget_is_the_servers_and_a_spent_one_is_reported(
    client, make_scan, bridges
):
    scan = make_scan(target_base_url="http://127.0.0.1")
    claim = _claim(client, scan)
    code, log = _go(client, claim, max_requests=5)
    assert code == EXIT_OK, log
    run = client.get(f"/scans/{scan.id}/runs").json()[0]
    assert run["requests"] <= 5
    assert run["gaps"]["budget_exhausted"] is True
    assert "request budget" in log


def test_the_runner_refuses_cloud_metadata_before_opening_a_socket(
    client, make_scan, bridges
):
    scan = make_scan(target_base_url="http://127.0.0.1")
    claim = _claim(client, scan)
    # The server would never issue this target; the runner must refuse it anyway.
    code, log = _go(client, claim, target_base_url="http://169.254.169.254")
    assert code == EXIT_FAILED
    assert "metadata" in log
    assert bridges == [], "no transport may be built for a refused target"
    assert client.get(f"/scans/{scan.id}").json()["status"] == "failed"


def test_private_hosts_are_allowed_but_ipv6_embedded_metadata_is_not():
    runner._allowed("http://10.0.0.5")  # reaching internal hosts is the point
    runner._allowed("http://192.168.1.20:8080")
    with pytest.raises(TargetNotAllowed):
        runner._allowed("http://169.254.169.254")
    with pytest.raises(TargetNotAllowed):
        runner._allowed("http://[::ffff:169.254.169.254]")


def test_bad_stdin_is_a_usage_error_not_a_crash():
    assert runner.main(io.StringIO("not json")) == EXIT_BAD_INPUT
    assert runner.main(io.StringIO("{}")) == EXIT_BAD_INPUT
    assert runner.main(io.StringIO('{"server": "http://s", "run": {"run_id": "x"}}')) == (
        EXIT_BAD_INPUT
    )


def test_an_upload_retries_a_server_error_but_not_a_refusal(monkeypatch):
    monkeypatch.setattr(runner.time, "sleep", lambda _s: None)

    def link_returning(*codes):
        answers = [httpx.Response(c, json={"detail": "d"}) for c in codes]
        return SimpleNamespace(post=lambda *_a, **_k: answers.pop(0))

    assert runner._upload(link_returning(503, 502, 200), {})[0] is True
    ok, detail = runner._upload(link_returning(503, 503, 503), {})
    assert ok is False and "503" in detail
    # A 4xx will not change on retry: one attempt, not three.
    link = link_returning(422, 200)
    ok, detail = runner._upload(link, {})
    assert ok is False and "422" in detail


def test_the_journal_redacts_before_anything_is_queued_for_upload():
    link = SimpleNamespace(post=lambda *_a, **_k: httpx.Response(200, json={"cancel": False}))
    journal = HttpRunJournal(link, Redactor(["sk-super-secret"]), out=io.StringIO())
    journal.record(
        EngineFinding(
            check="security_headers",
            owasp_id=None,
            severity=Severity.low,
            title="leaks sk-super-secret",
            description="the header held sk-super-secret",
            evidence={"header": "Authorization: sk-super-secret"},
            confidence=Confidence.verified,
        )
    )
    assert "sk-super-secret" not in json.dumps(journal.findings)


def test_a_server_refusal_marks_the_run_lost_and_stops_the_checks():
    link = SimpleNamespace(post=lambda *_a, **_k: httpx.Response(409, json={}))
    journal = HttpRunJournal(link, Redactor(), out=io.StringIO())
    assert journal.cancelled() is False
    journal.heartbeat()
    assert journal.lost is True and journal.cancelled() is True


def test_the_runner_link_identifies_as_the_cli_so_the_hosted_proxy_routes_it_to_the_api():
    """deploy/caddy/Caddyfile sends root paths to the API only for aidetector-cli/.

    httpx's default User-Agent landed every heartbeat on the web app, whose 404
    the runner read as a lost run while the API reaped the silent scan.
    """
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.headers["user-agent"])
        return httpx.Response(200, json={"cancel": False})

    client = httpx.Client(
        base_url="https://runpentests.example", transport=httpx.MockTransport(handler)
    )
    link = ServerLink("https://runpentests.example", "run-1", "tok", client=client)
    link.post("/heartbeat", {})
    link.get("/memory")
    assert seen and all(ua.startswith("aidetector-cli/") for ua in seen)


def test_a_local_run_with_a_plan_scans_the_riskiest_operation_first(
    client, make_scan, bridges, monkeypatch
):
    from app.ai import cascade as cascade_mod
    from tests.fakes import FakePlanner

    scan = make_scan(target_base_url="http://127.0.0.1")
    claim = _claim(client, scan, plan=True)
    last = claim["operations"][-1]
    monkeypatch.setattr(
        cascade_mod,
        "AICascade",
        lambda: FakePlanner(lambda path: "high" if path == last["path"] else "low"),
    )
    seen: list[list[str]] = []
    real = runner._apply_plan

    def spy(link, journal, operations):
        real(link, journal, operations)
        seen.append([str(op.id) for op in operations])

    monkeypatch.setattr(runner, "_apply_plan", spy)
    code, log = _go(client, claim)
    assert code == EXIT_OK, log
    assert seen and seen[0][0] == str(last["id"])
    assert "AI prioritised" in log
    run = client.get(f"/scans/{scan.id}/runs").json()[0]
    assert run["status"] == "completed" and run["plan"]


def test_explicit_name_owns_its_key_even_when_another_identity_has_that_role():
    creds, events, _ = _bind_credentials(
        {
            "credentials": [
                {"name": "alice", "role": "user", "auth_type": "bearer"},
                {"name": "user", "role": "admin", "auth_type": "bearer"},
            ]
        },
        {"user": {"secret": "SYNTHETIC-USER-ONLY"}},
    )
    assert [(c.name, c.secret) for c in creds] == [
        ("user", "SYNTHETIC-USER-ONLY")
    ]
    assert [name for name, _ in events] == ["credential_missing"]


def test_role_key_still_binds_when_no_identity_is_named_after_it():
    creds, events, _ = _bind_credentials(
        {
            "credentials": [
                {"name": "alice", "role": "user", "auth_type": "bearer"},
                {"name": "root", "role": "admin", "auth_type": "bearer"},
            ]
        },
        {"user": {"secret": "ALICE"}, "admin": {"secret": "ROOT"}},
    )
    assert {(c.name, c.secret) for c in creds} == {
        ("alice", "ALICE"),
        ("root", "ROOT"),
    }
    assert events == []


def test_a_shared_role_key_is_still_ambiguous():
    creds, events, _ = _bind_credentials(
        {
            "credentials": [
                {"name": "alice", "role": "user", "auth_type": "bearer"},
                {"name": "bob", "role": "user", "auth_type": "bearer"},
            ]
        },
        {"user": {"secret": "ONE"}},
    )
    assert creds == []
    assert [name for name, _ in events] == [
        "credential_ambiguous",
        "credential_ambiguous",
    ]


def test_a_local_run_registers_with_the_services_collector(
    client, make_scan, bridges, monkeypatch
):
    from app.core.config import settings
    from tests.fakes import CollectorOob

    monkeypatch.setattr(settings, "runner_oast_server", "oast.test")
    monkeypatch.setattr(settings, "runner_oast_token", "collector-token-value")
    made: list[tuple[str, str | None]] = []

    def collector(server, *, token=None, binary=None):
        made.append((server, token))
        return CollectorOob([])

    monkeypatch.setattr(runner, "InteractshClient", collector)
    scan = make_scan(target_base_url="http://127.0.0.1")
    claim = _claim(client, scan)
    assert claim["oast"] == {"server": "oast.test", "token": "collector-token-value"}
    code, log = _go(client, claim)
    assert code == EXIT_OK, log

    # The runner started the collector the claim named, and said so.
    assert made == [("oast.test", "collector-token-value")]
    events = client.get(f"/scans/{scan.id}/events").json()
    assert any(e["stage"] == "oast" for e in events)
    # The collector's token is the service's, handed out for this run only:
    # nothing the run stored carries it.
    stored = json.dumps({
        "findings": client.get(f"/scans/{scan.id}/findings").json(),
        "events": events,
        "trace": client.get(f"/scans/{scan.id}/runs/1/trace?limit=500").json(),
    })
    assert "collector-token-value" not in stored


def test_a_collector_that_cannot_start_is_said_not_silent(
    client, make_scan, bridges, monkeypatch
):
    from app.core.config import settings
    from app.engine.oob import NullOobClient

    monkeypatch.setattr(settings, "runner_oast_server", "oast.test")
    monkeypatch.setattr(runner, "InteractshClient", lambda *a, **k: NullOobClient())
    scan = make_scan(target_base_url="http://127.0.0.1")
    code, log = _go(client, _claim(client, scan))
    assert code == EXIT_OK, log
    events = client.get(f"/scans/{scan.id}/events").json()
    assert any(e["stage"] == "oast_unavailable" for e in events)
    skipped = [e["message"] for e in events if e["stage"] == "check_skipped"]
    assert any("oob_injection" in m for m in skipped)


def test_the_claim_names_no_collector_when_the_service_has_none(client, make_scan):
    scan = make_scan(target_base_url="http://127.0.0.1")
    assert _claim(client, scan)["oast"] is None


class _FakeZap:
    """A ZAP scanner double: no network, one finding, reports no error."""

    error = None

    def __init__(self, *a: object, **k: object) -> None:
        pass

    def run(self, target: str, *, spec_urls: object = ()) -> list[EngineFinding]:
        return [EngineFinding(
            check="security_headers", owasp_id="API8:2023", severity=Severity.medium,
            confidence=Confidence.verified, title="ZAP: missing header",
            description="", evidence={"source": "zap", "route": "/"},
        )]


def test_a_local_run_runs_zap_from_a_sibling_url_and_uploads_its_finding(
    client, make_scan, bridges, monkeypatch
):
    import app.engine.zap as zap_mod

    monkeypatch.setattr(zap_mod, "ZapScanner", _FakeZap)
    scan = make_scan(target_base_url="http://127.0.0.1")
    claim = _claim(client, scan, zap=True)
    assert claim["adjunct_budget_seconds"] > 0  # the claim issues the shared budget
    cfg = _cfg(claim)
    cfg["adjuncts"] = {"zap": {"base_url": "http://zap.sibling", "api_key": "k"}}
    link = ServerLink("http://testserver", claim["run_id"], claim["token"], client=client)
    code = runner.execute(cfg, link, out=io.StringIO())
    assert code == EXIT_OK

    findings = client.get(f"/scans/{scan.id}/findings").json()
    assert any(f["check"] == "security_headers" and f["evidence"].get("source") == "zap"
               for f in findings)
    events = [e["stage"] for e in client.get(f"/scans/{scan.id}/events").json()]
    assert "zap" in events and "zap_done" in events


def test_a_spent_adjunct_budget_skips_zap_and_says_so(
    client, make_scan, bridges, monkeypatch
):
    import app.engine.zap as zap_mod

    ran: list[str] = []
    monkeypatch.setattr(zap_mod, "ZapScanner",
                        lambda *a, **k: ran.append("built") or _FakeZap())
    scan = make_scan(target_base_url="http://127.0.0.1")
    claim = _claim(client, scan, zap=True)
    cfg = _cfg(claim)
    # A zero budget is spent before the first pass.
    cfg["adjuncts"] = {"zap": {"base_url": "http://zap.sibling"}, "budget_seconds": -1}
    link = ServerLink("http://testserver", claim["run_id"], claim["token"], client=client)
    assert runner.execute(cfg, link, out=io.StringIO()) == EXIT_OK

    assert ran == []  # the scanner was never built
    events = [e["stage"] for e in client.get(f"/scans/{scan.id}/events").json()]
    assert "zap_skipped" in events
    # The diff must see it as not-retested, not clean.
    run = client.get(f"/scans/{scan.id}/runs").json()[0]
    assert "zap" in run["gaps"]["not_run"]

class _FakeJournal:
    """A minimal RunJournal the adjunct sink can drive, with seeded leads."""

    def __init__(self, leads: list[dict] | None = None) -> None:
        self.findings: list[dict] = list(leads or [])
        self.recorded: list[EngineFinding] = []
        self.events: list[str] = []
        self.progress = 50

    def record(self, finding: EngineFinding) -> None:
        self.recorded.append(finding)

    def event(self, stage: str, pct: int, message: str) -> None:
        self.events.append(stage)

    def cancelled(self) -> bool:
        return False


def test_the_runner_confirm_pass_reads_leads_and_records_a_confirmation(monkeypatch):
    import shutil

    import app.engine.sqlmap_confirm as sqlmap_mod
    from app.runner.main import _run_adjuncts
    from app.scans.run_options import RunOptions

    monkeypatch.setattr(shutil, "which", lambda name: "/usr/bin/" + name)
    for tool in ("dalfox", "commix", "tplmap"):  # only sqlmap has a lead here
        monkeypatch.setattr(settings, f"{tool}_bin", "")
    monkeypatch.setattr(settings, "sqlmap_bin", "")  # _enable_local_binaries sets it

    class _FakeConfirmer:
        def __init__(self, *a: object, **k: object) -> None:
            pass

        def run(self, base: str, targets: list[dict], *, deadline: object, should_stop: object):
            assert targets and targets[0]["path"] == "/items"
            return [EngineFinding(
                check="signature_injection", owasp_id="API8:2023", severity=Severity.high,
                confidence=Confidence.verified, title="sqlmap confirmed SQLi",
                description="", evidence={"route": "/items", "param": "id"},
            )]

    monkeypatch.setattr(sqlmap_mod, "SqlmapConfirmer", _FakeConfirmer)

    lead = {"check": "signature_injection", "operation_id": None,
            "evidence": {"family": "sqli", "location": "query", "method": "GET",
                         "path": "/items", "param": "id"}}
    journal = _FakeJournal([lead])
    ctx = SimpleNamespace(base_url="http://t", operations=[], pins=None, redact=Redactor())
    opts = RunOptions(confirm=True)
    skipped = _run_adjuncts(
        {}, {"adjunct_budget_seconds": 60, "requests_per_second": 5},
        ctx, journal, opts, Redactor(),
    )

    assert "sqlmap" not in skipped
    assert any(f.check == "signature_injection" for f in journal.recorded)
    assert "sqlmap_done" in journal.events


def test_enable_local_binaries_points_settings_at_tools_on_path(monkeypatch):
    import shutil

    from app.runner.main import _enable_local_binaries
    from app.scans.run_options import RunOptions

    for tool in ("sqlmap", "dalfox", "commix", "tplmap"):
        monkeypatch.setattr(settings, f"{tool}_bin", "")
    monkeypatch.setattr(settings, "testssl_bin", "")
    monkeypatch.setattr(shutil, "which", lambda name: "/usr/bin/" + name)
    _enable_local_binaries(RunOptions(confirm=True, testssl=True))
    assert settings.sqlmap_bin == "sqlmap" and settings.dalfox_bin == "dalfox"
    assert settings.testssl_bin in ("testssl.sh", "testssl")


def test_apply_ai_payloads_installs_variants_from_the_remote_planner():
    # The DB-free payload-generation half: given a planner that returns variants,
    # the reflection pool is deepened; a malformed string is dropped by the
    # sanitizer, never installed raw.
    from app.engine.context import ScanContext
    from app.engine.payloads import apply_ai_payloads

    class _Planner:
        def generate_payloads(self, families):
            return {"xss": ["<x>aidxAB</x>", "bad string with spaces"]}, []

    ctx = ScanContext(base_url="http://t", operations=[], credentials=[], probe=None, seed=1)
    events: list[str] = []
    apply_ai_payloads(ctx, _Planner(), lambda stage, pct, msg: events.append(stage))
    assert ctx.payload_provider is not None
    assert "genai_payloads_ready" in events


def test_remote_planner_round_trips_the_ai_endpoint(client, make_scan, monkeypatch):
    import app.ai.planner as planner_mod
    from app.runner.main import _RemotePlanner

    monkeypatch.setattr(settings, "premium_tenants", "*")

    class _FakePlanner:
        def generate_payloads(self, families):
            return {"xss": ["<x>aidxAB</x>"]}, []

        def refine(self, payload):
            return {"action": "stop"}, []

    monkeypatch.setattr(planner_mod, "OpusPlanner", lambda *a, **k: _FakePlanner())
    scan = make_scan(target_base_url="http://127.0.0.1")
    cfg = _claim(client, scan, genai_payloads=True, adaptive=True, premium=True, mutate=True)
    link = ServerLink("http://testserver", cfg["run_id"], cfg["token"], client=client)
    rp = _RemotePlanner(link)
    # payloads mode
    payloads, usages = rp.generate_payloads([{"family": "xss"}])
    assert payloads == {"xss": ["<x>aidxAB</x>"]} and usages == []
    # adaptive mode
    proposal, _ = rp.refine({"param": "q"})
    assert proposal == {"action": "stop"}


class _FlakyLink:
    """Fails the first ``fail`` posts with ``error`` (an exception or a status)."""

    def __init__(self, fail: int, error: object) -> None:
        self.fail, self.error = fail, error
        self.events: list[dict] = []
        self.posts = 0

    def post(self, path, payload, **_kwargs):
        self.posts += 1
        if self.fail > 0:
            self.fail -= 1
            if isinstance(self.error, Exception):
                raise self.error
            return httpx.Response(int(self.error), json={})
        if path == "/events":
            self.events.extend(payload["events"])
        return httpx.Response(200, json={})


@pytest.mark.parametrize("error", [httpx.ReadTimeout("slow"), 503])
def test_an_events_batch_that_was_not_delivered_is_sent_on_the_next_flush(error):
    """One timeout used to drop the batch for good — and with it the lines that
    say what limited the run."""
    link = _FlakyLink(fail=1, error=error)
    journal = HttpRunJournal(link, Redactor(), out=io.StringIO())
    journal.event("check_skipped", 0, "bfla did not run: no privileged operation")
    journal.event("resource_setup_note", 0, "resource setup failed after 1 attempt(s)")
    assert journal.flush() is False and link.events == []
    journal.event("bola", 50, "completed bola")
    assert journal.flush() is True
    # Nothing lost, nothing out of order.
    assert [e["stage"] for e in link.events] == ["check_skipped", "resource_setup_note", "bola"]


def test_a_batch_the_api_cannot_store_is_not_retried_forever():
    # A 500 is the API failing on this payload: resending it would block every
    # later event behind it.
    link = _FlakyLink(fail=1, error=500)
    journal = HttpRunJournal(link, Redactor(), out=io.StringIO())
    journal.event("x", 0, "poison")
    assert journal.flush() is True
    journal.event("y", 0, "after")
    journal.flush()
    assert [e["stage"] for e in link.events] == ["y"]


def test_the_end_of_run_drain_retries_and_then_gives_up():
    link = _FlakyLink(fail=2, error=httpx.ConnectError("down"))
    journal = HttpRunJournal(link, Redactor(), out=io.StringIO())
    journal.event("done", 85, "last line")
    assert journal.drain() is True and [e["stage"] for e in link.events] == ["done"]

    down = _FlakyLink(fail=100, error=httpx.ConnectError("down"))
    journal = HttpRunJournal(down, Redactor(), out=io.StringIO())
    journal.event("done", 85, "last line")
    assert journal.drain() is False and down.posts == 3  # bounded


def test_a_long_outage_keeps_a_bounded_buffer(monkeypatch):
    import app.runner.main as runner_main

    monkeypatch.setattr(runner_main, "_MAX_BUFFERED_EVENTS", 5)
    monkeypatch.setattr(runner_main, "_FLUSH_EVERY", 10_000)
    link = _FlakyLink(fail=100, error=httpx.ConnectError("down"))
    journal = HttpRunJournal(link, Redactor(), out=io.StringIO())
    for i in range(8):
        journal.event("e", 0, str(i))
        journal.flush()
    assert len(journal._events) == 5
