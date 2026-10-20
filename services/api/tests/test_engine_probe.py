"""HttpProbe accounting: the request budget, per-operation fairness, coverage.

The budget is a safety ceiling rather than a tuning knob — past it ``send()``
returns None and checks stop silently — so it gets its own tests.
"""
from __future__ import annotations

from fastapi.testclient import TestClient

from app.domain.enums import Severity
from app.engine.base import (
    HttpProbe,
    TargetOperation,
)
from tests import factories
from tests.vulnapp import vulnapp

OPERATIONS = factories.engine_operations()
CREDS = factories.two_identities()


def test_probe_attributes_requests_per_operation_and_check():
    ctx = factories.scan_context(OPERATIONS, credentials=CREDS)
    probe = ctx.probe
    from app.engine.checks.injection import ReflectedInjectionCheck

    probe.check_context = "reflected_injection"
    ReflectedInjectionCheck().run(ctx)

    # /search (query param q) was fuzzed, and its requests are attributed to it
    # under the reflected_injection check.
    search = next(o for o in OPERATIONS if o.path == "/search")
    assert probe.coverage.get(search.id, {}).get("reflected_injection", 0) > 0
    # /health has no params, so it was never touched.
    health = next(o for o in OPERATIONS if o.path == "/health")
    assert health.id not in probe.coverage


def test_probe_respects_request_budget():
    probe = HttpProbe(TestClient(vulnapp), max_requests=1)
    assert probe.send("GET", "/health") is not None
    assert probe.send("GET", "/health") is None  # budget exhausted


def test_probe_default_allows_750_requests_then_stops():
    probe = HttpProbe(_Recorder("{}"))
    for _ in range(750):
        assert probe.send("GET", "/health") is not None
    assert probe.count == 750
    assert probe.send("GET", "/health") is None
    assert probe.count == 750


def test_probe_preserves_throttle_statuses_across_retry():
    from types import SimpleNamespace

    class Client:
        def __init__(self):
            self.calls = 0

        def request(self, method, path, **kwargs):
            self.calls += 1
            status = 429 if self.calls == 1 else 200
            return SimpleNamespace(
                status_code=status,
                headers={"content-type": "application/json", "retry-after": "0"},
                text="{}",
                content=b"{}",
            )

    probe = HttpProbe(Client(), max_requests=5)
    probe._max_backoff = 0
    result = probe.send("GET", "/auth/status")

    assert result is not None
    assert result.status == 200
    assert result.attempt_statuses == (429, 200)
    assert result.was_throttled is True
    assert probe.mutations[0]["response"]["attempt_statuses"] == [429, 200]


def test_probe_per_operation_fairness_cap():
    """One operation cannot monopolise the whole request budget: the per-op cap
    stops it well before the global max is spent."""
    ops = [
        TargetOperation(id=f"op{i}", method="GET", path=f"/p{i}", params=[])
        for i in range(20)
    ]
    probe = HttpProbe(TestClient(vulnapp), max_requests=100, operations=ops)
    sent = 0
    for _ in range(50):
        if probe.send("GET", "/p0") is None:  # attributed to op0 by path template
            break
        sent += 1
    # per-op cap = max(10, ceil(100/20)*2) = 10, far below the global 100.
    assert sent == 10
    assert probe.count == 10


def test_probe_keeps_ids_and_credentials_out_of_the_trace():
    operations = [
        TargetOperation(
            id="patch-widget", method="PATCH", path="/widgets/{widget_id}", params=[]
        )
    ]
    probe = HttpProbe(TestClient(vulnapp), max_requests=10, operations=operations)
    probe.check_context = "write_authz"

    result = probe.send(
        "PATCH",
        "/widgets/secret-id-123",
        headers={"Authorization": "Bearer do-not-store", "X-Debug-Mode": "enabled"},
        params={"token": "also-secret"},
        json={"name": "customer value", "nested": {"enabled": True}},
    )

    assert result is not None
    row = probe.mutations[0]
    assert row["route"] == "/widgets/{widget_id}"
    assert row["check"] == "write_authz"
    assert row["request"]["query_fields"] == ["token"]
    assert row["request"]["headers"] == {
        "authorization": "<redacted>",
        "content-type": "application/json",
        "x-debug-mode": "enabled",
    }
    assert row["response"]["headers"]["content-type"]
    assert row["request"]["json_shape"] == {
        "name": {"type": "string", "length": 14},
        "nested": {"enabled": {"type": "boolean"}},
    }
    # The payload we generated is retained (redacted) — it is our own data, and
    # it is what answers "why was this rejected" beside the response body.
    assert '"name":"customer value"' in row["request"]["json_body"]
    serialized = str(row)
    # The rendered id, the credential and the query secret still never land: the
    # route is templated, and header/param values carrying credentials are cut.
    assert "secret-id-123" not in serialized
    assert "do-not-store" not in serialized
    assert "also-secret" not in serialized


def test_probe_redacts_known_secrets_out_of_the_request_body():
    """A credential echoed into a payload is masked like one anywhere else."""
    from app.core.redact import Redactor

    probe = HttpProbe(
        TestClient(vulnapp),
        max_requests=10,
        redact=Redactor(["do-not-store"]),
    )
    assert probe.send("POST", "/widgets", json={"token": "do-not-store"}) is not None
    assert "do-not-store" not in probe.mutations[0]["request"]["json_body"]


def test_probe_masks_pii_shaped_fields_in_both_bodies():
    """The trace must not become a copy of the target's customer records."""
    from app.core.redact import Redactor

    probe = HttpProbe(TestClient(vulnapp), max_requests=10, redact=Redactor())
    payload = {"owner": {"ssn": "123-45-6789", "first_name": "Ada"},
               "routing_number": "021000021"}
    assert probe.send("POST", "/widgets", json=payload) is not None
    sent = probe.mutations[0]["request"]["json_body"]
    for value in ("123-45-6789", "Ada", "021000021"):
        assert value not in sent, f"{value} survived redaction"


def test_probe_records_read_requests_with_a_response_body():
    probe = HttpProbe(TestClient(vulnapp), max_requests=10)
    assert probe.send("GET", "/health") is not None
    assert len(probe.mutations) == 1
    row = probe.mutations[0]
    assert row["method"] == "GET"
    assert row["response"]["status"] == 200
    # The response body is retained (redacted by the runner) so a reviewer can
    # see what actually came back, not just its shape.
    assert row["response"]["body"]


def test_probe_redacts_the_response_body_when_a_redactor_is_supplied():
    from app.core.redact import Redactor

    probe = HttpProbe(
        TestClient(vulnapp),
        max_requests=10,
        redact=Redactor(["top-secret"]),
    )
    # /search reflects the query param verbatim — see the vulnapp handler.
    assert probe.send("GET", "/search", params={"q": "top-secret"}) is not None
    body = probe.mutations[0]["response"]["body"]
    assert "top-secret" not in body


# ---- Trace limits and attribution --------------------------------------------


class _Recorder:
    """Minimal client returning a body and content-type we control."""

    def __init__(self, body: str, content_type: str = "application/json") -> None:
        self._body = body
        self._content_type = content_type

    def request(self, method, path, **kwargs):
        import httpx

        return httpx.Response(
            200,
            content=self._body.encode(),
            headers={"content-type": self._content_type},
            request=httpx.Request(method, "http://t" + path),
        )


def test_trace_drops_non_textual_bodies_but_keeps_the_row():
    """A PDF or image decodes to mojibake that helps nobody and costs budget."""
    probe = HttpProbe(_Recorder("%PDF-1.4 binary", "application/pdf"), max_requests=5)
    assert probe.send("GET", "/report") is not None
    response = probe.mutations[0]["response"]
    assert response["body"] == ""
    assert response["body_omitted"] is True
    # The row still carries what it is worth: status and size.
    assert response["status"] == 200
    assert response["body_bytes"] > 0


def test_a_wide_nested_response_keeps_a_shape_the_upload_accepts():
    """A job carrying its user, its company and the company's account nests four
    wide objects deep; its full shape is over the server's cap, and one such row
    used to fail the whole local run's upload with a 422."""
    import json

    from app.api.schemas.runner import _TRACE_SHAPE_CHARS, RunnerTraceResponse
    from app.engine.probe import _SHAPE_CHARS

    def wide(level: int) -> dict:
        fields: dict = {f"field{n:02d}WithALongishName": "value" for n in range(40)}
        if level:
            fields["child"] = wide(level - 1)
        return fields

    probe = HttpProbe(_Recorder(json.dumps(wide(4))), max_requests=5)
    assert probe.send("GET", "/jobs/1") is not None
    shape = probe.mutations[0]["response"]["json_shape"]

    assert _SHAPE_CHARS == _TRACE_SHAPE_CHARS
    assert len(json.dumps(shape)) <= _TRACE_SHAPE_CHARS
    RunnerTraceResponse(json_shape=shape)  # the server's own validator
    # It degrades by depth, not to nothing: the top level is still described.
    assert shape["field00WithALongishName"] == {"type": "string", "length": 5}
    assert "child" in shape


def test_trace_stops_retaining_bodies_once_the_run_budget_is_spent():
    """One run's archive is bounded; rows past the budget keep their structure."""
    from app.engine.probe import _BODY_BUDGET

    # Prose rather than a long token: an unbroken 5000-character run would be
    # masked as an opaque blob before it could cost the budget anything.
    probe = HttpProbe(_Recorder('{"pad":"' + "lorem ipsum " * 500 + '"}'), max_requests=10_000)
    # A 750-request engine run plus 150 discovery requests can exceed the
    # retained-body budget even at the routine 1000-character limit.
    for _ in range(700):
        if probe.send("GET", "/big") is None:
            break
    retained = sum(len(row["response"]["body"]) for row in probe.mutations)
    assert retained <= _BODY_BUDGET
    # Every call is still logged — only the body text is dropped.
    assert any(row["response"]["body_omitted"] for row in probe.mutations)
    assert all(row["response"]["status"] == 200 for row in probe.mutations)


def test_trace_names_the_identity_that_sent_each_request():
    """The redacted Authorization header hides the one fact an authz row needs."""
    low, high = CREDS[0], CREDS[1]
    probe = HttpProbe(TestClient(vulnapp), max_requests=10, credentials=list(CREDS))

    probe.send("GET", "/health", headers=high.headers())
    probe.send("GET", "/health", headers=low.headers())
    probe.send("GET", "/health")

    assert [row["identity"] for row in probe.mutations] == [
        high.name,
        low.name,
        "anonymous",
    ]


def test_absorb_merges_a_secondary_pass_into_one_ordered_log():
    """The discovery pass runs on its own budget but belongs in one request log."""
    main = HttpProbe(TestClient(vulnapp), max_requests=10)
    main.send("GET", "/health")
    secondary = HttpProbe(TestClient(vulnapp), max_requests=10)
    secondary.send("GET", "/health")
    secondary.send("GET", "/health")

    main.absorb(secondary, label="discovery")

    assert [row["sequence"] for row in main.mutations] == [1, 2, 3]
    assert [row["pass"] for row in main.mutations] == ["engine", "discovery", "discovery"]
    # And its requests are counted, without inflating the engine's own budget.
    assert main.count == 1
    assert main.secondary_requests == 2


def test_the_default_redactor_masks_even_when_none_is_supplied():
    """A caller that forgets a redactor gets less masking, never raw data.

    ``HttpProbe`` used to accept ``redact=None`` and store bodies verbatim, and
    one construction site in the runner did exactly that — on the discovery
    pass, the one set of endpoints the spec never declared.
    """
    probe = HttpProbe(_Recorder('{"ssn":"123-45-6789","email":"a@b.com"}'), max_requests=5)
    body = probe.send("GET", "/x") and probe.mutations[0]["response"]["body"]
    assert "123-45-6789" not in body
    assert "a@b.com" not in body


def test_the_discovery_probe_inherits_the_runs_secret_aware_redactor():
    """The second pass must mask the scan's own credentials, not just patterns."""
    from app.core.redact import Redactor
    from app.engine.base import ScanContext

    redactor = Redactor(["scan-credential-value"])
    ctx = ScanContext(
        base_url="http://t",
        operations=[],
        credentials=[],
        probe=HttpProbe(TestClient(vulnapp), redact=redactor),
        redact=redactor,
    )
    # What ``runner._run_discovery_probe`` builds.
    discovery = HttpProbe(
        _Recorder('{"echo":"scan-credential-value"}'), max_requests=5, redact=ctx.redact
    )
    assert discovery.send("GET", "/shadow") is not None
    assert "scan-credential-value" not in discovery.mutations[0]["response"]["body"]


def test_a_finding_carries_the_trace_rows_that_produced_it():
    """The link that turns a 600-row log into two rows worth reading."""
    from app.engine.base import EngineFinding
    from app.engine.run_record import append_finding
    from app.models.scan import Scan, ScanStatus

    operations = [TargetOperation(id="op-a", method="GET", path="/accounts/{account_id}")]
    probe = HttpProbe(TestClient(vulnapp), max_requests=10, operations=operations)
    probe.check_context = "bola"
    probe.send("GET", "/accounts/1", headers={"Authorization": "a"})
    probe.send("GET", "/accounts/2", headers={"Authorization": "b"})
    probe.check_context = "broken_auth"
    probe.send("GET", "/accounts/3")

    scan = Scan(target_base_url="http://t", status=ScanStatus.draft)
    append_finding(
        scan,
        EngineFinding(
            check="bola",
            owasp_id="API1:2023",
            severity=Severity.high,
            title="Possible BOLA",
            description="",
            evidence={"route": "/accounts/{account_id}"},
        ),
        None,
        probe.mutations,
    )

    # Only this check's rows on this route — not the broken_auth call.
    assert scan.findings[0].evidence["trace"] == [1, 2]


def test_trace_links_are_not_part_of_identity():
    """Sequence numbers move every run; a fingerprint must not."""
    from app.engine.fingerprint import fingerprint

    evidence = {"route": "/accounts/{account_id}", "method": "GET"}
    assert fingerprint("bola", "API1:2023", "t", evidence) == fingerprint(
        "bola", "API1:2023", "t", {**evidence, "trace": [4, 9, 17]}
    )
