from __future__ import annotations

from types import SimpleNamespace

from app.engine.adaptive.contracts import AdaptiveSettings
from app.engine.adaptive.runner import run_adaptive
from tests import factories


class Refiner:
    def refine(self, payload: dict) -> dict:
        assert payload["method"] in {"GET", "POST"}
        return {"action": "refine", "variant": "v2", "assessment": "uncertain"}


def test_adaptive_loop_is_bounded_and_records_sanitized_trace() -> None:
    operations = [
        factories.operation(
            "GET",
            "/search",
            params=[
                {
                    "name": "q",
                    "in": "query",
                    "required": False,
                    "schema": {"type": "string", "maxLength": 4},
                }
            ],
        )
    ]
    ctx = factories.scan_context(operations, seed=7, max_requests=20)
    findings, history = run_adaptive(
        ctx,
        planner=Refiner(),
        settings=AdaptiveSettings(attempts=3, endpoints=1, requests=4, seconds=30),
    )
    assert ctx.probe.count == 4  # one valid control plus three revisions
    assert history["requests"] == 4
    assert len(history["tests"]) == 1
    assert len(history["tests"][0]["attempts"]) == 3
    assert all("value" not in attempt for attempt in history["tests"][0]["attempts"])
    assert all(f.confidence.value == "heuristic" for f in findings)


def test_adaptive_skips_mutating_operations_without_mutation_opt_in() -> None:
    op = factories.operation(
        "POST",
        "/widgets",
        params=[{"name": "name", "in": "body", "required": True,
                  "schema": {"type": "string"}}],
    )
    ctx = factories.scan_context([op], allow_mutation=False, seed=2)
    findings, history = run_adaptive(ctx)
    assert findings == []
    assert ctx.probe.count == 0
    assert history["tests"][0]["stop_reason"] == "mutation_disabled"


class RecordingClient:
    def __init__(self) -> None:
        self.requests: list[dict] = []

    def request(self, method: str, url: str, **kwargs):
        self.requests.append({"method": method, "url": url, **kwargs})
        return SimpleNamespace(
            status_code=201,
            headers={"content-type": "application/json"},
            text="{}",
            content=b"{}",
        )


def test_adaptive_probes_post_json_body_only_when_mutation_is_enabled() -> None:
    op = factories.operation(
        "POST",
        "/widgets",
        params=[
            {
                "name": "name",
                "in": "body",
                "required": True,
                "schema": {"type": "string", "maxLength": 4},
            }
        ],
    )
    client = RecordingClient()
    ctx = factories.scan_context(
        [op], client=client, allow_mutation=True, seed=2, max_requests=10
    )
    findings, history = run_adaptive(
        ctx,
        planner=Refiner(),
        settings=AdaptiveSettings(attempts=2, endpoints=1, requests=4, seconds=30),
    )

    assert len(client.requests) == 3  # valid control plus two bounded variants
    assert [request["method"] for request in client.requests] == ["POST"] * 3
    assert all(isinstance(request["json"], dict) for request in client.requests)
    assert all("name" in request["json"] for request in client.requests)
    assert history["tests"][0]["location"] == "body"
    assert len(history["tests"][0]["attempts"]) == 2
    assert all("value" not in attempt for attempt in history["tests"][0]["attempts"])
    assert all(f.confidence.value == "heuristic" for f in findings)


def test_adaptive_reuses_a_prepared_id_for_patch_body_tests() -> None:
    op = factories.operation(
        "PATCH",
        "/merchants/{merchant_id}",
        params=[
            {"name": "merchant_id", "in": "path", "required": True},
            {
                "name": "name",
                "in": "body",
                "required": True,
                "schema": {"type": "string", "maxLength": 4},
            },
        ],
    )
    client = RecordingClient()
    ctx = factories.scan_context(
        [op], client=client, allow_mutation=True, seed=2, max_requests=10
    )
    ctx.resource_ids = {"merchant": "existing-42"}

    run_adaptive(
        ctx,
        settings=AdaptiveSettings(attempts=2, endpoints=1, requests=4, seconds=30),
    )

    assert {request["url"] for request in client.requests} == {
        "/merchants/existing-42"
    }
