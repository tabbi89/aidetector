"""The run reads its own trace for signs it never reached the API.

A run where every request answered 404, or where one identity's key was
refused everywhere, completes like any other and reads as a clean result.
``engine.target_health`` turns those into one line naming the evidence and
the fix.
"""
from __future__ import annotations

from typing import Any

from app.engine.target_health import DEGRADED, UNREACHED, diagnose

BASE = "http://caddy/api/v1"


def _row(route: str, status: int | None, *, identity: str = "reader",
         method: str = "GET", error: str | None = None, pass_: str = "engine") -> dict[str, Any]:
    return {"method": method, "route": route, "identity": identity, "pass": pass_,
            "error": error, "response": {"status": status}}


def test_every_collection_route_404ing_names_the_url_and_the_doubled_prefix() -> None:
    rows = [_row("/api/v1/monitors", 404), _row("/api/v1/incidents", 404),
            _row("/api/v1/status-pages", 404), _row("/api/v1/monitors/{id}", 404)]
    [(stage, note)] = diagnose(BASE, rows, [])
    assert stage == UNREACHED
    assert "4 of 4" not in note  # collection routes only: an item 404 proves nothing
    assert "3 of 3 requests" in note and "never reached the API" in note
    assert "http://caddy/api/v1/api/v1/monitors" in note
    assert "set target: to http://caddy" in note


def test_a_route_that_does_not_repeat_the_target_gets_the_general_hint() -> None:
    rows = [_row("/monitors", 404)] * 3
    [(_stage, note)] = diagnose("http://caddy", rows, [])
    assert "http://caddy/monitors" in note and "base URL" in note


def test_a_healthy_api_with_item_404s_and_probe_paths_is_quiet() -> None:
    # Placeholder ids 404 and so does /.git — on an API that works.
    rows = [
        _row("/monitors", 200), _row("/incidents", 200), _row("/status-pages", 200),
        *[_row("/monitors/{id}", 404)] * 20,
        *[_row("(unattributed)", 404)] * 20,
        *[_row("/monitors", 404, pass_="discovery")] * 20,
    ]
    assert diagnose(BASE, rows, ["reader"]) == []


def test_item_routes_count_when_the_spec_has_nothing_else() -> None:
    rows = [_row("/things/{id}", 404)] * 4
    assert diagnose(BASE, rows, []) != []


def test_no_answer_at_all_says_unreachable_and_names_the_docker_flag() -> None:
    rows = [_row("/monitors", None, error="ConnectError")] * 3
    [(stage, note)] = diagnose(BASE, rows, [])
    assert stage == UNREACHED
    assert "ConnectError" in note and "--docker-network" in note


def test_a_target_answering_5xx_everywhere_is_called_failing() -> None:
    rows = [_row("/monitors", 502)] * 5
    [(stage, note)] = diagnose(BASE, rows, [])
    assert stage == DEGRADED
    assert "5 of 5 requests answered 5xx" in note


def test_an_identity_refused_everywhere_is_named_and_the_others_are_not() -> None:
    rows = [
        *[_row("/monitors", 401, identity="workspace-b")] * 3,
        *[_row("/monitors", 200, identity="workspace-a")] * 3,
        # One 200 among its 401s: a key that works somewhere is not "rejected".
        *[_row("/monitors", 401, identity="mixed")] * 3,
        _row("/incidents", 200, identity="mixed"),
    ]
    notes = diagnose(BASE, rows, ["workspace-a", "workspace-b", "mixed"])
    assert notes == [(DEGRADED, notes[0][1])]
    assert "identity 'workspace-b' was rejected" in notes[0][1]


def test_404s_without_credentials_name_both_causes() -> None:
    # An API may 404 a caller without a key so a resource's existence does not
    # leak; with no identity the run cannot tell that from a missing route.
    rows = [_row("/monitors", 404, identity="anonymous")] * 3
    [(stage, note)] = diagnose(BASE, rows, [])
    assert stage == UNREACHED
    assert "without credentials" in note and "add an identity" in note
    assert "never reached the API" not in note


def test_too_few_requests_say_nothing() -> None:
    assert diagnose(BASE, [_row("/monitors", 404)] * 2, []) == []
    assert diagnose(BASE, [], ["a"]) == []


def test_the_engine_loop_announces_it_from_the_real_trace() -> None:
    """End to end over the in-process app: routes the target does not serve."""
    from app.engine.execution import _run_engine_checks
    from tests import factories
    from tests.fakes import FakeJournal

    ops = [factories.operation("GET", f"/api/v1/missing{i}") for i in range(4)]
    ctx = factories.scan_context(ops)
    journal = FakeJournal()
    _run_engine_checks(ctx, journal, max_workers=1)
    health = [msg for stage, _pct, msg in journal.events if stage == UNREACHED]
    assert health and "404" in health[0]
