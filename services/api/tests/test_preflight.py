"""The run probes a few endpoints for reachability before spending the budget.

A target that answers nothing is stopped early (``target_unreached``); a target
that answers anything proceeds to the full run and the post-hoc diagnosis.
"""
from __future__ import annotations

from app.engine.operations import TargetOperation
from app.engine.preflight import UNREACHED, assess, choose_probe_ops, run_preflight


def _ops():
    return [
        TargetOperation(id="a", method="POST", path="/items"),
        TargetOperation(id="b", method="GET", path="/items/{id}",
                        params=[{"name": "id", "in": "path", "required": True}]),
        TargetOperation(id="c", method="GET", path="/health"),
        TargetOperation(id="d", method="GET", path="/items"),
    ]


def test_choose_probe_ops_prefers_gets_with_the_fewest_path_params():
    chosen = choose_probe_ops(_ops())
    assert all(op.method == "GET" for op in chosen)
    # /health and /items (no path params) come before /items/{id}
    assert [op.path for op in chosen[:2]] == ["/health", "/items"]


def test_assess_aborts_only_when_nothing_answered():
    assert assess(answered=0, attempted=3) and assess(answered=0, attempted=3)[0][0] == UNREACHED
    assert assess(answered=1, attempted=3) == []  # any answer proceeds
    assert assess(answered=0, attempted=1) == []  # one probe is too little signal


def test_run_preflight_proceeds_when_a_probe_answers():
    def send(method, path, headers=None):
        class _R:
            status = 404
        return _R()

    assert run_preflight(_ops(), {}, send) == []


def test_run_preflight_aborts_when_every_probe_errors_or_returns_none():
    def send(method, path, headers=None):
        raise ConnectionError("refused")

    events = run_preflight(_ops(), {}, send)
    assert events and events[0][0] == UNREACHED
    assert "none of the" in events[0][1]


def test_run_preflight_is_a_noop_without_get_operations():
    only_posts = [TargetOperation(id="a", method="POST", path="/items")]

    def send(method, path, headers=None):  # pragma: no cover - must not be called
        raise AssertionError("no GET operation should be probed")

    assert run_preflight(only_posts, {}, send) == []
