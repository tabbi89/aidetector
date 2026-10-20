"""A NUL anywhere in a run's trace or evidence must not fail the run.

PostgreSQL text and jsonb columns refuse ``\\u0000``. ``schema_fuzz`` invents
query parameter names carrying it, so the first local run to upload its trace
answered 500 and was lost.
"""
from __future__ import annotations

from types import SimpleNamespace

from app.core.jsonsafe import REPLACEMENT, jsonb_safe
from app.engine.base import HttpProbe


def test_jsonb_safe_replaces_nul_in_keys_values_and_nesting() -> None:
    raw = {"a\x00": ["x\x00y", {"k": "\x00"}], "n": 1, "t": ("\x00",)}
    assert jsonb_safe(raw) == {
        f"a{REPLACEMENT}": [f"x{REPLACEMENT}y", {"k": REPLACEMENT}],
        "n": 1,
        "t": [REPLACEMENT],
    }


def test_a_fuzzed_nul_parameter_name_reaches_the_trace_storable() -> None:
    class Client:
        def request(self, method, url, **kwargs):
            return SimpleNamespace(status_code=200, headers={}, text="{}", content=b"{}")

    probe = HttpProbe(Client(), max_requests=5)
    probe.send("GET", "/monitors", params={"f\x1e\x1d:\xaa\x00": "1"})
    [row] = probe.mutations
    assert "\x00" not in repr(row)
    assert row["request"]["query_fields"] == [f"f\x1e\x1d:\xaa{REPLACEMENT}"]


def test_a_local_upload_with_nul_in_its_trace_and_evidence_is_stored(
    client, scan_with_spec, monkeypatch
) -> None:
    from app.core.config import settings

    monkeypatch.setattr(settings, "local_runner_enabled", True)
    sid = scan_with_spec("http://127.0.0.1")
    claim = client.post(f"/scans/{sid}/local-runs", json={"authorized": True}).json()
    row = {
        "sequence": 1, "method": "GET", "route": "/items", "check": "schema_fuzz",
        "pass": "engine", "identity": "anonymous", "elapsed_ms": 1.0, "error": None,
        "request": {"headers": {}, "query_fields": ["f\x00"], "json_shape": None,
                    "json_body": "", "content_bytes": 0},
        "response": {"status": 200, "attempt_statuses": [200], "headers": {},
                     "content_type": "", "body_bytes": 0, "body": "\x00", "truncated": False,
                     "body_omitted": False, "sensitive_fields": [], "json_shape": None},
    }
    finding = {
        "check": "reflected_injection", "owasp_id": "API8", "severity": "low",
        "title": "Reflected\x00 input", "description": "echo \x00",
        "evidence": {"route": "/items", "payload": "a\x00b"}, "confidence": "heuristic",
    }
    r = client.post(
        f"/runner/runs/{claim['run_id']}/complete",
        headers={"X-Run-Token": claim["token"]},
        json={"findings": [finding], "requests": 1, "trace": [row]},
    )
    assert r.status_code == 200, r.text
    titles = [f["title"] for f in client.get(f"/scans/{sid}/findings").json()]
    assert titles == [f"Reflected{REPLACEMENT} input"]
