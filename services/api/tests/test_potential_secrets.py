"""G2: offline, bounded potential-secret detection without value retention."""
from __future__ import annotations

import json
import subprocess
from types import SimpleNamespace

import pytest

from app.domain.enums import Confidence
from app.engine.base import HeaderSnapshot, HttpProbe
from app.engine.checks.potential_secrets import PotentialSecretsCheck
from app.engine.secret_scan import (
    MAX_MATCHES,
    MAX_TOTAL_BYTES,
    MAX_UNITS,
    ScanUnit,
    _worker_scan,
    scan_offline,
)
from tests import factories

GITHUB_TOKEN_A = "ghp_" + "A" * 36
GITHUB_TOKEN_B = "ghp_" + "B" * 36
SLACK_TOKEN = "xoxb" + "-1234567890-abcdefghijklmnopqrstuvwxyz"
ENTROPY_SECRET = "N7mq2Vk9Lp4zX8cR5uY3wT6sQ1"


def _context(*, body: str = "", path: str = "/profile", spec_text: str | None = None):
    operation = factories.operation("GET", path, id="op")
    ctx = factories.scan_context(
        [operation], credentials=[], spec_text=spec_text, probe=HttpProbe(SimpleNamespace())
    )
    ctx.header_sweep = [
        HeaderSnapshot("op", "GET", path, 200, {"content-type": "application/json"}, body)
    ]
    return ctx


def test_offline_wrapper_detects_specific_and_entropy_secrets():
    matches = scan_offline(
        [
            ScanUnit(0, "json/object[0]", json.dumps(GITHUB_TOKEN_A)),
            ScanUnit(1, "spec/line-7", f'secret: "{ENTROPY_SECRET}"'),
        ]
    )
    assert {(match.source_id, match.detector) for match in matches} == {
        (0, "GitHub Token"),
        (1, "Base64 High Entropy String"),
    }
    assert all(not hasattr(match, "secret") for match in matches)


@pytest.mark.parametrize(
    "text",
    [
        'api_key: "your-api-key-here"',
        'password: "changeme"',
        'secret: "${API_SECRET}"',
        'token: "123e4567-e89b-12d3-a456-426614174000"',
    ],
)
def test_common_placeholders_and_uuids_are_not_reported(text):
    assert scan_offline([ScanUnit(0, "spec/line-1", text)]) == []


def test_detector_verification_is_explicitly_offline(monkeypatch):
    import requests

    def network_forbidden(*_args, **_kwargs):
        pytest.fail("detect-secrets attempted online verification")

    monkeypatch.setattr(requests.sessions.Session, "request", network_forbidden)
    result = _worker_scan([json.dumps(SLACK_TOKEN)], MAX_MATCHES)
    assert result == [{"unit": 0, "detector": "Slack Token"}]


def test_timeout_degrades_without_exposing_subprocess_diagnostics(monkeypatch, capsys):
    secret = GITHUB_TOKEN_A

    def timeout(*_args, **_kwargs):
        raise subprocess.TimeoutExpired(["python"], 0.1, output=secret, stderr=secret)

    monkeypatch.setattr(subprocess, "run", timeout)
    assert scan_offline([ScanUnit(0, "json/value", secret)]) == []
    captured = capsys.readouterr()
    assert secret not in captured.out
    assert secret not in captured.err


def test_wrapper_bounds_units_bytes_and_matches(monkeypatch):
    observed = {}

    def fake_run(*_args, **kwargs):
        payload = json.loads(kwargs["input"])
        observed.update(payload)
        rows = [
            {"unit": index, "detector": "Secret Keyword"}
            for index in range(len(payload["texts"]))
        ]
        return SimpleNamespace(returncode=0, stdout=json.dumps({"matches": rows}))

    monkeypatch.setattr(subprocess, "run", fake_run)
    units = [ScanUnit(index, f"line-{index}", "x" * 50_000) for index in range(400)]
    matches = scan_offline(units)

    assert len(observed["texts"]) <= MAX_UNITS
    assert sum(len(text.encode()) for text in observed["texts"]) <= MAX_TOTAL_BYTES
    assert len(matches) <= MAX_MATCHES


def test_truncation_is_reported_instead_of_silent(monkeypatch):
    """A bound cutting the input short is a signal, not a clean answer."""
    from app.engine.secret_scan import scan_offline_truncated

    monkeypatch.setattr(
        subprocess, "run",
        lambda *_args, **_kwargs: SimpleNamespace(
            returncode=0, stdout=json.dumps({"matches": []})
        ),
    )
    # One oversized unit exceeds MAX_UNIT_BYTES; many units exceed MAX_UNITS.
    _, truncated = scan_offline_truncated([ScanUnit(0, "line-0", "x" * 50_000)])
    assert truncated

    _, truncated = scan_offline_truncated(
        [ScanUnit(i, f"line-{i}", "x") for i in range(MAX_UNITS + 10)]
    )
    assert truncated


def test_response_and_uploaded_spec_are_reported_without_values(capsys):
    spec = f'''openapi: 3.0.0
info:
  title: t
  version: "1"
x-internal-secret: "{ENTROPY_SECRET}"
paths: {{}}
'''
    ctx = _context(body=json.dumps({"credential": GITHUB_TOKEN_A}), spec_text=spec)
    before = ctx.probe.count

    findings = PotentialSecretsCheck().run(ctx)

    assert ctx.probe.count == before, "the check must reuse the existing header sweep"
    assert {finding.evidence["source"] for finding in findings} == {
        "response",
        "uploaded_spec",
    }
    assert all(finding.confidence == Confidence.heuristic for finding in findings)
    serialized = json.dumps(
        [
            {
                "title": finding.title,
                "description": finding.description,
                "evidence": finding.evidence,
            }
            for finding in findings
        ]
    )
    assert GITHUB_TOKEN_A not in serialized
    assert ENTROPY_SECRET not in serialized
    assert "hashed_secret" not in serialized
    captured = capsys.readouterr()
    assert GITHUB_TOKEN_A not in captured.out + captured.err
    assert ENTROPY_SECRET not in captured.out + captured.err


def test_examples_and_expected_token_endpoints_are_suppressed():
    spec = f'''openapi: 3.0.0
info:
  title: t
  version: "1"
example: "{ENTROPY_SECRET}"
paths: {{}}
'''
    ctx = _context(
        body=json.dumps({"access_token": GITHUB_TOKEN_A}),
        path="/oauth/token",
        spec_text=spec,
    )
    assert PotentialSecretsCheck().run(ctx) == []


def test_minified_example_does_not_hide_an_unrelated_spec_secret():
    spec = json.dumps(
        {
            "openapi": "3.0.0",
            "example": ENTROPY_SECRET,
            "x-internal-secret": GITHUB_TOKEN_A,
            "paths": {},
        }
    )
    findings = PotentialSecretsCheck().run(_context(spec_text=spec))

    assert len(findings) == 1
    assert findings[0].evidence["source"] == "uploaded_spec"
    assert findings[0].evidence["detector"] == "GitHub Token"


def test_candidate_rotation_keeps_fingerprint_stable():
    from app.engine.fingerprint import fingerprint

    def digest(candidate: str) -> str:
        finding = PotentialSecretsCheck().run(
            _context(body=json.dumps({"credential": candidate}))
        )[0]
        return fingerprint(
            finding.check, finding.owasp_id, finding.title, finding.evidence
        )

    assert digest(GITHUB_TOKEN_A) == digest(GITHUB_TOKEN_B)


def test_candidate_cannot_reach_persistence_report_or_ai(db_session):
    from app.ai.cascade import build_payload
    from app.engine.run_record import append_finding
    from app.models.scan import Scan, ScanStatus
    from app.scans.report import build_report_html

    engine_finding = PotentialSecretsCheck().run(
        _context(body=json.dumps({"credential": GITHUB_TOKEN_A}))
    )[0]
    # This unit-level context has no persisted Operation row; the production
    # runner supplies its real UUID. Persistence of the value-free finding is
    # what this sentinel exercises.
    engine_finding.operation_id = None
    scan = Scan(target_base_url="http://target.test", status=ScanStatus.draft)
    db_session.add(scan)
    db_session.flush()
    append_finding(scan, engine_finding)
    db_session.commit()
    db_session.refresh(scan)

    persisted = scan.findings[0]
    outputs = [
        json.dumps(persisted.evidence),
        persisted.description,
        json.dumps(build_payload([persisted])),
        build_report_html(scan),
    ]
    assert all(GITHUB_TOKEN_A not in output for output in outputs)


def test_detector_failure_is_silent_and_non_fatal(monkeypatch, caplog):
    from app.engine.checks import potential_secrets

    secret = GITHUB_TOKEN_A

    def broken(_units):
        raise RuntimeError(secret)

    monkeypatch.setattr(potential_secrets, "scan_offline_truncated", broken)
    assert PotentialSecretsCheck().run(
        _context(body=json.dumps({"credential": secret}))
    ) == []
    assert secret not in caplog.text
