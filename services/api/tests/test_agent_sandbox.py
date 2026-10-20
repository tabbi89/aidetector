"""Per-tool sandbox: a curated allowlist, graded conservatively, graceful-degrade."""
from __future__ import annotations

import json

import pytest

from app.agent.sandbox import (
    SANDBOX_CHECK_KEYS,
    SANDBOX_TOOLS,
    Sandbox,
    SandboxProc,
    SandboxUnavailable,
    available_tools,
)
from app.domain.enums import Confidence, Severity
from app.engine.remediation import CATALOGUE

TARGET = "http://target:9000"


def _runner(procs: dict[str, SandboxProc]):
    """A fake process runner keyed by the tool image named in argv."""

    def run(argv: list[str], stdin, timeout):
        image = next((a for a in argv if "/" in a and ":" in a.split("/")[-1]), "")
        for key, proc in procs.items():
            if key in image:
                return proc
        return SandboxProc(returncode=0, stdout="", stderr="")

    return run


def test_every_sandbox_key_has_a_catalogue_entry() -> None:
    # The server ingest accepts these; each must have remediation.
    for key in SANDBOX_CHECK_KEYS:
        assert key in CATALOGUE, f"sandbox check key {key} has no remediation entry"


def test_unknown_tool_is_refused() -> None:
    sb = Sandbox(runner=_runner({}))
    with pytest.raises(SandboxUnavailable):
        sb.run("metasploit", TARGET)
    assert "metasploit" not in available_tools()


def test_disabled_sandbox_raises_rather_than_runs() -> None:
    sb = Sandbox(runner=_runner({}), enabled=False)
    with pytest.raises(SandboxUnavailable):
        sb.run("nuclei", TARGET)


def test_target_must_be_absolute_url() -> None:
    sb = Sandbox(runner=_runner({}))
    with pytest.raises(SandboxUnavailable):
        sb.run("nuclei", "target:9000")


def test_argv_is_hardened_and_names_only_the_allowlisted_image() -> None:
    captured: list[list[str]] = []

    def run(argv, stdin, timeout):
        captured.append(argv)
        return SandboxProc(returncode=0, stdout="", stderr="")

    Sandbox(runner=run).run("nuclei", TARGET)
    argv = captured[0]
    assert argv[:2] == ["docker", "run"]
    assert "--read-only" in argv and "--cap-drop" in argv and "no-new-privileges" in argv
    assert "--user" in argv and "65534:65534" in argv
    assert SANDBOX_TOOLS["nuclei"].image in argv
    # No shell, no injected flags beyond the fixed arg shape + the target.
    assert TARGET in argv


def test_network_override_replaces_host() -> None:
    captured: list[list[str]] = []

    def run(argv, stdin, timeout):
        captured.append(argv)
        return SandboxProc(returncode=0, stdout="", stderr="")

    Sandbox(runner=run, network="aidetector_default").run("nuclei", TARGET)
    argv = captured[0]
    i = argv.index("--network")
    assert argv[i + 1] == "aidetector_default"
    assert "host" not in argv[i : i + 2]


def test_nuclei_output_parses_and_grades_heuristic() -> None:
    line = json.dumps(
        {
            "template-id": "exposed-env",
            "info": {
                "name": "Exposed .env",
                "severity": "high",
                "reference": ["https://x"],
                "classification": {"cwe-id": "CWE-200"},
            },
            "matched-at": "http://target:9000/.env",
        }
    )
    sb = Sandbox(runner=_runner({"nuclei": SandboxProc(0, line + "\nnot-json\n")}))
    res = sb.run("nuclei", TARGET)
    assert len(res.findings) == 1
    f = res.findings[0]
    assert f.check == "kali_nuclei"
    assert f.severity == Severity.high
    assert f.confidence == Confidence.heuristic  # a template match is a lead
    assert f.evidence["template"] == "exposed-env"
    assert f.evidence["cwe"] == "CWE-200"


def test_sqlmap_confirmation_is_verified() -> None:
    out = "sqlmap identified the following injection point\nParameter: id is vulnerable"
    sb = Sandbox(runner=_runner({"sqlmap": SandboxProc(0, out)}))
    res = sb.run("sqlmap", TARGET)
    assert len(res.findings) == 1
    assert res.findings[0].confidence == Confidence.verified
    # No confirmation phrase -> no finding.
    sb2 = Sandbox(runner=_runner({"sqlmap": SandboxProc(0, "all tested parameters appear safe")}))
    assert sb2.run("sqlmap", TARGET).findings == []


def test_ffuf_results_become_shadow_endpoints() -> None:
    doc = json.dumps({"results": [{"url": "http://target:9000/admin", "status": 200}]})
    sb = Sandbox(runner=_runner({"ffuf": SandboxProc(0, doc)}))
    res = sb.run("ffuf", TARGET)
    assert res.findings and res.findings[0].check == "kali_discovery"
    assert res.findings[0].severity == Severity.low


def test_runner_exception_degrades_to_unavailable() -> None:
    def boom(argv, stdin, timeout):
        raise RuntimeError("socket gone")

    sb = Sandbox(runner=boom)
    with pytest.raises(SandboxUnavailable):
        sb.run("nuclei", TARGET)
