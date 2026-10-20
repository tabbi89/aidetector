"""SARIF 2.1.0 export for a scan's findings.

SARIF is the interchange format GitHub code-scanning, Azure DevOps, and most CI
security dashboards consume, so emitting it makes aidetector's findings gate a
pipeline instead of living only in the UI. One SARIF ``run`` per scan: distinct
checks become ``rules`` (carrying CWE + OWASP metadata and the remediation
help GitHub renders under an alert), findings become ``results`` anchored to the
operation path. Each rule also carries ``security-severity`` and ``tags``, the
properties code scanning needs to file its alerts as ranked security findings.

Rule metadata comes from the single per-check catalogue in
``app/engine/remediation.py``, so a SARIF rule and the finding it describes can
never disagree about what the weakness is or how to fix it.
"""
from __future__ import annotations

from typing import Any

from app.domain.enums import Confidence, Severity, Verdict
from app.engine.remediation import cwe, knowledge, remediate
from app.models.finding import Finding
from app.models.scan import Scan

_SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"

# Severity → SARIF result level.
_LEVEL = {
    Severity.critical: "error",
    Severity.high: "error",
    Severity.medium: "warning",
    Severity.low: "note",
    Severity.info: "note",
}

# One step down the ladder, for demoting an unconfirmed lead.
_DEMOTED = {"error": "warning", "warning": "note", "note": "note"}

# Severity → the numeric score GitHub's code-scanning dashboard ranks alerts by.
# The dashboard sorts on ``security-severity`` and ignores the SARIF ``level``,
# so a lead has to be *scored* a step down too — otherwise a heuristic hunch
# ranks above proven evidence on the screen people triage from.
_SECURITY_SEVERITY = {
    Severity.critical: 9.5,
    Severity.high: 8.0,
    Severity.medium: 5.5,
    Severity.low: 2.0,
}

# One step down the severity ladder, for demoting an unconfirmed lead.
_DEMOTED_SEVERITY = {
    Severity.critical: Severity.high,
    Severity.high: Severity.medium,
    Severity.medium: Severity.low,
    Severity.low: Severity.info,
    Severity.info: Severity.info,
}


def effective_severity(severity: Severity, confidence: Confidence | None) -> Severity:
    """The severity a finding is credited with, given its evidence tier."""
    if confidence is not Confidence.verified:
        return _DEMOTED_SEVERITY.get(severity, Severity.info)
    return severity


def security_severity(
    severity: Severity, confidence: Confidence | None
) -> float | None:
    """GitHub's security score for one finding, or ``None`` when it is only info.

    ``info`` has no entry in the map: a dashboard reads ``0.0`` oddly and an
    informational note is not a security finding, so the rule omits the property
    rather than publishing a zero.
    """
    return _SECURITY_SEVERITY.get(effective_severity(severity, confidence))


def _scores_by_check(findings: list[Finding]) -> dict[str, float]:
    """Highest security score per check — a rule is as bad as its worst finding."""
    scores: dict[str, float] = {}
    for f in findings:
        score = security_severity(f.severity, f.confidence)
        if score is not None and score > scores.get(f.check, 0.0):
            scores[f.check] = score
    return scores


def result_level(severity: Severity, confidence: Confidence | None) -> str:
    """SARIF level from severity *and* evidence tier.

    A dashboard that treats a reflection lead the way it treats a proven
    cross-identity write teaches people to ignore the dashboard. Severity sets
    the level; a heuristic finding is demoted one step, so only evidence that
    demonstrates the weakness can raise an ``error``.
    """
    level = _LEVEL.get(severity, "warning")
    if confidence is not Confidence.verified:
        return _DEMOTED[level]
    return level

_DEFAULT_HELP_URI = "https://owasp.org/API-Security/editions/2023/en/0x11-t10/"


def _rules(checks: list[str], scores: dict[str, float]) -> list[dict[str, Any]]:
    """One rule per check, carrying its CWE, summary and remediation.

    ``help.markdown`` is what a code-scanning UI shows under an alert, so the
    generic (evidence-free) remediation and its references live there; the
    evidence-shaped text goes on each individual result. ``scores`` maps a check
    to its highest security score in this scan; a check missing from it is only
    informational and gets no ``security-severity``.
    """
    rules: list[dict[str, Any]] = []
    for key in checks:
        entry = knowledge(key)
        props: dict[str, Any] = {}
        tags = ["security"]
        if entry and entry.cwe:
            props["cwe"] = entry.cwe
            tags.append(f"external/cwe/{entry.cwe.lower()}")
        props["tags"] = tags
        score = scores.get(key)
        if score is not None:
            props["security-severity"] = f"{score:.1f}"
        rule: dict[str, Any] = {
            "id": key,
            "name": key,
            "shortDescription": {"text": entry.summary if entry else key},
            "helpUri": (
                entry.references[0] if entry and entry.references else _DEFAULT_HELP_URI
            ),
            "properties": props,
        }
        if entry:
            # Rule help is evidence-free, so fill the template's placeholders
            # with neutral prose — the raw template would show literal {method}/
            # {path} in a code-scanning UI. The per-result text (below) is
            # shaped by each finding's own evidence.
            generic = remediate(key)[0] or entry.remediation
            links = "".join(f"\n- {url}" for url in entry.references)
            rule["help"] = {
                "text": generic,
                "markdown": (
                    f"**{entry.summary}**\n\n{generic}"
                    + (f"\n\n**References**{links}" if links else "")
                ),
            }
        rules.append(rule)
    return rules


def to_sarif(scan: Scan) -> dict[str, Any]:
    """Build a SARIF 2.1.0 document for the scan's current findings."""
    findings = list(scan.findings)
    checks = sorted({f.check for f in findings})
    scores = _scores_by_check(findings)

    results: list[dict[str, Any]] = []
    for f in findings:
        path = f.evidence.get("path") if isinstance(f.evidence, dict) else None
        # A finding recorded before the catalogue existed has no stored text;
        # derive it now rather than exporting an alert with no fix.
        fix = f.remediation or remediate(f.check, f.evidence)[0]
        results.append(
            {
                "ruleId": f.check,
                "level": result_level(f.severity, f.confidence),
                "message": {
                    "text": f.title
                    + " — "
                    + (f.description or "")
                    + (f"\n\nFix: {fix}" if fix else "")
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": str(path or f.check),
                                "uriBaseId": "TARGET",
                            }
                        }
                    }
                ],
                "properties": {
                    "severity": f.severity.value,
                    "confidence": (f.confidence or Confidence.heuristic).value,
                    "owasp_id": f.owasp_id,
                    "verdict": (f.verdict or Verdict.unreviewed).value,
                    "cwe": cwe(f.check),
                    "remediation": fix,
                },
            }
        )

    return {
        "$schema": _SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "aidetector",
                        "version": "0.1.0",
                        "informationUri": "https://owasp.org/API-Security/",
                        "rules": _rules(checks, scores),
                    }
                },
                "originalUriBaseIds": {
                    "TARGET": {"uri": scan.target_base_url.rstrip("/") + "/"}
                },
                "results": results,
            }
        ],
    }
