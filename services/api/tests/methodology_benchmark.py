"""Paired ground-truth effectiveness benchmark, independently runnable offline."""
from fastapi.testclient import TestClient

from app.engine.business_state import run_workflows
from app.engine.independent_injection import confirm_independently
from app.engine.methodology import finish_manifest
from tests import factories
from tests.methodology_targets import expanded_workflow_specs, target

#: Every route a workflow step can address. ``configured`` drops a workflow whose
#: steps are not enabled operations, so the corpus must be listed in full.
WORKFLOW_OPERATIONS = [
    ("POST", "/drafts"),
    ("GET", "/drafts/{id}"),
    ("DELETE", "/drafts/{id}"),
    ("POST", "/drafts/{id}/approve"),
    ("POST", "/drafts/{id}/settle"),
    ("POST", "/projects"),
    ("POST", "/projects/{project_id}/items"),
    ("POST", "/projects/{project_id}/items/{item_id}/publish"),
    ("GET", "/projects/{project_id}/items/{item_id}"),
    ("DELETE", "/projects/{project_id}/items/{item_id}"),
    ("DELETE", "/projects/{project_id}"),
    ("POST", "/batches"),
    ("POST", "/batches/{batch_id}/approve"),
    ("POST", "/batches/{batch_id}/settle"),
    ("GET", "/batches/{batch_id}"),
    ("DELETE", "/batches/{batch_id}"),
    ("POST", "/records"),
    ("POST", "/records/{record_id}/archive"),
    ("POST", "/records/{record_id}/restore"),
    ("GET", "/records/{record_id}"),
    ("DELETE", "/records/{record_id}"),
]


def measure() -> dict:
    cases = []
    cleanup_successes = cleanup_attempts = 0
    for vulnerable, mode in [(True, "compute"), (False, "compute"),
                              (False, "static"), (False, "reject")]:
        app, _ = target(vulnerable=vulnerable, expression_mode=mode)
        ctx = factories.scan_context([factories.operation("GET", "/preview", params=[
            {"name": "template", "in": "query", "schema": {"type": "string"}},
        ])], client=TestClient(app))
        ctx.confirm = True
        findings = confirm_independently(ctx)
        cases.append({"name": f"expression:{vulnerable}:{mode}",
                      "expected": vulnerable, "detected": bool(findings),
                      "baseline_valid": ctx.probe.test_cases[0]["baseline_valid"],
                      "outcome": ctx.probe.test_cases[0]["outcome"]})
    for vulnerable in (True, False):
        app, rows = target(vulnerable=vulnerable)
        operations = [
            factories.operation(method, path)
            for method, path in WORKFLOW_OPERATIONS
        ]
        ctx = factories.scan_context(operations, client=TestClient(app), allow_mutation=True,
                                     credentials=[factories.credential("owner", "user"),
                                                  factories.credential("peer", "user")],
                                     spec=expanded_workflow_specs())
        findings = run_workflows(ctx)
        detected = {f.evidence["param"] for f in findings}
        for case in ctx.probe.test_cases:
            cases.append({"name": f"{case['label']}:{vulnerable}", "expected": vulnerable,
                          "detected": case["label"] in detected,
                          "baseline_valid": case["baseline_valid"], "outcome": case["outcome"]})
        metrics = finish_manifest(ctx.probe)["metrics"]
        cleanup_attempts += metrics["cleanup_attempts"]
        cleanup_successes += metrics["cleanup_successes"]
        assert rows == {}, "benchmark left target fixtures behind"
    tp = sum(c["expected"] and c["detected"] for c in cases)
    fp = sum(not c["expected"] and c["detected"] for c in cases)
    fn = sum(c["expected"] and not c["detected"] for c in cases)
    return {"version": 1, "scope": "held-out synthetic detector cases; not production estimates",
            "true_positives": tp, "false_positives": fp, "false_negatives": fn,
            "precision": tp / (tp + fp) if tp + fp else None,
            "recall": tp / (tp + fn) if tp + fn else None,
            "valid_request_coverage": sum(bool(c["baseline_valid"]) for c in cases) / len(cases),
            "inconclusive_rate": sum(c["outcome"] not in {"passed", "finding"}
                                     for c in cases) / len(cases),
            "cleanup_attempts": cleanup_attempts, "cleanup_successes": cleanup_successes,
            "cleanup_success_rate": cleanup_successes / cleanup_attempts,
            "cases": cases}


if __name__ == "__main__":
    import json

    print(json.dumps(measure(), indent=2))
