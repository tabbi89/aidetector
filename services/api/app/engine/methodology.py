"""Versioned, value-free run manifests and evidence-sensitive AI cache keys."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

VERSION = "methodology-1"


def digest(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, default=str).encode()).hexdigest()


def source_digest(directory: Path, patterns: tuple[str, ...]) -> str:
    """Hash installed implementation/corpus bytes; never run git or tool binaries."""
    paths = sorted({p for pattern in patterns for p in directory.glob(pattern) if p.is_file()})
    return digest(
        [(str(p.relative_to(directory)), hashlib.sha256(p.read_bytes()).hexdigest()) for p in paths]
    )


def build_manifest(ctx, options: dict[str, Any]) -> dict[str, Any]:
    root = Path(__file__).parent
    return {
        "version": VERSION,
        "seed": ctx.seed,
        "engine_digest": source_digest(root, ("*.py", "checks/*.py")),
        "payload_digest": source_digest(root, ("payload*.py", "signatures.py", "data/payloads/*")),
        "spec_digest": digest(ctx.spec),
        "options_digest": digest(options),
        "operations": [{"method": op.method, "path": op.path} for op in ctx.operations],
        "checks": sorted(ctx.check_scope),
        "replay_limits": [
            "target state and credentials may change",
            "concurrent scheduling",
            "external tools and AI output are not deterministic",
            "callback and authentication nonces remain fresh",
        ],
    }


def finish_manifest(probe) -> dict[str, Any]:
    cases = list(probe.test_cases)
    baselines = [r for r in cases if r.get("baseline_valid") is not None]
    cleanups = probe.cleanup_results
    return {
        **probe.manifest,
        "cases": cases,
        "metrics": {
            "scheduled_cases": len(cases),
            "completed_cases": sum(r["outcome"] in {"passed", "finding"} for r in cases),
            "valid_baselines": sum(bool(r["baseline_valid"]) for r in baselines),
            "attempted_baselines": len(baselines),
            "valid_request_coverage": (
                sum(bool(r["baseline_valid"]) for r in baselines) / len(baselines)
                if baselines
                else None
            ),
            "cleanup_attempts": len(cleanups),
            "cleanup_successes": sum(cleanups),
            "cleanup_success_rate": sum(cleanups) / len(cleanups) if cleanups else None,
            "scope": "instrumented cases only; live precision/recall requires ground truth",
        },
    }


def adjudication_key(finding, *, premium: bool = False) -> str:
    """Human fingerprint stays stable; AI reuse requires identical review input."""
    from app.ai.cascade import build_payload
    from app.core.config import settings

    payload = build_payload([finding])[0]
    payload.pop("id", None)
    # The remediation is model output from a prior review (and may be an
    # evidence-specific fix), so feeding it into the identity would make a
    # successful cache hit impossible on the next run.
    payload.pop("remediation", None)
    # Per-request canaries prove the observation but are intentionally not part
    # of the review identity. The surrounding status, location, controls and
    # response shape remain included, so a changed observation still invalidates
    # reuse.
    evidence = payload.get("evidence")
    if isinstance(evidence, dict):
        evidence = dict(evidence)
        evidence.pop("canary", None)
        # Rendered paths and payload text are generated inputs. The stable
        # route/parameter identity and the response observation below are the
        # review signal; retaining these would invalidate cache entries when a
        # different payload family is selected on a later run.
        evidence.pop("path", None)
        evidence.pop("payload", None)
        # Trace sequence numbers are an archival location for the observation,
        # not part of the observation itself. They are re-numbered on every
        # run, so including them would defeat reuse for an unchanged finding.
        evidence.pop("trace", None)
        # Payloads and rendered paths can carry the same per-request marker;
        # scrub it wherever it appears while retaining all other evidence.
        def scrub(value):
            if isinstance(value, str):
                return re.sub(r"aidx[0-9a-f]{8,32}", "aidx<canary>", value)
            if isinstance(value, dict):
                return {key: scrub(item) for key, item in value.items()}
            if isinstance(value, list):
                return [scrub(item) for item in value]
            return value

        evidence = scrub(evidence)
        if finding.check in {"reflected_injection", "signature_injection"}:
            # The sample necessarily contains the generated probe payload. The
            # stable review facts are the status, reflection/error flags and
            # route metadata; payload text is already excluded above.
            evidence.pop("response_sample", None)
        payload["evidence"] = evidence
    # Use all evidence, including controls/statuses; conservative invalidation is
    # preferable to carrying a stale dismissal across a changed observation.
    root = Path(__file__).resolve().parents[2]
    return digest(
        {
            "payload": payload,
            "policy": VERSION,
            "premium": premium,
            "planner": settings.effective_planner_model(),
            "executor": settings.executor_model,
            "runtime": source_digest(root / "ai_runtime", ("*.py", "*.md")),
            "provider": settings.deepseek_base_url,
        }
    )
