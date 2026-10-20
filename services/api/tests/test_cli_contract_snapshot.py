"""The Go CLI's contract snapshot must be the live OpenAPI document.

``cli/testdata/openapi.json`` is what the CLI's own contract tests read (every
route it calls exists; every ``RunRequest`` boolean is a flag). If it were
allowed to go stale those tests would keep passing against an API that no longer
exists, so this fails the moment the app's contract moves.

Regenerate with ``make cli-contract``.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

from app.main import app


def _snapshot_path() -> Path:
    here = Path(__file__).resolve()
    override = os.getenv("AIDETECTOR_REPO_ROOT", "").strip()
    for root in ([Path(override)] if override else []) + list(here.parents):
        candidate = root / "cli" / "testdata" / "openapi.json"
        if candidate.is_file():
            return candidate
    raise AssertionError(
        "cli/testdata/openapi.json not found. The CLI's contract tests need it; "
        "run `make cli-contract` to create it."
    )


def test_cli_contract_snapshot_matches_the_live_openapi_document():
    snapshot = json.loads(_snapshot_path().read_text())
    live = json.loads(json.dumps(app.openapi()))
    assert snapshot == live, (
        "cli/testdata/openapi.json is stale: the API contract changed. "
        "Run `make cli-contract`, then `make test-cli`, and commit both."
    )
