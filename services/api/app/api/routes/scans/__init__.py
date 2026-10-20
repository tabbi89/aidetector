"""Scan API — create a scan, ingest a spec, attach credentials, inspect.

Every handler that addresses one scan takes it as a dependency, not an id:

- :data:`ScanDep` loads it, scoped to the caller's tenant, 404 if absent.
- :data:`EditableScanDep` does that *and* refuses while a worker is writing to
  the scan.

That is the difference between a convention and a guarantee. The active-scan
check used to be a line each handler remembered to call, and its own comment
said forgetting it "would corrupt the running engine pass" — so whether a new
endpoint was safe depended on whether its author had read a neighbouring one.
Now a mutating handler says so in its signature and a read-only handler is
visibly read-only; ``tests/test_route_guards.py`` fails on one that is neither.

Mutating handlers also return the in-session object rather than re-fetching it.
``service.get_scan`` eager-loads five collections, so the old load-mutate-reload
shape built that graph twice per write — the second time to read back rows the
first had already loaded.
"""
from __future__ import annotations

from fastapi import APIRouter

from app.workers.tasks import run_scan_task

from . import collection, configuration, findings, reports, runs, schedule
from ._shared import (
    _ACTIVE,
    EditableScanDep,
    LightScanDep,
    ScanDep,
    TenantId,
    _require_premium,
    _require_run_authorization,
    _require_runnable,
    _require_target_allowed,
    load_editable_scan,
    load_scan,
    load_scan_light,
)

__all__ = [
    "EditableScanDep",
    "LightScanDep",
    "ScanDep",
    "TenantId",
    "_ACTIVE",
    "_require_premium",
    "_require_run_authorization",
    "_require_runnable",
    "_require_target_allowed",
    "load_editable_scan",
    "load_scan",
    "load_scan_light",
    "router",
    "run_scan_task",
]

router = APIRouter()
router.include_router(collection.router)
router.include_router(configuration.router)
router.include_router(runs.router)
router.include_router(findings.router)
router.include_router(reports.router)
router.include_router(schedule.router)
