"""The scan's operation set: replaced by a spec upload, narrowed by selection."""
from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sqlalchemy.orm import Session

from app.models.event import ScanEvent
from app.models.scan import Operation, Scan
from app.specs.importers import load_source
from app.specs.parser import (
    HTTP_METHODS,
    SpecError,
    load_spec,
    parse_operations,
    recompose_route,
    routing_warnings,
    spec_warnings,
)

log = logging.getLogger("aidetector.service")


#: Path-item keys that are OpenAPI metadata rather than operations.
_PATH_ITEM_KEYS = frozenset({"$ref", "summary", "description", "servers", "parameters"})


def _skipped_items(data: dict[str, Any]) -> list[dict[str, str]]:
    """Path items and method keys ``parse_operations`` walked past, with a reason.

    The parser is lenient on purpose — anything that is not an HTTP operation is
    dropped so the rest of the spec still loads. Naming what was dropped is the
    difference between thin coverage and a user knowing why.
    """
    paths = data.get("paths")
    if not isinstance(paths, dict):
        return []
    skipped: list[dict[str, str]] = []
    for path, item in paths.items():
        if not isinstance(path, str) or not isinstance(item, dict):
            skipped.append({"path": str(path), "reason": "path item is not an object"})
            continue
        for method, operation in item.items():
            if str(method).lower() in HTTP_METHODS:
                if not isinstance(operation, dict):
                    skipped.append(
                        {
                            "path": path,
                            "method": str(method).upper(),
                            "reason": "operation is not an object",
                        }
                    )
            elif method not in _PATH_ITEM_KEYS:
                skipped.append(
                    {
                        "path": path,
                        "method": str(method).upper(),
                        "reason": "not an HTTP method",
                    }
                )
    return skipped


@dataclass(frozen=True)
class SpecIngest:
    """What a spec upload produced: the replaced operations and a parse report.

    The report is the user-facing half: an operation count, whatever the parser
    dropped, and the validation/routing warnings that also reach the event log.
    """

    operations: list[Operation]
    report: dict[str, Any]


def ingest_spec(db: Session, scan: Scan, content: str) -> SpecIngest:
    """Parse a spec and replace the scan's operations. Raises SpecError.

    Mutating through the ``scan.operations`` relationship (rather than deleting
    by query and inserting by scan_id) keeps the in-session Scan instance's
    collection consistent, so a re-fetch in the same session reflects the new
    operations instead of a stale cached collection.
    """
    data, canonical = load_source(content)
    parsed = parse_operations(data, target_base_url=scan.target_base_url)
    warnings = _record_warnings(scan, data)

    # For HAR/Postman `canonical` is the synthesised OpenAPI JSON, so the stored
    # spec_text is always OpenAPI whatever was uploaded; a real spec is stored
    # verbatim.
    scan.spec_text = canonical
    scan.spec_origin = "openapi" if canonical == content else "derived"
    scan.spec_uploaded_at = datetime.now(UTC)
    # An endpoint the user unchecked stays unchecked across a replacement — a
    # re-upload of the same spec must not silently put it back in scope.
    disabled = {(op.method, op.path) for op in scan.operations if not op.enabled}
    # Re-uploading a spec is idempotent: clear() delete-orphans the old rows.
    scan.operations.clear()
    db.flush()
    scan.operations.extend(
        Operation(
            method=p.method,
            path=p.path,
            params=p.params,
            auth_scope=p.auth_scope,
            enabled=(p.method, p.path) not in disabled,
        )
        for p in parsed
    )
    db.commit()
    report = {
        "operations": len(parsed),
        "skipped": _skipped_items(data),
        "warnings": warnings,
    }
    return SpecIngest(operations=list(scan.operations), report=report)


def retarget_operations(
    scan: Scan, previous_target: str, *, notes: list[tuple[str, str]] | None = None
) -> int:
    """Recompose each operation's route for the scan's current target; the count moved.

    A route is composed from the target as well as the spec: a target whose path
    already ends with the spec's server prefix stores ``/monitors``, one without
    it stores ``/api/v1/monitors``. So a target change re-derives every route
    from ``spec_text``, as an upload under the new target would have. Rows are
    updated in place, keeping their ids, their enabled choice and findings'
    links. ``previous_target`` locates each stored route; one composed under an
    earlier target still is found too, so re-saving an unchanged target repairs
    routes a past target change left stale. An operation the spec cannot place
    keeps its route, and an event says so.

    Every run calls this at its start too, with the target unchanged: a route
    stored under an older parser or an older target otherwise sends the whole
    run to a path that does not exist (``/api/v1/api/v1/monitors``) and every
    check reads a 404. ``notes`` collects the ``(stage, message)`` events instead
    of appending them, for a caller about to reset the scan's events.
    """

    def announce(message: str) -> None:
        if notes is not None:
            notes.append(("operations_retargeted", message))
        else:
            scan.events.append(ScanEvent(stage="operations_retargeted", pct=0, message=message))

    if not scan.spec_text:
        return 0
    try:
        # spec_text is always OpenAPI (a capture is stored converted). Routes need
        # only path keys, methods and servers, so a settings change never fetches
        # a remote $ref.
        data = load_spec(scan.spec_text, remote_ref_allowlist=[])
    except SpecError:
        return 0
    moved = 0
    unplaced: list[str] = []
    for op in scan.operations:
        route = recompose_route(
            data,
            op.method,
            op.path,
            old_target=previous_target,
            new_target=scan.target_base_url,
        )
        if route is None:
            unplaced.append(f"{op.method} {op.path}")
        elif route != op.path:
            op.path = route
            moved += 1
    _record_warnings(scan, data)
    if moved:
        # A finding's identity includes its route, so say why the next run's
        # findings on these endpoints will not match their earlier triage.
        announce(
            f"{moved} endpoint route(s) re-derived for target {scan.target_base_url}; "
            "findings on them get new identities from the next run on"
        )
    if unplaced:
        announce(
            f"{len(unplaced)} endpoint(s) the spec could not place kept their route: "
            + ", ".join(unplaced[:5]) + (" …" if len(unplaced) > 5 else "")
        )
    return moved


def _record_warnings(scan: Scan, data: dict[str, Any]) -> list[str]:
    """Replace the scan's spec-warning events with this spec's, for its current target."""
    warnings = [*spec_warnings(data), *routing_warnings(data, scan.target_base_url)]
    for warning in warnings:
        log.warning("spec validation warning for scan %s: %s", scan.id, warning)
    scan.events[:] = [event for event in scan.events if event.stage != "spec_warning"]
    scan.events.extend(
        ScanEvent(stage="spec_warning", pct=0, message=warning) for warning in warnings
    )
    return warnings


def set_operation_selection(
    db: Session, scan: Scan, selections: list[tuple[uuid.UUID, bool]]
) -> list[Operation]:
    """Enable/disable operations by id, scoped to this scan.

    Ids not belonging to the scan are ignored. Returns the scan's operations.
    """
    by_id = {op.id: op for op in scan.operations}
    for op_id, enabled in selections:
        op = by_id.get(op_id)
        if op is not None:
            op.enabled = enabled
    db.commit()
    return list(scan.operations)
