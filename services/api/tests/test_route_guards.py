"""Every scan route declares how it treats the scan, in its signature.

Two dependencies express the whole policy: ``load_scan`` fetches the scan scoped
to the caller's tenant, and ``load_editable_scan`` adds the refusal to touch a
scan a worker is still writing to. A handler that takes ``EditableScanDep``
cannot forget the guard, and one that takes ``ScanDep`` is visibly read-only.

Before that, the guard was a line each handler remembered to call — and its own
comment said forgetting it "would corrupt the running engine pass". Nothing
caught a new endpoint that skipped it. This does.
"""
from __future__ import annotations

import pytest
from fastapi.routing import APIRoute

from app.api.routes.scans import load_editable_scan, load_scan, load_scan_light, router

#: Mutating routes that deliberately do NOT take the editable guard, and why.
#: Each is a write whose whole point is the state the guard would refuse.
GUARD_EXEMPT = {
    # Cancelling requires the scan to be running.
    ("POST", "/scans/{scan_id}/cancel"),
    # Queueing answers the authorization gate first, then raises its own 409
    # with a message about the run rather than about editing.
    ("POST", "/scans/{scan_id}/run"),
    # Deleting says "cancel the scan before deleting it" — same rule, wording
    # matched to the irreversible action.
    ("DELETE", "/scans/{scan_id}"),
    # Triage records a human's verdict on a finding; it is not a scan edit and
    # is useful while a re-run is queued.
    ("PATCH", "/scans/{scan_id}/findings/{finding_id}"),
    # A schedule configures future runs, not the spec the current run is
    # walking. Enabling one answers the run's authorization gate instead.
    ("PUT", "/scans/{scan_id}/schedule"),
    # Which settings a project file owns is metadata the web reads to lock its
    # controls; the engine never reads it, so a running pass cannot be corrupted.
    ("PUT", "/scans/{scan_id}/managed-config"),
    ("DELETE", "/scans/{scan_id}/managed-config"),
}

#: Routes that do not address a single existing scan. ``/scans/example`` creates
#: a new scan (dev only), exactly like ``POST /scans``.
_COLLECTION_ROUTES = {("POST", "/scans"), ("GET", "/scans"), ("POST", "/scans/example")}

_WRITE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


def _routes() -> list[tuple[str, str, APIRoute]]:
    out: list[tuple[str, str, APIRoute]] = []
    for route in router.routes:
        if not isinstance(route, APIRoute):
            continue
        for method in sorted(route.methods or set()):
            if method in ("HEAD", "OPTIONS"):
                continue
            out.append((method, route.path, route))
    return out


def _dependency_functions(route: APIRoute) -> set[object]:
    """Every callable in the route's dependency tree, however deeply nested."""
    seen: set[object] = set()
    stack = list(route.dependant.dependencies)
    while stack:
        dep = stack.pop()
        if dep.call is not None:
            seen.add(dep.call)
        stack.extend(dep.dependencies)
    return seen


def test_every_scan_scoped_route_loads_the_scan_as_a_dependency() -> None:
    """No handler should be taking a bare ``scan_id`` and fetching it by hand."""
    missing = [
        f"{m} {p}"
        for m, p, r in _routes()
        if (m, p) not in _COLLECTION_ROUTES
        and load_scan not in _dependency_functions(r)
        and load_scan_light not in _dependency_functions(r)
    ]
    assert not missing, (
        f"routes not using ScanDep/EditableScanDep/LightScanDep: {missing}. Take the "
        "scan as a dependency so tenant scoping and the 404 are not per-handler code."
    )


@pytest.mark.parametrize(
    ("method", "path"),
    [(m, p) for m, p, _ in _routes() if m in _WRITE_METHODS],
    ids=lambda v: str(v),
)
def test_write_routes_take_the_editable_guard_or_are_listed_as_exempt(
    method: str, path: str
) -> None:
    """A mutating route either carries the guard or documents why it does not.

    The exemption list is the point: skipping the guard becomes a decision
    someone wrote down, not an omission nobody noticed.
    """
    if (method, path) in _COLLECTION_ROUTES or (method, path) in GUARD_EXEMPT:
        return
    route = next(r for m, p, r in _routes() if (m, p) == (method, path))
    assert load_editable_scan in _dependency_functions(route), (
        f"{method} {path} modifies a scan but does not take EditableScanDep. "
        "Editing a scan mid-run corrupts the running engine pass — take the "
        "guard, or add it to GUARD_EXEMPT with the reason."
    )


def test_exemptions_all_name_a_real_route() -> None:
    """A stale exemption silently excuses a route that no longer exists."""
    live = {(m, p) for m, p, _ in _routes()}
    stale = sorted(GUARD_EXEMPT - live)
    assert not stale, f"GUARD_EXEMPT names routes that are gone: {stale}"


def test_the_editable_guard_refuses_a_running_scan(client, scan_with_spec, db_session):
    """The behaviour behind the wiring, asserted once end to end."""
    from app.models.scan import Scan, ScanStatus

    sid = scan_with_spec()
    scan = db_session.get(Scan, sid)
    scan.status = ScanStatus.running
    db_session.commit()

    # A guarded route refuses...
    r = client.post(f"/scans/{sid}/spec", json={"content": "{}"})
    assert r.status_code == 409
    assert "running" in r.json()["detail"]

    # ...while a read-only one still answers.
    assert client.get(f"/scans/{sid}/findings").status_code == 200
