"""Pinned metadata context; no source execution, arbitrary files or SQL."""

from __future__ import annotations

import hashlib
import uuid

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.db import SessionLocal
from app.db_schema.snapshots import latest_snapshot
from app.models.monitoring import EvidenceSource, InfrastructureMonitor
from app.models.scan import Operation, Scan
from app.monitoring import remote, sources
from app.monitoring.contracts import ORIGIN_SOURCE_KEY, RouteBinding, SourceUnavailable
from app.scans.workspace import is_premium


def contract_context(db: Session, scan: Scan) -> dict:
    """The pinned route vocabulary a monitor maps traffic with, from a scan's operations."""
    operations = list(db.scalars(select(Operation).where(Operation.scan_id == scan.id).limit(201)))
    if len(operations) > 200:
        raise HTTPException(422, "context route limit exceeded")
    try:
        routes = [
            RouteBinding(method=op.method.upper(), path=op.path).model_dump() for op in operations
        ]
    except ValueError:
        raise HTTPException(422, "unsupported route template") from None
    return {
        "routes": routes,
        "openapi_revision": hashlib.sha256((scan.spec_text or "").encode()).hexdigest(),
        "openapi_explicit": scan.spec_origin == "openapi",
        "advisories": [
            {
                "type": "declared_public_operation",
                "method": op.method.upper(),
                "path": op.path,
                "confidence": "heuristic",
            }
            for op in operations
            if not op.auth_scope
        ],
    }


def attach_context(
    db: Session,
    monitor: InfrastructureMonitor,
    scan_id: uuid.UUID,
    repository_source_id: uuid.UUID | None,
    include_database: bool,
) -> dict:
    tenant_id, target = monitor.tenant_id, monitor.target_binding
    scan = db.scalar(select(Scan).where(Scan.id == scan_id, Scan.tenant_id == tenant_id))
    if scan is None:
        raise HTTPException(404, "scan not found")
    if scan.target_base_url.rstrip("/") != target.rstrip("/"):
        raise HTTPException(409, "scan belongs to another target")
    context = contract_context(db, scan)
    repo = db.get(EvidenceSource, repository_source_id) if repository_source_id else None
    if repository_source_id and (
        repo is None
        or repo.tenant_id != tenant_id
        or repo.target_binding != target
        or repo.connector != "github"
        or repo.status == "revoked"
    ):
        raise HTTPException(404, "repository source not found")
    repo_revision = repo.revision if repo else None
    # Schema context is a snapshot a local run uploaded; the server never
    # connects to the target database. Bind to that run so a newer snapshot
    # (or a forgotten one) during the remote fetch reads as a changed binding.
    if include_database and not is_premium(db, tenant_id):
        raise HTTPException(402, "premium tier required")
    snapshot = latest_snapshot(db, scan_id) if include_database else None
    if include_database and snapshot is None:
        raise HTTPException(
            409, "no schema snapshot — run `aidetector --local` with a schema: block"
        )
    snapshot_run = snapshot.run_id if snapshot else None
    monitor_id = monitor.id
    db.commit()  # No DB locks span a remote request.

    def guard() -> None:
        with SessionLocal() as fresh:
            owner = fresh.get(InfrastructureMonitor, monitor_id)
            linked = fresh.get(Scan, scan_id)
            if (
                owner is None
                or owner.status != "active"
                or linked is None
                or linked.tenant_id != tenant_id
            ):
                raise SourceUnavailable("binding_changed")
            if repository_source_id:
                live = fresh.get(EvidenceSource, repository_source_id)
                if live is None or live.status == "revoked" or live.revision != repo_revision:
                    raise SourceUnavailable("binding_changed")
            if include_database:
                current = latest_snapshot(fresh, scan_id)
                if current is None or current.run_id != snapshot_run:
                    raise SourceUnavailable("binding_changed")

    try:
        guard()
        if repo:
            repo_config = sources.bound_config(repo)
            context["repository"] = (
                remote.github_context(repo_config, sources.read_credentials(repo), guard)
                if repo_config.commit and repo_config.paths
                # Branch-mode sources are read on demand through the GitHub MCP server.
                else {"repository": repo_config.repository, "ref": repo_config.ref}
            )
            context["repository_source_id"] = str(repo.id)
            context["repository_revision"] = repo.revision
        if snapshot is not None:
            context["database"] = snapshot.context
            context["database_revision"] = str(snapshot_run)
        guard()
    except SourceUnavailable as exc:
        if repo:
            sources.audit(db, repo, "context", "source_unavailable")
            db.commit()
        raise HTTPException(503, exc.code) from None
    if repo:
        locked = sources.load_source(db, repo.id, tenant_id)
        if locked.status == "revoked" or locked.revision != repo_revision:
            raise HTTPException(409, "repository source changed")
    owner = db.scalar(
        select(InfrastructureMonitor)
        .where(InfrastructureMonitor.id == monitor_id)
        .with_for_update()
    )
    if owner is None or owner.status != "active":
        raise HTTPException(409, "monitor changed")
    # Attaching a contract rebuilds context from the scan, so carry the origin source
    # across; replacing the dict wholesale would silently unlink the load balancer.
    if owner.context.get(ORIGIN_SOURCE_KEY):
        context[ORIGIN_SOURCE_KEY] = owner.context[ORIGIN_SOURCE_KEY]
    owner.context, owner.scan_id = context, scan_id
    if repo:
        sources.audit(db, repo, "context", "complete")
    db.commit()
    return context


def readable_context(db: Session, monitor: InfrastructureMonitor) -> dict:
    context = monitor.context
    if context.get("repository_source_id"):
        source = db.get(EvidenceSource, context["repository_source_id"])
        if (
            source is None
            or source.status == "revoked"
            or source.revision != context.get("repository_revision")
        ):
            raise HTTPException(409, "context binding changed; attach fresh context")
    if context.get("database_revision"):
        live = latest_snapshot(db, monitor.scan_id) if monitor.scan_id else None
        if live is None or str(live.run_id) != context["database_revision"]:
            raise HTTPException(409, "database context binding changed")
    return context
