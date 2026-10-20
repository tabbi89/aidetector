from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api import schemas
from app.core.db import get_db
from app.domain.enums import (
    Confidence,
    Severity,
    Verdict,
)
from app.engine import run_record
from app.models.finding import Finding
from app.models.finding_work import FindingComment, FindingWork
from app.models.scan import Scan
from app.scans import workspace
from app.scans.finding_query import FindingFilter, FindingSort, findings_query

from ._shared import (
    SCAN_ROUTER_KWARGS,
    EditableScanDep,
    LightScanDep,
    ScanDep,
    ScanWriteDep,
    TenantId,
    _require_premium,
)

router = APIRouter(**SCAN_ROUTER_KWARGS)


@router.get("/{scan_id}/findings", response_model=list[schemas.FindingOut])
def list_findings(
    scan: LightScanDep,
    db: Session = Depends(get_db),
    severity: Severity | None = None,
    check: str | None = None,
    operation_id: uuid.UUID | None = None,
    verdict: Verdict | None = None,
    confidence: Confidence | None = None,
    premium: bool | None = None,
    q: str | None = None,
    endpoint: str | None = Query(
        default=None,
        max_length=4096,
        description="An endpoint label as the UI shows it (`GET /users/{id}`); "
        "matches findings with an operation and evidence-only findings alike.",
    ),
    include_dismissed: bool = True,
    sort: FindingSort = "severity",
    limit: int = Query(default=1000, ge=1, le=5000),
    offset: int = Query(default=0, ge=0),
) -> list[schemas.FindingOut]:
    """Filtered findings, ordered server-side so a page is a true slice.

    The list used to arrive whole and be filtered in the browser; at scale a
    page of the wrong rows is worse than useless, so the filters and ordering
    are part of the query. The response stays a bare list for existing clients.
    """
    filters = FindingFilter(
        severity=severity,
        check=check,
        operation_id=operation_id,
        verdict=verdict,
        confidence=confidence,
        premium=premium,
        q=q,
        endpoint=endpoint,
        include_dismissed=include_dismissed,
    )
    stmt = findings_query(scan.id, filters, sort)
    rows = db.scalars(stmt.limit(limit).offset(offset)).all()
    return [schemas.FindingOut.model_validate(f) for f in rows]


@router.get(
    "/{scan_id}/findings/summary", response_model=schemas.FindingSummaryOut
)
def finding_summary(
    scan: LightScanDep, db: Session = Depends(get_db)
) -> schemas.FindingSummaryOut:
    """Counts over every finding, not just the page the list happens to show."""
    severity_rows = db.execute(
        select(Finding.severity, func.count())
        .where(
            Finding.scan_id == scan.id,
            Finding.verdict != Verdict.dismissed,
        )
        .group_by(Finding.severity)
    ).all()
    severity = {
        str(level.value): int(count) for level, count in severity_rows
    }
    dismissed = int(
        db.scalar(
            select(func.count())
            .select_from(Finding)
            .where(
                Finding.scan_id == scan.id,
                Finding.verdict == Verdict.dismissed,
            )
        )
        or 0
    )
    verified_rows = db.execute(
        select(Finding.severity, func.count())
        .where(
            Finding.scan_id == scan.id,
            Finding.verdict != Verdict.dismissed,
            Finding.confidence == Confidence.verified,
            Finding.severity.in_((Severity.critical, Severity.high)),
        )
        .group_by(Finding.severity)
    ).all()
    verified = {
        str(level.value): int(count) for level, count in verified_rows
    }
    active = sum(severity.values())
    return schemas.FindingSummaryOut(
        total=active + dismissed,
        active=active,
        dismissed=dismissed,
        verified_critical=verified.get("critical", 0),
        verified_high=verified.get("high", 0),
        severity=severity,
    )


@router.patch("/{scan_id}/findings/{finding_id}", response_model=schemas.FindingOut)
def set_verdict(
    finding_id: uuid.UUID,
    body: schemas.VerdictUpdate,
    scan: ScanDep,
    principal: ScanWriteDep,
    db: Session = Depends(get_db),
) -> schemas.FindingOut:
    """Mark a finding confirmed or dismissed (false positive).

    The verdict is remembered against the finding's fingerprint as well as its
    row, so the next run does not hand back a false positive somebody already
    dismissed.
    """
    finding = db.get(Finding, finding_id)
    if finding is None or finding.scan_id != scan.id:
        raise HTTPException(status_code=404, detail="finding not found")
    finding.verdict = body.verdict
    run_record.record_triage(scan, finding, body.verdict)
    workspace.record_audit(
        db,
        principal,
        "finding.triage",
        "finding",
        finding.id,
        {"fingerprint": finding.fingerprint, "verdict": body.verdict.value},
    )
    db.commit()
    db.refresh(finding)
    return schemas.FindingOut.model_validate(finding)


# ---- Finding work items and comments (premium team workflow) -----------------


def _require_live_finding(db: Session, scan: Scan, fingerprint: str) -> None:
    """404 unless this scan's current findings contain that fingerprint.

    Work is keyed by fingerprint rather than by finding row: a re-run replaces
    the rows, and the fingerprint is the part that survives. A finding that is
    gone is not something a person can open, so an item for it is stale.
    """
    live = db.scalar(
        select(Finding.id)
        .where(Finding.scan_id == scan.id, Finding.fingerprint == fingerprint)
        .limit(1)
    )
    if live is None:
        raise HTTPException(status_code=404, detail="finding not found")


def _work_out(item: FindingWork, comments: list[FindingComment]) -> schemas.FindingWorkOut:
    return schemas.FindingWorkOut(
        scan_id=item.scan_id,
        fingerprint=item.fingerprint,
        owner=item.owner,
        owner_user_id=item.owner_user_id,
        due_date=item.due_date,
        status=item.status,
        updated_at=item.updated_at,
        comments=[schemas.FindingCommentOut.model_validate(c) for c in comments],
    )


@router.get("/{scan_id}/work", response_model=list[schemas.FindingWorkOut])
def list_finding_work(
    scan: ScanDep, tenant_id: TenantId, db: Session = Depends(get_db)
) -> list[schemas.FindingWorkOut]:
    """Every live finding with an assignment or a discussion.

    A discussion is independent of an assignment: a comment written before
    anyone is assigned (or after the assignment is cleared) still has to be
    readable, so a commented fingerprint with no work row is returned as an
    unassigned, "open" item. Otherwise the UI would accept a comment and then
    lose it on the next read.
    """
    _require_premium(tenant_id, db)
    live = set(
        db.scalars(
            select(Finding.fingerprint).where(
                Finding.scan_id == scan.id, Finding.fingerprint != ""
            )
        ).all()
    )
    if not live:
        return []
    items = db.scalars(
        select(FindingWork).where(
            FindingWork.scan_id == scan.id, FindingWork.fingerprint.in_(live)
        )
    ).all()
    by_fingerprint = {item.fingerprint: item for item in items}
    comments: dict[str, list[FindingComment]] = {}
    for comment in db.scalars(
        select(FindingComment)
        .where(
            FindingComment.scan_id == scan.id,
            FindingComment.fingerprint.in_(live),
        )
        .order_by(FindingComment.created_at)
    ):
        comments.setdefault(comment.fingerprint, []).append(comment)

    discussed = set(comments) - set(by_fingerprint)
    out: list[schemas.FindingWorkOut] = []
    for item in items:
        out.append(_work_out(item, comments.get(item.fingerprint, [])))
    for fingerprint in discussed:
        history = comments[fingerprint]
        out.append(
            schemas.FindingWorkOut(
                scan_id=scan.id,
                fingerprint=fingerprint,
                owner=None,
                due_date=None,
                status="open",
                # The row's own timestamp: the first thing anyone wrote about it.
                updated_at=history[0].created_at,
                comments=[schemas.FindingCommentOut.model_validate(c) for c in history],
            )
        )
    out.sort(key=lambda row: (row.updated_at, row.fingerprint))
    return out


@router.put("/{scan_id}/findings/{fingerprint}/work", response_model=schemas.FindingWorkOut)
def upsert_finding_work(
    fingerprint: str,
    body: schemas.FindingWorkIn,
    scan: EditableScanDep,
    principal: ScanWriteDep,
    db: Session = Depends(get_db),
) -> schemas.FindingWorkOut:
    """Create or partially update the work item for one live finding.

    An omitted field is unchanged; an explicit null clears owner/due date.
    """
    _require_premium(principal.tenant, db)
    _require_live_finding(db, scan, fingerprint)
    item = db.scalar(
        select(FindingWork).where(
            FindingWork.scan_id == scan.id, FindingWork.fingerprint == fingerprint
        )
    )
    if item is None:
        item = FindingWork(scan_id=scan.id, fingerprint=fingerprint, status="open")
        db.add(item)
    changed = body.model_dump(exclude_unset=True)
    if "owner_user_id" in changed:
        owner_user_id = changed["owner_user_id"]
        if owner_user_id is None:
            item.owner_user_id = None
            item.owner = None
        else:
            owner = workspace.member_user(db, principal.tenant, owner_user_id)
            if owner is None:
                raise HTTPException(
                    status_code=422,
                    detail="owner is not a member of this workspace",
                )
            item.owner_user_id = owner.id
            item.owner = owner.display_name
    elif "owner" in changed:
        item.owner = changed["owner"]
    if "due_date" in changed:
        item.due_date = changed["due_date"]
    if changed.get("status") is not None:
        item.status = changed["status"]
    workspace.record_audit(
        db,
        principal,
        "work.updated",
        "finding_work",
        fingerprint,
        {
            "status": item.status,
            "owner_user_id": str(item.owner_user_id) if item.owner_user_id else None,
        },
    )
    db.commit()
    db.refresh(item)
    comments = db.scalars(
        select(FindingComment)
        .where(
            FindingComment.scan_id == scan.id,
            FindingComment.fingerprint == fingerprint,
        )
        .order_by(FindingComment.created_at)
    ).all()
    return _work_out(item, list(comments))


@router.delete("/{scan_id}/findings/{fingerprint}/work")
def delete_finding_work(
    fingerprint: str,
    scan: EditableScanDep,
    principal: ScanWriteDep,
    db: Session = Depends(get_db),
) -> dict[str, str]:
    """Remove a work item. Its comments are separate rows and stay."""
    _require_premium(principal.tenant, db)
    item = db.scalar(
        select(FindingWork).where(
            FindingWork.scan_id == scan.id, FindingWork.fingerprint == fingerprint
        )
    )
    if item is None:
        raise HTTPException(status_code=404, detail="work item not found")
    workspace.record_audit(
        db, principal, "work.deleted", "finding_work", fingerprint
    )
    db.delete(item)
    db.commit()
    return {"status": "deleted"}


@router.post(
    "/{scan_id}/findings/{fingerprint}/comments",
    response_model=schemas.FindingCommentOut,
    status_code=201,
)
def create_finding_comment(
    fingerprint: str,
    body: schemas.FindingCommentIn,
    scan: EditableScanDep,
    principal: ScanWriteDep,
    db: Session = Depends(get_db),
) -> FindingComment:
    """Comment on a live finding, attributed to the acting person."""
    _require_premium(principal.tenant, db)
    _require_live_finding(db, scan, fingerprint)
    author = principal.display_name or principal.email or principal.tenant
    comment = FindingComment(
        scan_id=scan.id,
        fingerprint=fingerprint,
        author=author,
        author_user_id=principal.user_id,
        body=body.body,
    )
    db.add(comment)
    db.flush()
    workspace.record_audit(
        db,
        principal,
        "comment.created",
        "finding_comment",
        comment.id,
        {"fingerprint": fingerprint},
    )
    db.commit()
    db.refresh(comment)
    return comment


@router.delete("/{scan_id}/comments/{comment_id}")
def delete_finding_comment(
    comment_id: uuid.UUID,
    scan: EditableScanDep,
    principal: ScanWriteDep,
    db: Session = Depends(get_db),
) -> dict[str, str]:
    """Delete a comment that belongs to this scan."""
    _require_premium(principal.tenant, db)
    comment = db.get(FindingComment, comment_id)
    if comment is None or comment.scan_id != scan.id:
        raise HTTPException(status_code=404, detail="comment not found")
    workspace.record_audit(
        db,
        principal,
        "comment.deleted",
        "finding_comment",
        comment.id,
        {"fingerprint": comment.fingerprint},
    )
    db.delete(comment)
    db.commit()
    return {"status": "deleted"}
