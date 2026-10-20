from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Response
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from app.api import schemas
from app.core.db import get_db
from app.models.finding import sort_findings

from ._shared import (
    SCAN_ROUTER_KWARGS,
    EditableScanDep,
    ScanDep,
    ScanWriteDep,
    TenantId,
    _latest_run,
    _require_premium,
)

router = APIRouter(**SCAN_ROUTER_KWARGS)


@router.get("/{scan_id}/sarif")
def findings_sarif(scan: ScanDep) -> JSONResponse:
    """Findings as a SARIF 2.1.0 document, for CI security dashboards."""
    from app.scans.sarif import to_sarif

    return JSONResponse(
        to_sarif(scan),
        headers={
            "Content-Disposition": f'attachment; filename="scan-{scan.id}.sarif.json"'
        },
    )


@router.get("/{scan_id}/cost", response_model=schemas.CostOut)
def cost(scan: ScanDep) -> schemas.CostOut:
    """Per-call token ledger and total cost for the scan."""
    from app.ai.summary import summarize_models

    return schemas.CostOut(
        scan_id=scan.id,
        total_usd=scan.cost_usd,
        entries=[schemas.LedgerEntryOut.model_validate(e) for e in scan.ledger],
        models=[schemas.AiModelUsage.model_validate(m) for m in summarize_models(scan.ledger)],
    )


@router.get("/{scan_id}/export")
def export(scan: ScanDep) -> JSONResponse:
    """Download the full scan result as JSON."""
    from app.ai.summary import summarize_models

    latest = _latest_run(scan)
    payload = {
        "scan": schemas.ScanOut.model_validate(scan).model_dump(mode="json"),
        "findings": [
            schemas.FindingOut.model_validate(f).model_dump(mode="json")
            for f in sort_findings(scan.findings)
        ],
        "coverage": (latest.coverage if latest else []) or [],
        "ai": summarize_models(scan.ledger),
    }
    return JSONResponse(
        content=payload,
        headers={
            "Content-Disposition": f'attachment; filename="scan-{scan.id}.json"'
        },
    )


@router.get("/{scan_id}/report.pdf")
def report_pdf(scan: ScanDep) -> Response:
    """Download a formatted PDF report of the scan's findings."""
    from app.scans.report import build_report

    pdf = build_report(scan)
    return Response(
        content=pdf,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="scan-{scan.id}.pdf"'
        },
    )


@router.get("/{scan_id}/report.html")
def report_html(scan: ScanDep):
    """Standalone HTML report — renders in the browser, printable to PDF."""
    from fastapi.responses import HTMLResponse

    from app.scans.report import build_report_html

    return HTMLResponse(content=build_report_html(scan))


@router.get("/{scan_id}/report.pentest")
def report_pentest(
    scan: ScanDep, tenant_id: TenantId, db: Session = Depends(get_db)
) -> Response:
    """Pentest-grade Markdown report — a premium deliverable.

    Gated like ``POST /scans/{id}/ask``; the PDF/HTML/JSON exports stay
    available on every plan.
    """
    _require_premium(tenant_id, db)
    from app.scans.pentest import build_pentest_report

    return Response(
        content=build_pentest_report(scan),
        media_type="text/markdown",
        headers={
            "Content-Disposition": f'attachment; filename="scan-{scan.id}.pentest.md"'
        },
    )


@router.post("/{scan_id}/ask", response_model=schemas.AskOut)
def ask(
    body: schemas.AskRequest,
    scan: EditableScanDep,
    principal: ScanWriteDep,
    db: Session = Depends(get_db),
) -> schemas.AskOut:
    """Answer a natural-language question about the scan's findings (premium).

    Takes the editable guard: answering writes token-ledger rows, so it must not
    run while a worker is still writing to the scan.
    """
    _require_premium(principal.tenant, db)
    from app.ai.budget import BudgetExhausted
    from app.ai.planner import PlannerUnavailable
    from app.engine import ai_phases

    try:
        answer = ai_phases.answer_question(db, scan, body.question, None)
    except BudgetExhausted as exc:
        raise HTTPException(status_code=402, detail=str(exc)) from exc
    except PlannerUnavailable as exc:
        raise HTTPException(status_code=502, detail="AI unavailable") from exc
    return schemas.AskOut(answer=answer)
