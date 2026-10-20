"""Report generation for a completed scan (PDF and standalone HTML)."""
from __future__ import annotations

import html
import io
import json
from datetime import UTC, datetime

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    HRFlowable,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from app.domain.enums import Confidence, Severity, Verdict
from app.models.finding import sort_findings
from app.models.scan import Scan

_SEV_COLOR = {
    Severity.critical: colors.HexColor("#b3261e"),
    Severity.high: colors.HexColor("#d83a3f"),
    Severity.medium: colors.HexColor("#c9820a"),
    Severity.low: colors.HexColor("#697485"),
    Severity.info: colors.HexColor("#697485"),
}


def _latest_coverage(scan: Scan) -> list[dict]:
    """Per-endpoint coverage rows from the most recent run (empty if never run)."""
    latest = max(scan.runs, key=lambda r: r.run_number, default=None)
    return (latest.coverage if latest else []) or []


def _latest_adaptive(scan: Scan) -> dict:
    latest = max(scan.runs, key=lambda r: r.run_number, default=None)
    value = (latest.adaptive if latest else {}) or {}
    return value if isinstance(value, dict) else {}


def _coverage_sorted(rows: list[dict]) -> list[dict]:
    """Findings first, then the busiest endpoints, then by path."""
    return sorted(
        rows,
        key=lambda r: (-r.get("findings", 0), -r.get("requests", 0), r.get("path", "")),
    )


def _ai_summary_text(scan: Scan) -> str:
    """One-line 'what AI was used', or '' when the scan ran engine-only."""
    from app.ai.summary import summarize_models

    models = summarize_models(scan.ledger)
    if not models:
        return ""
    parts = [f"{m['model']} ({', '.join(m['phases'])})" for m in models]
    return "AI: " + " · ".join(parts)


def _coverage_html(scan: Scan, e) -> str:
    rows = _latest_coverage(scan)
    if not rows:
        return ""
    trs: list[str] = []
    for r in _coverage_sorted(rows):
        checks = ", ".join(r.get("checks") or []) or "—"
        req = r.get("requests", 0)
        req_cell = str(req) if req else '<span class="zero">0</span>'
        cls = "" if r.get("enabled", True) else "off"
        path = e(r.get("path", ""))
        if not r.get("enabled", True):
            path += ' <span class="zero">(excluded)</span>'
        trs.append(
            f'<tr class="{cls}"><td class="mono">{e(r.get("method", ""))}</td>'
            f'<td class="mono">{path}</td><td class="num">{req_cell}</td>'
            f"<td class=\"num\">{r.get('findings', 0)}</td><td>{e(checks)}</td></tr>"
        )
    return (
        '<section class="cov"><h2>Per-endpoint coverage</h2>'
        "<table class=\"cov\"><thead><tr><th>Method</th><th>Path</th>"
        "<th class=\"num\">Requests</th><th class=\"num\">Findings</th>"
        "<th>Checks exercised</th></tr></thead><tbody>"
        + "".join(trs)
        + "</tbody></table></section>"
    )


def build_report(scan: Scan) -> bytes:
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        leftMargin=18 * mm, rightMargin=18 * mm,
        topMargin=18 * mm, bottomMargin=18 * mm,
        title=f"aidetector scan {scan.id}",
    )
    styles = getSampleStyleSheet()
    h1 = ParagraphStyle("h1", parent=styles["Heading1"], fontSize=20, spaceAfter=2)
    meta = ParagraphStyle("meta", parent=styles["Normal"], textColor=colors.HexColor("#697485"))
    ftitle = ParagraphStyle("ft", parent=styles["Heading3"], fontSize=12, spaceAfter=1)
    body = ParagraphStyle("bd", parent=styles["Normal"], fontSize=9.5, leading=13)
    ai = ParagraphStyle("ai", parent=body, textColor=colors.HexColor("#1a54ff"))

    elems: list = [
        Paragraph("API Security Scan Report", h1),
        Paragraph(f"Target: {scan.target_base_url}", meta),
        Paragraph(
            f"Status: {scan.status.value} · {len(scan.findings)} findings · "
            f"AI cost ${scan.cost_usd:.4f}",
            meta,
        ),
    ]
    ai_text = _ai_summary_text(scan)
    if ai_text:
        elems.append(Paragraph(ai_text, meta))
    elems.append(Spacer(1, 8))

    # Severity summary table
    counts = {s: 0 for s in Severity}
    for f in scan.findings:
        counts[f.severity] += 1
    summary = [["Severity", "Count"]] + [
        [s.value.title(), str(counts[s])] for s in Severity if counts[s]
    ]
    if len(summary) > 1:
        t = Table(summary, colWidths=[40 * mm, 25 * mm])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#eef1f5")),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#e2e6ec")),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
        ]))
        elems += [t, Spacer(1, 12)]

    findings = sort_findings(scan.findings)
    adaptive = _latest_adaptive(scan)
    if adaptive.get("enabled"):
        elems += [
            Spacer(1, 8),
            Paragraph(
                "Adaptive validation: "
                f"{len(adaptive.get('tests') or [])} tests · "
                f"{adaptive.get('requests', 0)} requests · "
                f"stop reason: {html.escape(str(adaptive.get('stop_reason', 'unknown')))}",
                meta,
            ),
        ]
    for f in findings:
        hexcode = "#" + _SEV_COLOR[f.severity].hexval()[2:]
        tag = f"<font color='{hexcode}'><b>{f.severity.value.upper()}</b></font>"
        conf = f" · {(f.confidence or Confidence.heuristic).value}"
        owasp = f" · {f.owasp_id}" if f.owasp_id else ""
        verdict = f.verdict or Verdict.unreviewed
        vd = f" · verdict: {verdict.value}" if verdict.value != "unreviewed" else ""
        elems.append(Paragraph(f"{tag}{conf}{owasp}{vd} — {html.escape(f.title)}", ftitle))
        elems.append(Paragraph(html.escape(f.description), body))
        if f.remediation:
            # Remediation interpolates evidence (paths, params), so escape it:
            # reportlab parses the paragraph as markup and a stray & or < in a
            # target's own URL would abort the export. Title and description
            # carry the same target-controlled text, so they are escaped above.
            elems.append(Paragraph(f"<b>Fix:</b> {html.escape(f.remediation)}", body))
        if f.ai_rationale:
            elems.append(Paragraph(f"AI: {html.escape(f.ai_rationale)}", ai))
        elems.append(Spacer(1, 4))
        elems.append(HRFlowable(width="100%", thickness=0.3, color=colors.HexColor("#e2e6ec")))
        elems.append(Spacer(1, 8))

    if not findings:
        elems.append(Paragraph("No findings recorded.", body))

    cov = _latest_coverage(scan)
    if cov:
        h2 = ParagraphStyle("h2", parent=styles["Heading2"], fontSize=13, spaceBefore=10)
        elems += [Spacer(1, 8), Paragraph("Per-endpoint coverage", h2)]
        data = [["Method", "Path", "Reqs", "Finds", "Checks"]]
        for r in _coverage_sorted(cov):
            path = r.get("path", "") + ("" if r.get("enabled", True) else " (excluded)")
            data.append([
                r.get("method", ""),
                path,
                str(r.get("requests", 0)),
                str(r.get("findings", 0)),
                str(len(r.get("checks") or [])),
            ])
        ct = Table(data, colWidths=[18 * mm, 92 * mm, 15 * mm, 15 * mm, 18 * mm], repeatRows=1)
        ct.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#eef1f5")),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#e2e6ec")),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("ALIGN", (2, 0), (-1, -1), "RIGHT"),
        ]))
        elems.append(ct)

    doc.build(elems)
    return buf.getvalue()


_SEV_HEX = {
    Severity.critical: "#b3261e",
    Severity.high: "#d83a3f",
    Severity.medium: "#c9820a",
    Severity.low: "#697485",
    Severity.info: "#697485",
}


def build_report_html(scan: Scan) -> str:
    """Self-contained HTML report: inline CSS, light/dark, print-friendly."""
    e = html.escape
    counts = {s: 0 for s in Severity}
    for f in scan.findings:
        counts[f.severity] += 1
    summary = "".join(
        f'<span class="chip" style="--c:{_SEV_HEX[s]}">{s.value} '
        f"<b>{counts[s]}</b></span>"
        for s in Severity
        if counts[s]
    )
    findings = sort_findings(scan.findings)

    blocks: list[str] = []
    for f in findings:
        verdict = f.verdict or Verdict.unreviewed
        vd = (
            f' <span class="vd">verdict: {e(verdict.value)}</span>'
            if verdict.value != "unreviewed"
            else ""
        )
        owasp = f' <span class="owasp">{e(f.owasp_id)}</span>' if f.owasp_id else ""
        conf_value = (f.confidence or Confidence.heuristic).value
        conf = f' <span class="conf {conf_value}">{e(conf_value)}</span>'
        ai = (
            f'<p class="ai">AI: {e(f.ai_rationale)}</p>' if f.ai_rationale else ""
        )
        evidence = (
            "<details><summary>Evidence</summary><pre>"
            + e(json.dumps(f.evidence, indent=2, default=str))
            + "</pre></details>"
        )
        refs = "".join(
            f'<a href="{e(str(u))}" rel="noreferrer noopener">{e(str(u))}</a>'
            for u in (f.references or [])
        )
        fix = (
            f'<div class="fix"><span class="fix-tag">Fix</span>'
            f"<p>{e(f.remediation)}</p>"
            + (f'<div class="refs">{refs}</div>' if refs else "")
            + "</div>"
            if f.remediation
            else ""
        )
        blocks.append(
            f'<article class="f {f.severity.value}">'
            f'<div class="fh"><span class="sev" style="--c:{_SEV_HEX[f.severity]}">'
            f"{f.severity.value.upper()}</span>{conf}{owasp}{vd}"
            f'<span class="t">{e(f.title)}</span></div>'
            f"<p>{e(f.description)}</p>{fix}{ai}{evidence}"
            f'<div class="m">{e(f.check)}</div></article>'
        )

    body = "\n".join(blocks) or '<p class="none">No findings recorded.</p>'
    coverage_html = _coverage_html(scan, e)
    adaptive = _latest_adaptive(scan)
    adaptive_html = ""
    if adaptive.get("enabled"):
        adaptive_html = (
            "<section><h2>Premium adaptive validation</h2>"
            f"<p class=\"meta\">{len(adaptive.get('tests') or [])} tests · "
            f"{adaptive.get('requests', 0)} requests · stop reason: "
            f"{e(adaptive.get('stop_reason', 'unknown'))}</p></section>"
        )
    ai_text = _ai_summary_text(scan)
    ai_html = f'<p class="meta ai-line">{e(ai_text)}</p>' if ai_text else ""
    generated = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>aidetector report — {e(scan.target_base_url)}</title>
<style>
  :root {{
    --bg:#f7f8fa; --surface:#fff; --ink:#17202b; --dim:#697485; --line:#e2e6ec;
    /* Remediation reads as its own thing, not as the blue AI note. */
    --fix:#0b8578; --fix-soft:#ddf3ef;
  }}
  @media (prefers-color-scheme: dark) {{
    :root {{ --bg:#0d1117; --surface:#161b22; --ink:#e6edf3; --dim:#9aa7b4;
             --line:#2d3542; --fix:#3ccdb8; --fix-soft:#10302d; }}
  }}
  * {{ box-sizing:border-box; }}
  body {{ margin:0; background:var(--bg); color:var(--ink);
         font:14px/1.55 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto,
         sans-serif; }}
  main {{ max-width:860px; margin:0 auto; padding:32px 20px 64px; }}
  h1 {{ font-size:24px; margin:0 0 4px; }}
  .meta {{ color:var(--dim); margin:2px 0; }}
  .chips {{ margin:14px 0 22px; display:flex; gap:8px; flex-wrap:wrap; }}
  .chip {{ border:1px solid var(--line); border-radius:999px; padding:3px 11px;
          color:var(--c); background:var(--surface); }}
  article.f {{ background:var(--surface); border:1px solid var(--line);
              border-radius:10px; padding:14px 16px; margin:0 0 12px; }}
  .fh {{ display:flex; gap:8px; align-items:baseline; flex-wrap:wrap; }}
  .fh .t {{ font-weight:600; }}
  .sev {{ color:var(--c); font-weight:700; font-size:11px; letter-spacing:.04em; }}
  .owasp {{ color:var(--dim); font-size:12px; }}
  .vd {{ color:var(--dim); font-size:12px; }}
  .conf {{ font-size:11px; letter-spacing:.03em; border:1px solid var(--line);
          border-radius:999px; padding:1px 8px; color:var(--dim); }}
  .conf.verified {{ color:#1f7a4d; border-color:#1f7a4d; }}
  .fix {{ border-left:3px solid var(--fix); background:var(--fix-soft);
         border-radius:0 8px 8px 0; padding:8px 12px; margin:10px 0 0; }}
  .fix p {{ margin:4px 0 0; }}
  .fix-tag {{ font-size:10px; font-weight:700; letter-spacing:.06em;
             text-transform:uppercase; color:var(--fix); }}
  .refs {{ margin-top:6px; display:flex; flex-direction:column; gap:2px; }}
  .refs a {{ font-size:11.5px; color:var(--dim); word-break:break-all; }}
  .refs a:hover {{ color:var(--fix); }}
  .m {{ color:var(--dim); font-size:12px; margin-top:8px; }}
  .ai {{ color:#1a54ff; }}
  .none {{ color:var(--dim); }}
  details summary {{ cursor:pointer; color:var(--dim); font-size:12px; }}
  pre {{ background:var(--bg); border:1px solid var(--line); border-radius:8px;
        padding:10px; overflow-x:auto; font-size:11.5px; }}
  h2 {{ font-size:16px; margin:34px 0 10px; }}
  table.cov {{ width:100%; border-collapse:collapse; font-size:12.5px; }}
  table.cov th, table.cov td {{ text-align:left; padding:6px 8px;
        border-bottom:1px solid var(--line); vertical-align:top; }}
  table.cov th {{ color:var(--dim); font-weight:600; }}
  table.cov td.num {{ text-align:right; font-variant-numeric:tabular-nums; }}
  table.cov .mono {{ font-family:ui-monospace, SFMono-Regular, Menlo, monospace; }}
  table.cov tr.off td {{ color:var(--dim); }}
  table.cov .zero {{ color:var(--dim); }}
  @media print {{
    body {{ background:#fff; color:#000; }}
    article.f {{ break-inside:avoid; }}
  }}
</style>
</head>
<body>
<main>
  <h1>API Security Scan Report</h1>
  <p class="meta">Target: {e(scan.target_base_url)}</p>
  <p class="meta">Status: {e(scan.status.value)} · {len(scan.findings)} findings ·
     AI cost ${scan.cost_usd:.4f} · generated {generated}</p>
  {ai_html}
  <div class="chips">{summary}</div>
  {body}
  {adaptive_html}
  {coverage_html}
</main>
</body>
</html>"""
