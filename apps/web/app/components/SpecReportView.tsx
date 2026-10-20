"use client";

import type { SpecReport } from "@/lib/api";

/** Past a handful of lines the report stops being scannable, so it folds. */
const REPORT_LIST_LIMIT = 5;

function ReportList({ title, items }: { title: string; items: string[] }) {
  const list = (
    <ul>
      {items.map((text, i) => (
        <li key={`${i}-${text}`}>{text}</li>
      ))}
    </ul>
  );
  if (items.length <= REPORT_LIST_LIMIT) {
    return (
      <>
        <p className="muted-sm">{title}</p>
        {list}
      </>
    );
  }
  return (
    <details>
      <summary className="muted-sm">
        {title} ({items.length})
      </summary>
      {list}
    </details>
  );
}

/** What a spec parse kept, dropped and warned about — shown after every parse. */
export function SpecReportView({ report }: { report: SpecReport }) {
  return (
    <div className="spec-report">
      <p className="muted-sm">
        Parsed {report.operations} operation{report.operations === 1 ? "" : "s"}.
      </p>
      {report.warnings.length > 0 && (
        <ReportList title="Warnings" items={report.warnings} />
      )}
      {report.skipped.length > 0 && (
        <ReportList
          title="Skipped"
          items={report.skipped.map(
            (s) => `${s.method ? `${s.method} ` : ""}${s.path} — ${s.reason}`,
          )}
        />
      )}
    </div>
  );
}
