"use client";

import type { Finding, FindingSummaryState, RunDiff, ScanEvent, Severity } from "@/lib/api";
import { RANK, gapCountLabel } from "../../components/scanShared";

const HIGH_RISK = new Set<Severity>(["critical", "high"]);

function byRisk(a: { severity: Severity }, b: { severity: Severity }) {
  return RANK[a.severity] - RANK[b.severity];
}

function findingLabel(count: number) {
  return `${count} finding${count === 1 ? "" : "s"}`;
}

/**
 * "What needs attention", above the workspace.
 *
 * Every row names the tab that shows its evidence, so the summary is a route
 * into the results rather than a second place to read them. It deliberately
 * makes no "secure" claim: absent findings plus an untested endpoint is not a
 * clean result, and the copy says so.
 */
export function AttentionSummary({
  findings, summary, complete, diff, gaps, notRun, running, onFindings, onDismissed, onTab,
}: {
  findings: Finding[];
  /** Counts over every finding, or why they are not known. */
  summary: FindingSummaryState;
  /** `findings` holds every finding (no further page on the server). */
  complete: boolean;
  /** Null until the changes section has loaded it; null is "not compared". */
  diff: RunDiff | null;
  /** Steps the engine reported it could not do. */
  gaps: ScanEvent[];
  /** Requested tools the latest run did not run, when the run list is loaded. */
  notRun: string[];
  running: boolean;
  onFindings: (severity: Severity) => void;
  onDismissed: () => void;
  onTab: (tab: "changes" | "gaps") => void;
}) {
  const verified = findings
    .filter(
      (f) =>
        f.verdict !== "dismissed" &&
        f.confidence === "verified" &&
        HIGH_RISK.has(f.severity),
    )
    .sort(byRisk);
  const full = summary.status === "ready" ? summary.summary : null;
  // The loaded page speaks for every finding only when it holds them all.
  // Otherwise its counts are a floor, and nothing may be called clean.
  const known = full !== null || complete;
  const verifiedCritical =
    full?.verified_critical ??
    verified.filter((f) => f.severity === "critical").length;
  const verifiedHigh =
    full?.verified_high ??
    verified.filter((f) => f.severity === "high").length;
  const verifiedCount = verifiedCritical + verifiedHigh;
  const worst = verified[0]?.severity;

  const regressions = (diff?.added ?? [])
    .filter((f) => HIGH_RISK.has(f.severity))
    .sort(byRisk);
  const dismissed =
    full?.dismissed ??
    findings.filter((f) => f.verdict === "dismissed").length;
  const gapCount = gaps.length || notRun.length;
  const clean = known && verifiedCount === 0 && regressions.length === 0;

  const severityParts = [
    verifiedCritical ? `${verifiedCritical} critical` : "",
    verifiedHigh ? `${verifiedHigh} high` : "",
  ].filter(Boolean);

  // The gap row below already names the skipped steps, so the verdict only
  // says that they qualify it rather than repeating the count.
  const caveats = [
    running ? "the scan is still running" : "",
    diff === null ? "changes between runs were not compared" : "",
    gapCount ? "some steps did not run" : "",
  ].filter(Boolean);
  const rowCount =
    Number(verifiedCount > 0) +
    Number(regressions.length > 0 && diff !== null) +
    Number(gapCount > 0) +
    Number(dismissed > 0);

  return (
    <section className="attention" aria-labelledby="attention-title">
      <div className="attention-head">
        <h2 id="attention-title">Needs attention</h2>
        {rowCount > 1 && <span className="attention-sub">Most severe first</span>}
      </div>

      {clean && (
        <div className={`attention-verdict ${caveats.length ? "caution" : "ok"}`}>
          <span className="attention-verdict-icon" aria-hidden="true">
            {caveats.length ? "!" : "✓"}
          </span>
          <span className="attention-copy">
            <strong>No verified high or critical findings</strong>
            <span className="attention-detail">
              {caveats.length
                ? `Not a clean result yet: ${caveats.join("; ")}.`
                : "Review coverage before calling it clean."}
            </span>
          </span>
        </div>
      )}

      {verifiedCount > 0 && (
        <button
          type="button"
          className="attention-row high-risk"
          onClick={() => onFindings(worst ?? "high")}
        >
          <span className="attention-count">{verifiedCount}</span>
          <span className="attention-copy">
            <strong>
              Verified {severityParts.join(" · ")}{" "}
              {verifiedCount === 1 ? "finding" : "findings"}
              {known ? "" : " among the findings loaded so far"}
            </strong>
            <span className="attention-detail">
              {verified.slice(0, 2).map((f) => (
                <span className="attention-finding" key={f.id}>
                  <span className={`sev-badge ${f.severity}`}>{f.severity}</span>
                  {f.title}
                </span>
              ))}
            </span>
          </span>
          <span className="attention-action">View findings</span>
        </button>
      )}

      {regressions.length > 0 && diff && (
        <button
          type="button"
          className="attention-row high-risk"
          onClick={() => onTab("changes")}
        >
          <span className="attention-count">{regressions.length}</span>
          <span className="attention-copy">
            <strong>
              New high-risk {findingLabel(regressions.length)} since run{" "}
              {diff.from_run} → {diff.to_run}
            </strong>
            <span className="attention-detail">
              {regressions.slice(0, 2).map((f) => (
                <span className="attention-finding" key={f.fingerprint || f.title}>
                  <span className={`sev-badge ${f.severity}`}>{f.severity}</span>
                  {f.title}
                </span>
              ))}
            </span>
          </span>
          <span className="attention-action">View changes</span>
        </button>
      )}

      {gapCount > 0 && (
        <button
          type="button"
          className="attention-row gap"
          onClick={() => onTab("gaps")}
        >
          <span className="attention-count">{gapCount}</span>
          <span className="attention-copy">
            <strong>
              {gaps.length
                ? gapCountLabel(gaps)
                : "Requested tools did not run"}
            </strong>
            <span className="attention-detail">
              {notRun.length > 0
                ? `Requested but not run: ${notRun.join(", ")}`
                : "A step that never ran looks the same as one that found nothing — check what was skipped."}
            </span>
          </span>
          <span className="attention-action">Review coverage</span>
        </button>
      )}

      {dismissed > 0 && (
        <button
          type="button"
          className="attention-row muted"
          onClick={onDismissed}
        >
          <span className="attention-count">
            {known ? "" : "≥"}
            {dismissed}
          </span>
          <span className="attention-copy">
            <strong>
              {dismissed === 1 ? "Finding" : "Findings"} dismissed as false
              positive
            </strong>
            <span className="attention-detail">
              Hidden by default; review if the run has changed since.
            </span>
          </span>
          <span className="attention-action">Show dismissed</span>
        </button>
      )}

      {!known && (
        <p className="attention-clean" role="status">
          {summary.status === "loading"
            ? "Counting every finding…"
            : "Counts over every finding are unavailable right now; the numbers above cover only the findings loaded so far, so this is not a clean result."}
        </p>
      )}
    </section>
  );
}