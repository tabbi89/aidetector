"use client";

import { memo } from "react";
import type { ScanEvent, ScanStatus } from "@/lib/api";
import { ACTIVE, clock } from "../../components/scanShared";

/**
 * Stage names are the engine's own snake_case. A stage missing here is progress,
 * not a caveat, so it falls back to the name with underscores spaced out.
 */
const STAGE_LABELS: Record<string, string> = {
  check_skipped: "check skipped",
  check_failed: "check failed",
  budget_exhausted: "budget spent",
  zap_skipped: "ZAP skipped",
  kali_skipped: "Kali skipped",
  testssl_skipped: "testssl skipped",
  sqlmap_skipped: "sqlmap skipped",
  dalfox_skipped: "dalfox skipped",
  commix_skipped: "commix skipped",
  tplmap_skipped: "tplmap skipped",
  adjuncts_skipped: "tools skipped",
  kali_partial: "Kali partial",
  ai_skipped: "AI triage skipped",
  plan_skipped: "AI plan skipped",
  genai_payloads_skipped: "AI payloads skipped",
  security_review_skipped: "AI design review",
  credential_unreadable: "credential unreadable",
  auth_grant_failed: "authentication failed",
  egress_blocked: "egress blocked",
  cleanup_failed: "cleanup failed",
  identities_unavailable: "identities unavailable",
  spec_warning: "spec warning",
  error: "error",
  cancelled: "cancelled",
  done: "done",
};

/** Readable label for an event stage; the raw name stays available as a title. */
export function stageLabel(stage: string): string {
  return STAGE_LABELS[stage] ?? stage.replaceAll("_", " ");
}

/**
 * The engine's per-stage event stream, newest first. Open while a scan runs, and
 * after a run failed or was cancelled — that is when the log explains why.
 */
function ActivityLogImpl({
  events,
  status,
}: {
  events: ScanEvent[];
  status: ScanStatus;
}) {
  if (events.length === 0) return null;
  const open = ACTIVE.has(status) || status === "failed" || status === "cancelled";
  return (
    <details className="log" open={open}>
      <summary>
        Activity log
        <span className="n">{events.length} events</span>
      </summary>
      <div className="events">
        {[...events].reverse().map((e, i) => (
          <div className="ev-row" key={`${e.created_at}-${i}`}>
            <span className="t">{clock(e.created_at)}</span>
            <span className="stage" title={e.stage}>{stageLabel(e.stage)}</span>
            <span className="m">{e.message}</span>
          </div>
        ))}
      </div>
    </details>
  );
}

export const ActivityLog = memo(ActivityLogImpl);
