"use client";

import { memo, useMemo } from "react";
import type { Cost, LedgerEntry } from "@/lib/api";

/** What each AI step did, in the reader's words. The ledger stores the code name. */
const STEP_LABELS: Record<string, string> = {
  plan: "Planning",
  adjudicate: "Finding review",
  execute: "Triage",
  security_review: "Security design review",
  qa: "Questions",
  genai_payloads: "Payload design",
  agent: "Agent",
};

function stepLabel(phase: string): string {
  if (STEP_LABELS[phase]) return STEP_LABELS[phase];
  const words = phase.replace(/[_-]+/g, " ").trim();
  return words ? words[0].toUpperCase() + words.slice(1) : "Other";
}

interface Step {
  phase: string;
  calls: number;
  tokensIn: number;
  tokensOut: number;
  micros: number;
}

/** One row per AI step, in the order the run first used it. */
function byStep(entries: LedgerEntry[]): Step[] {
  const steps = new Map<string, Step>();
  for (const e of entries) {
    const step = steps.get(e.phase) ?? {
      phase: e.phase, calls: 0, tokensIn: 0, tokensOut: 0, micros: 0,
    };
    step.calls += 1;
    step.tokensIn += e.tokens_in;
    step.tokensOut += e.tokens_out;
    step.micros += e.cost_micros;
    steps.set(e.phase, step);
  }
  return [...steps.values()];
}

const usd = (value: number) => `$${value.toFixed(4)}`;

/**
 * What the scan spent on AI, per step, and the total.
 *
 * Which model answered is an operator detail, not something a scan report needs,
 * so the panel names the step (planning, security review, …) and its tokens and
 * cost, never the model.
 *
 * An empty panel means one of three different things — the read failed, the run
 * asked for an AI step that never ran, or no AI step was asked for — so it says
 * which. "Nothing recorded" over a skipped step reads as "the model found
 * nothing", which is the one thing it must not say.
 */
function AiCostPanelImpl({
  cost,
  failed,
  aiSkip,
}: {
  cost: Cost | null;
  /** The cost read failed; the panel is showing nothing rather than zero. */
  failed: boolean;
  /** Why a requested AI step did not run, when the run's events say so. */
  aiSkip: string | null;
}) {
  const steps = useMemo(() => byStep(cost?.entries ?? []), [cost]);
  if (!cost || steps.length === 0) {
    return (
      <div className="specbox config-empty-state">
        <div className="spec-head"><h2>AI usage</h2></div>
        {failed ? (
          <p>
            Could not load AI usage for this scan. Reload the page to try again.
          </p>
        ) : aiSkip ? (
          <p>
            No AI usage: this run asked for an AI step that did not run — {aiSkip}
          </p>
        ) : (
          <p>No AI usage has been recorded for this scan yet.</p>
        )}
      </div>
    );
  }
  const calls = steps.reduce((n, s) => n + s.calls, 0);
  return (
    <details className="ai-panel">
      <summary className="ai-summary">
        <span className="ai-caret" aria-hidden="true" />
        <span className="ai-used-label">AI usage</span>
        <span className="ai-steps">
          {steps.map((s) => stepLabel(s.phase)).join(" · ")}
        </span>
        <span className="grow" />
        <span className="ai-calls">
          {calls} call{calls === 1 ? "" : "s"}
        </span>
        <span className="ai-total">{usd(cost.total_usd)}</span>
      </summary>
      <div className="cost-rows" role="table" aria-label="AI usage by step">
        <div className="cost-row cost-head" role="row">
          <span role="columnheader">Step</span>
          <span role="columnheader" className="num">Tokens in</span>
          <span role="columnheader" className="num">Tokens out</span>
          <span role="columnheader" className="num">Cost</span>
        </div>
        {steps.map((s) => (
          <div className="cost-row" role="row" key={s.phase}>
            <span role="cell" className="cost-step">
              {stepLabel(s.phase)}
              {s.calls > 1 && <span className="cost-calls"> × {s.calls}</span>}
            </span>
            <span role="cell" className="mono num">{s.tokensIn.toLocaleString()}</span>
            <span role="cell" className="mono num">{s.tokensOut.toLocaleString()}</span>
            <span role="cell" className="mono num">{usd(s.micros / 1_000_000)}</span>
          </div>
        ))}
      </div>
    </details>
  );
}

export const AiCostPanel = memo(AiCostPanelImpl);
