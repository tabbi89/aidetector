"use client";

import { memo, useState } from "react";
import type { RunOptions } from "@/lib/api";
import { clock } from "../../components/scanShared";
import { useCapabilities } from "../../components/useCapabilities";
import { WebRunNotice } from "../../components/WebRunNotice";

const SCHEDULES = [
  { m: 15, label: "every 15 min" },
  { m: 60, label: "hourly" },
  { m: 360, label: "every 6h" },
  { m: 1440, label: "daily" },
  { m: 10080, label: "weekly" },
];

/** The API accepts 0..100000 minutes; below 15 a run can outlive its own interval. */
const MIN_CUSTOM_MINUTES = 15;
const MAX_CUSTOM_MINUTES = 100000;

/** Flags worth naming: the ones that change what a run does to the target or costs. */
const PASS_LABELS: [keyof RunOptions, string][] = [
  ["mutate", "write testing"],
  ["ai", "AI"],
  ["zap", "ZAP"],
  ["kali", "Kali adjuncts"],
  ["confirm", "confirmation tools"],
  ["testssl", "testssl.sh TLS audit"],
  ["fuzz", "schema fuzzing"],
  ["premium", "premium"],
  ["adaptive", "adaptive validation"],
  ["resource_refine", "AI resource refinement"],
  ["plan", "AI plan"],
  ["adjudicate", "AI adjudication"],
  ["security_review", "AI security review"],
  ["genai_payloads", "AI payloads"],
];

export function describePasses(options: Record<string, unknown>): string {
  const on = PASS_LABELS.filter(([key]) => options[key] === true).map(([, label]) => label);
  const level = typeof options.level === "string" ? `${options.level} ` : "";
  return on.length
    ? `${level}engine scan + ${on.join(", ")}`
    : `${level}read-only engine scan`;
}

/**
 * Recurring re-run controls: pick an interval, or stop the active schedule.
 *
 * A schedule starts active scans nobody will click "Run" for, so enabling one
 * asks for the same authorization as a run — local state, cleared when the
 * panel remounts — and saves the passes currently selected under Run scan.
 */
function SchedulePanelImpl({
  targetUrl,
  minutes,
  nextRunAt,
  scheduleOptions,
  runOptions,
  onSchedule,
}: {
  targetUrl: string;
  minutes: number | null;
  nextRunAt: string | null;
  /** What the active schedule runs with. */
  scheduleOptions: Record<string, unknown>;
  /** What a new schedule would run with: the Run scan selection. */
  runOptions: RunOptions;
  onSchedule: (minutes: number | null, authorized: boolean) => void;
}) {
  const [authorized, setAuthorized] = useState(false);
  const [custom, setCustom] = useState("30");
  const [customError, setCustomError] = useState("");
  const { premium, loading } = useCapabilities();
  const locked = premium?.available === false;

  function scheduleCustom() {
    const value = Number(custom);
    if (
      !Number.isInteger(value) ||
      value < MIN_CUSTOM_MINUTES ||
      value > MAX_CUSTOM_MINUTES
    ) {
      setCustomError(
        `Enter a whole number of minutes between ${MIN_CUSTOM_MINUTES} and ${MAX_CUSTOM_MINUTES}.`,
      );
      return;
    }
    setCustomError("");
    onSchedule(value, authorized);
  }

  if (minutes) {
    return (
      <div>
      {locked && <p className="opt-warn">Scheduled runs are paused while this workspace is on Free. Premium access is required to dispatch them.</p>}
      <div className="sched">
        <span className="sched-on">
          ↻ Re-runs every {minutes} min
          {nextRunAt && ` · next at ${clock(nextRunAt)}`}
          {` · ${describePasses(scheduleOptions)}`}
        </span>
        <span className="grow" />
        <button
          className="btn quiet sm"
          onClick={() => {
            setAuthorized(false);
            onSchedule(null, false);
          }}
        >
          Stop schedule
        </button>
      </div>
      </div>
    );
  }

  if (locked) return <WebRunNotice />;

  return (
    <div>
      <label className="gate">
        <input
          type="checkbox"
          checked={authorized}
          disabled={loading}
          onChange={(e) => setAuthorized(e.target.checked)}
        />
        <span>
          I own, or am explicitly authorized to security-test,{" "}
          <strong>{targetUrl}</strong> on every scheduled run.{" "}
          <span className="muted-sm">
            Scheduled runs use the passes selected under Run scan:{" "}
            {describePasses(runOptions as unknown as Record<string, unknown>)}.
          </span>
        </span>
      </label>
      <div className="sched">
        <span className="muted-sm">Re-run this scan automatically:</span>
        {SCHEDULES.map((s) => (
          <button
            key={s.m}
            className="btn quiet sm"
            disabled={!authorized || loading}
            onClick={() => onSchedule(s.m, authorized)}
          >
            {s.label}
          </button>
        ))}
        <span className="muted-sm">or every</span>
        <input
          type="number"
          className="sched-minutes"
          min={MIN_CUSTOM_MINUTES}
          max={MAX_CUSTOM_MINUTES}
          value={custom}
          onChange={(e) => {
            setCustom(e.target.value);
            setCustomError("");
          }}
          disabled={!authorized || loading}
          aria-label="Custom schedule interval in minutes"
          aria-invalid={Boolean(customError)}
        />
        <span className="muted-sm">min</span>
        <button
          className="btn quiet sm"
          disabled={!authorized || loading}
          onClick={scheduleCustom}
        >
          Set
        </button>
        {customError && <span className="field-error">{customError}</span>}
      </div>
    </div>
  );
}

export const SchedulePanel = memo(SchedulePanelImpl);
