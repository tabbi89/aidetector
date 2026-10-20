"use client";

import type { Credential, Operation, RunOptions } from "@/lib/api";
import { ALL_SCOPE_KEYS, SCOPE_GROUPS, type ScopeCheck } from "./checkScope";
import type { TenantEntitlement } from "./useCapabilities";

type SkipReason = "premium-plan" | "premium-off" | "writes" | "fuzzing";

const SKIP_TEXT: Record<SkipReason, string> = {
  "premium-plan": "premium checks are not in this tenant's plan",
  "premium-off": "premium checks need the Standard scan level",
  writes: 'checks that modify the target need "Test writes"',
  fuzzing: "need the Standard scan level (schema fuzzing)",
};

/** Why this check is known not to run, or null when it will. OAST is unknown. */
function skipReason(
  check: ScopeCheck,
  options: RunOptions,
  entitled: boolean,
): SkipReason | null {
  const needs = check.needs ?? [];
  const level = options.level ?? "quick";
  if (needs.includes("premium")) {
    if (level === "quick") return "premium-off";
    if (!entitled) return "premium-plan";
  }
  if (needs.includes("mutate") && !options.mutate) return "writes";
  if (needs.includes("fuzz") && level === "quick") return "fuzzing";
  return null;
}

/**
 * What the run will actually do, in one scannable block above the Run panel.
 * It counts enabled endpoints, identities by role, and the engine checks a
 * known run flag leaves out. OAST has no capability flag, so those checks are
 * reported as "may be skipped" rather than promised or written off.
 */
export function ScanReadiness({
  target,
  operations,
  credentials,
  options,
  entitlement,
}: {
  target: string;
  operations: Operation[];
  credentials: Credential[];
  options: RunOptions;
  /** null while capabilities load, or when the API predates the entitlement. */
  entitlement: TenantEntitlement | null;
}) {
  const enabledOps = operations.filter((o) => o.enabled).length;
  // The web lane is a server run, which leaves local-only identities out.
  const usable = credentials.filter((c) => !c.local_only);
  const localOnly = credentials.length - usable.length;
  const roles = [...new Set(usable.map((c) => c.role || c.name).filter(Boolean))];

  const selected = new Set<string>(options.checks.length ? options.checks : ALL_SCOPE_KEYS);
  const checks = SCOPE_GROUPS.flatMap((g) => g.checks).filter((c) => selected.has(c.key));
  const entitled = entitlement ? entitlement.available : true;

  const skipped = new Map<SkipReason, number>();
  let maySkipOast = 0;
  for (const check of checks) {
    const reason = skipReason(check, options, entitled);
    if (reason) skipped.set(reason, (skipped.get(reason) ?? 0) + 1);
    else if ((check.needs ?? []).includes("oast")) maySkipOast += 1;
  }
  const skippedCount = [...skipped.values()].reduce((a, b) => a + b, 0);
  const runnable = checks.length - skippedCount;

  const premiumNote = (options.level ?? "quick") === "quick"
    ? "Not in a Quick scan"
    : entitlement && !entitlement.available
      ? "Requested — locked by this tenant's plan; premium checks will be skipped"
      : "Included";

  return (
    <dl className="readiness" aria-label="Run readiness">
      <div className="readiness-row">
        <dt>Target URL</dt>
        <dd className="readiness-target">{target}</dd>
      </div>
      <div className="readiness-row">
        <dt>Endpoints</dt>
        <dd>
          <strong>{enabledOps}</strong> of {operations.length} enabled
        </dd>
      </div>
      <div className="readiness-row">
        <dt>Identities</dt>
        <dd>
          {usable.length === 0 ? (
            <span className="is-warn">None — unauthenticated checks only</span>
          ) : (
            <>
              {usable.length} profile{usable.length === 1 ? "" : "s"}
              {roles.length > 0 && ` — ${roles.join(", ")}`}
            </>
          )}
          {localOnly > 0 && (
            <span className="muted">
              {" "}· {localOnly} local-only — a web run leaves {localOnly === 1 ? "it" : "them"} out;
              use <code>aidetector run</code>
            </span>
          )}
        </dd>
      </div>
      <div className="readiness-row">
        <dt>Checks</dt>
        <dd>
          <strong>{runnable}</strong> of {checks.length} engine checks
          {skippedCount > 0 ? (
            <>
              {" · "}
              <span className="is-warn">{skippedCount} will be skipped</span>
              <ul className="readiness-reasons">
                {[...skipped].map(([reason, count]) => (
                  <li key={reason}>
                    {count} skipped — {SKIP_TEXT[reason]}
                  </li>
                ))}
              </ul>
            </>
          ) : (
            " · none skipped"
          )}
          {maySkipOast > 0 && (
            <p className="readiness-maybe">
              {maySkipOast} may be skipped — out-of-band checks need an OAST
              server (a deployment setting); without one they report as skipped.
            </p>
          )}
        </dd>
      </div>
      <div className="readiness-row">
        <dt>Write permission</dt>
        <dd className={options.mutate ? "readiness-danger" : undefined}>
          {options.mutate ? (
            <strong>Writes allowed — target data will be modified</strong>
          ) : (
            "Read-only"
          )}
        </dd>
      </div>
      <div className="readiness-row">
        <dt>Executor</dt>
        <dd>Server worker (this deployment)</dd>
      </div>
      <div className="readiness-row">
        <dt>Premium checks</dt>
        <dd>{premiumNote}</dd>
      </div>
    </dl>
  );
}
