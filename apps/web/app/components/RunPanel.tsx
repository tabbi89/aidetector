"use client";

import { memo, useEffect, useId, useState, type ReactNode } from "react";
import { type CheckKey, type RunOptions } from "@/lib/api";
import {
  ALL_SCOPE_KEYS,
  NEED_HINT,
  NEED_OPTION,
  NEED_TAG,
  SCOPE_GROUPS,
  normaliseScope,
  presetOf,
  unmetNeeds,
  withPresetPasses,
  type Need,
  type ScopeGroup,
} from "./checkScope";
import { SCAN_LEVELS } from "./scanLevels";
import { useCapabilities } from "./useCapabilities";

const PRESETS: { id: string; title: string; blurb: string }[] = [
  {
    id: "all",
    title: "Full scan",
    blurb: "Every engine check. Ones that need writes or premium report as skipped.",
  },
  ...SCOPE_GROUPS.map(({ id, title, blurb }) => ({ id, title, blurb })),
  { id: "custom", title: "Custom", blurb: "Pick individual checks." },
];

function Opt({
  label,
  hint,
  checked,
  onChange,
  disabled = false,
  danger = false,
  wide = false,
  describedBy,
}: {
  label: string;
  hint?: ReactNode;
  checked: boolean;
  onChange: (on: boolean) => void;
  disabled?: boolean;
  danger?: boolean;
  wide?: boolean;
  /** Lets a reason block elsewhere describe the control. */
  describedBy?: string;
}) {
  return (
    <label className={`opt${danger ? " opt-danger" : ""}${wide ? " opt-wide" : ""}`}>
      <input
        type="checkbox"
        checked={checked}
        disabled={disabled}
        aria-describedby={describedBy}
        onChange={(e) => onChange(e.target.checked)}
      />
      <span>
        <span className="opt-label">{label}</span>
        {hint && <span className="opt-hint">{hint}</span>}
      </span>
    </label>
  );
}

/**
 * The "Run now" panel — the web **fast lane**: a scan level (quick or
 * standard), the two explicit switches (writes and AI), the checks to run, and
 * the authorization gate.
 *
 * The level is a name only. The server expands quick/standard/deep into the
 * passes they imply, with the tenant's entitlement and the deployment's
 * capabilities in view; this panel never sets `fuzz`, `premium` or the heavy
 * passes itself. Deep is shown but disabled: ZAP, the Kali adjuncts and the
 * injection-confirm tools run from the `aidetector` CLI heavy lane, where they
 * also get whitebox source access.
 *
 * The authorization checkbox is a product requirement, not decoration: the API
 * refuses a run without it and this panel keeps the Run button disabled until
 * it is ticked. It is deliberately *local* state, so closing the panel clears
 * it and every run re-confirms authorization. Scope and switches are lifted to
 * the page so re-opening the panel keeps what was already selected.
 *
 * Scope only narrows. A selected check that needs a pass left off (writes,
 * a higher level) still does not run — the panel says so before the run, and
 * the run's `check_skipped` events say so after.
 */
function RunPanelImpl({
  targetUrl,
  options,
  busy,
  onChange,
  onRun,
  onClose,
  closeLabel = "Close",
  showRequestRate = true,
  showResourceIds = true,
  showSeed = true,
  replacesFindings = 0,
  verifiedHost = null,
}: {
  targetUrl: string;
  options: RunOptions;
  busy: boolean;
  onChange: (next: RunOptions) => void;
  onRun: () => void;
  onClose: () => void;
  /** The wizard steps back rather than closing a panel. */
  closeLabel?: string;
  /** The detail page saves this under Scan configuration instead. */
  showRequestRate?: boolean;
  /** Detail pages edit these in the persistent SPEC configuration panel. */
  showResourceIds?: boolean;
  /** Only the seed has no home in the detail page's configuration panels. */
  showSeed?: boolean;
  /** Live findings a new run will replace; the panel says so before the run. */
  replacesFindings?: number;
  /**
   * The host this workspace has proven it owns. The Run button then states the
   * authorization itself instead of a separate checkbox — still one explicit
   * act per run, because pressing a button that says it is the attestation.
   */
  verifiedHost?: string | null;
}) {
  const radioName = useId();
  const levelName = useId();
  const [authorized, setAuthorized] = useState(false);
  const [customising, setCustomising] = useState(() => presetOf(options.checks) === "custom");
  const [customiseOpen, setCustomiseOpen] = useState(
    () => presetOf(options.checks) !== "all",
  );
  const [resourceIdsText, setResourceIdsText] = useState(() =>
    Object.keys(options.predefined_resource_ids ?? {}).length
      ? JSON.stringify(options.predefined_resource_ids, null, 2)
      : "",
  );
  const [resourceIdsError, setResourceIdsError] = useState("");
  const set = (patch: Partial<RunOptions>) => onChange({ ...options, ...patch });

  // Availability is advisory; the run still enforces its own gates.
  const capabilities = useCapabilities();
  const entitlement = capabilities.premium;
  const featureTitleId = useId();
  const passes = capabilities.passes as unknown as Record<
    string,
    { available: boolean; reason: string | null } | undefined
  >;
  const premiumLocked = Boolean(entitlement && !entitlement.available);
  const premiumUnavailable = passes.premium?.available === false;
  const premiumDisabled = premiumLocked || premiumUnavailable;

  // A restored selection with premium on must not stay on when the plan
  // excludes it; the level alone asks the server for premium now.
  useEffect(() => {
    if (capabilities.loading) return;
    if (entitlement && !entitlement.available && options.premium) {
      onChange({ ...options, premium: false });
    }
  }, [capabilities.loading, entitlement, options, onChange]);

  const unavailablePass = (key: string) =>
    passes[key]?.available === false ? passes[key] : undefined;
  const fuzzUnavailable = unavailablePass("fuzz");
  const writesUnavailable = unavailablePass("mutate");

  // The Standard level asks the server for fuzzing and premium; say up front
  // which of those the deployment or the tenant's plan leaves out.
  const standardNotes: string[] = [];
  if (fuzzUnavailable) {
    standardNotes.push(
      `Schema fuzzing is skipped: ${fuzzUnavailable.reason ?? "not available on this deployment"}.`,
    );
  }
  if (premiumDisabled) {
    standardNotes.push(
      `Premium detections are skipped: ${
        premiumLocked
          ? entitlement?.reason ?? "not in this tenant's plan"
          : passes.premium?.reason ?? "not available on this deployment"
      }.`,
    );
  }

  const level = options.level ?? "quick";
  const preset = customising ? "custom" : presetOf(options.checks);
  const chosen = new Set(options.checks.length ? options.checks : ALL_SCOPE_KEYS);
  const selected = SCOPE_GROUPS.flatMap((g) => g.checks).filter((c) => chosen.has(c.key));
  // The level enables fuzzing and premium server-side; score the picker
  // against that, not the (always-false) individual flags.
  // A pass the deployment or the plan leaves out stays off here too, so the
  // picker still says which checks will not run.
  const effectiveOptions: RunOptions = {
    ...options,
    fuzz: options.fuzz || (level !== "quick" && !fuzzUnavailable),
    premium: options.premium || (level !== "quick" && !premiumDisabled),
  };
  const aiUnavailable = unavailablePass("plan");

  const choosePreset = (id: string) => {
    if (id === "custom") {
      setCustomising(true);
      return;
    }
    setCustomising(false);
    const group = SCOPE_GROUPS.find((g) => g.id === id);
    onChange({
      ...withPresetPasses(options, id),
      checks: group ? group.checks.map((c) => c.key) : [],
    });
  };

  // An empty selection would read as "every check", so the last one stays on.
  const applyScope = (next: Set<string>) => {
    if (next.size > 0) set({ checks: normaliseScope(next) });
  };

  const toggleCheck = (key: CheckKey) => {
    const next = new Set(chosen);
    if (next.has(key)) next.delete(key);
    else next.add(key);
    applyScope(next);
  };

  const toggleGroup = (group: ScopeGroup) => {
    const next = new Set(chosen);
    const all = group.checks.every((c) => next.has(c.key));
    for (const c of group.checks) {
      if (all) next.delete(c.key);
      else next.add(c.key);
    }
    applyScope(next);
  };

  const blocked = new Map<Need, number>();
  for (const check of selected) {
    for (const need of unmetNeeds(check, effectiveOptions)) {
      blocked.set(need, (blocked.get(need) ?? 0) + 1);
    }
  }

  const updateResourceIds = (text: string) => {
    setResourceIdsText(text);
    try {
      const parsed: unknown = JSON.parse(text || "{}");
      if (
        !parsed || Array.isArray(parsed) || typeof parsed !== "object" ||
        Object.entries(parsed).some(([key, value]) => !key || typeof value !== "string" || !value)
      ) {
        throw new Error("invalid map");
      }
      setResourceIdsError("");
      set({ predefined_resource_ids: parsed as Record<string, string> });
    } catch {
      setResourceIdsError("Use a JSON object of resource names and IDs.");
    }
  };

  const levelTitle = SCAN_LEVELS.find((l) => l.id === level)?.title ?? "Quick";
  const summary = [
    levelTitle,
    preset === "all"
      ? `All ${ALL_SCOPE_KEYS.length} checks`
      : `${selected.length} of ${ALL_SCOPE_KEYS.length} checks`,
    options.mutate ? "writes to target" : "read-only",
    options.ai && "AI",
  ].filter(Boolean).join(" · ");

  return (
    <div className="specbox">
      {!verifiedHost && (
        <label className="gate">
          <input
            type="checkbox"
            checked={authorized}
            onChange={(e) => setAuthorized(e.target.checked)}
          />
          <span>
            I own, or am explicitly authorized to security-test,{" "}
            <strong>{targetUrl}</strong>.
          </span>
        </label>
      )}

      <section className="run-section">
        <h3 className="run-section-title">Scan level</h3>
        <div className="scope-presets" role="radiogroup" aria-label="Scan level">
          {SCAN_LEVELS.map((l) => (
            <label key={l.id} className="scope-preset">
              <input
                type="radio"
                name={levelName}
                checked={level === l.id}
                disabled={l.cliOnly}
                onChange={() => set({ level: l.id })}
              />
              <span className="scope-preset-title">{l.title}</span>
              <span className="scope-preset-blurb">{l.blurb}</span>
              {l.cliOnly && (
                <span className="opt-hint">CLI only: aidetector URL --level deep</span>
              )}
              {l.id === "standard" && standardNotes.length > 0 && (
                <span className="opt-hint">{standardNotes.join(" ")}</span>
              )}
            </label>
          ))}
        </div>
      </section>

      <section className="run-section">
        <h3 className="run-section-title">
          Switches <span className="muted-sm">neither is ever pre-ticked</span>
        </h3>
        <div className="opt-grid">
          <Opt
            wide
            danger
            label="Test writes — mutates target data"
            hint="BOLA/BFLA-on-write, mass assignment, races and body-sink injection."
            checked={options.mutate}
            onChange={(mutate) => set({ mutate })}
          />
          <Opt
            wide
            label="Use AI — spends tokens"
            hint={
              aiUnavailable
                ? `Skipped on this run — ${aiUnavailable.reason ?? "AI is not available on this deployment"}.`
                : "AI risk plan, verdicts on BOLA/BFLA/SSRF findings and a security design review."
            }
            checked={options.ai}
            onChange={(ai) => set({ ai })}
          />
        </div>
        {options.mutate && (
          <p className="opt-warn">
            The write oracle restores its updates and deletes what it creates, but
            injection payloads sent to POST/PUT/PATCH bodies are <strong>not</strong>{" "}
            cleaned up. Use only against a disposable or staging target.
          </p>
        )}
      </section>

      <details
        className="run-advanced"
        open={customiseOpen}
        onToggle={(e) => setCustomiseOpen(e.currentTarget.open)}
      >
        <summary>Customise checks</summary>
        <div className="scope-presets" role="radiogroup" aria-label="Scan scope">
          {PRESETS.map((p) => (
            <label key={p.id} className="scope-preset">
              <input
                type="radio"
                name={radioName}
                checked={preset === p.id}
                onChange={() => choosePreset(p.id)}
              />
              <span className="scope-preset-title">{p.title}</span>
              <span className="scope-preset-blurb">{p.blurb}</span>
            </label>
          ))}
        </div>

        {preset === "custom" && (
          <div className="scope-picker">
            {SCOPE_GROUPS.map((group) => {
              const on = group.checks.filter((c) => chosen.has(c.key)).length;
              return (
                <fieldset key={group.id} className="scope-group">
                  <legend>
                    <label>
                      <input
                        type="checkbox"
                        checked={on === group.checks.length}
                        ref={(el) => {
                          if (el) el.indeterminate = on > 0 && on < group.checks.length;
                        }}
                        onChange={() => toggleGroup(group)}
                      />
                      {group.title}
                    </label>
                    <span className="muted-sm">{on}/{group.checks.length}</span>
                  </legend>
                  {group.checks.map((check) => {
                    const unmet = unmetNeeds(check, effectiveOptions);
                    return (
                      <label key={check.key} className="scope-check" title={check.key}>
                        <input
                          type="checkbox"
                          checked={chosen.has(check.key)}
                          onChange={() => toggleCheck(check.key)}
                        />
                        <span>{check.label}</span>
                        {(check.needs ?? []).map((need) => (
                          <span
                            key={need}
                            className={`need-tag${unmet.includes(need) ? " is-unmet" : ""}`}
                          >
                            {/* abbr so the tag explains itself on hover, for a reader who
                                has not met the acronym. */}
                            <abbr title={NEED_HINT[need]}>{NEED_TAG[need]}</abbr>
                          </span>
                        ))}
                      </label>
                    );
                  })}
                </fieldset>
              );
            })}
          </div>
        )}

        {preset !== "all" && (
          <p className="muted-sm scope-summary">
            {selected.length} check{selected.length === 1 ? "" : "s"} selected
            {blocked.size > 0 && (
              <span className="is-warn">
                {" — "}
                {[...blocked]
                  .map(([need, n]) => `${n} need${n === 1 ? "s" : ""} ${NEED_OPTION[need]}`)
                  .join(", ")}
                {" and will be skipped."}
              </span>
            )}
          </p>
        )}
      </details>

      <section className="run-section" aria-labelledby={featureTitleId}>
        <h3 className="run-section-title" id={featureTitleId}>
          Feature availability
        </h3>
        <ul className="feat-list">
          <li className="feat-row">
            <span className="feat-name">Test writes</span>
            <span className={`feat-chip ${writesUnavailable ? "unavailable" : "available"}`}>
              {writesUnavailable ? "Unavailable" : "Available"}
            </span>
            {writesUnavailable?.reason && (
              <span className="feat-reason">{writesUnavailable.reason}</span>
            )}
          </li>
        </ul>
        {capabilities.error && (
          <p className="muted-sm">
            Could not check feature availability: {capabilities.error}. Planned work
            will be reported as skipped after the run.
          </p>
        )}
      </section>

      {(showSeed || showRequestRate || showResourceIds) && (
        <details className="run-advanced">
          <summary>Advanced</summary>
          {showSeed && (
            <label className="gate">
              <span>
                Reproducibility seed (optional):{" "}
                <input
                  type="number"
                  min={0}
                  max={2147483647}
                  value={options.seed ?? ""}
                  onChange={(e) => {
                    const value = e.target.value === "" ? null : Number(e.target.value);
                    set({ seed: Number.isInteger(value) ? value : null });
                  }}
                  aria-label="Reproducibility seed"
                />
                <span className="muted-sm">
                  Keep the run manifest seed to replay payload selection. Target state
                  and credentials can still vary.
                </span>
              </span>
            </label>
          )}
          {showRequestRate && (
            <label className="gate">
              <span>
                Request rate for this scan:{" "}
                <select
                  value={options.requests_per_second}
                  onChange={(e) => set({ requests_per_second: Number(e.target.value) })}
                  aria-label="Requests per second"
                >
                  <option value={1}>1 request/second</option>
                  <option value={2}>2 requests/second</option>
                  <option value={5}>5 requests/second</option>
                  <option value={10}>10 requests/second</option>
                  <option value={20}>20 requests/second</option>
                  <option value={50}>50 requests/second</option>
                  <option value={100}>100 requests/second</option>
                </select>{" "}
                <span className="muted-sm">
                  Caps the core scanner; above 10/second only against targets you know
                  can take it. The deployment may enforce a lower ceiling. The write-only
                  race check may send one bounded 6-request burst.
                </span>
              </span>
            </label>
          )}
          {showResourceIds && (
            <label className="gate">
              <span>
                Predefined resource IDs. Use singular resource names matching path
                parameters, for example <code>{'{"merchant":"merchant_123"}'}</code>.
                Values are used for dependent paths and are not written to reports.
                <textarea
                  value={resourceIdsText}
                  onChange={(e) => updateResourceIds(e.target.value)}
                  rows={3}
                  spellCheck={false}
                  placeholder="None — the run creates the resources it needs."
                  aria-label="Predefined resource IDs as JSON"
                  aria-invalid={Boolean(resourceIdsError)}
                />
                {resourceIdsError && <span className="field-error">{resourceIdsError}</span>}
              </span>
            </label>
          )}
        </details>
      )}

      {replacesFindings > 0 && (
        <p className="opt-warn run-replaces">
          Running again replaces the current {replacesFindings} finding{replacesFindings === 1 ? "" : "s"} with
          this run&apos;s results. Your verdicts carry over to findings that come back, and the
          previous run stays in Run history for comparison.
        </p>
      )}
      <div className="actions">
        <span className="muted-sm run-summary">{summary}</span>
        <button
          className="btn"
          onClick={onRun}
          disabled={busy || !(authorized || verifiedHost) || Boolean(resourceIdsError)}
        >
          {busy && <span className="spinner" aria-hidden="true" />}
          {busy
            ? "Queueing…"
            : verifiedHost
              ? `I'm authorized — run scan on ${verifiedHost}`
              : "Run scan"}
        </button>
        <button className="btn quiet" onClick={onClose} disabled={busy}>
          {closeLabel}
        </button>
      </div>
    </div>
  );
}

export const RunPanel = memo(RunPanelImpl);
