"use client";

import { useRef, useState } from "react";
import {
  GROUPS,
  apiCoverage,
  type Check,
  type Confidence,
} from "@/lib/coverage";
import { useUrlState } from "@/lib/useUrlState";
import { Select } from "./Select";
import { COVERAGE_LABELS } from "@/lib/coverageLabels";
import { TierChip } from "./TierChip";
import styles from "./CoverageExplorer.module.css";

const LABELS: Record<Confidence, string> = {
  verified: "Verified",
  heuristic: "Lead",
  planned: "Planned",
};
const TOTAL = GROUPS.reduce((sum, group) => sum + group.checks.length, 0);

function matches(
  check: Check,
  query: string,
  evidence: string,
  risk: string,
  plan: string,
) {
  return (
    (!evidence || check.confidence === evidence) &&
    (!risk || check.owasp === risk) &&
    (!plan || (plan === "premium" ? check.premium : !check.premium)) &&
    query
      .toLowerCase()
      .trim()
      .split(/\s+/)
      .every((term) =>
        `${check.name} ${check.key ?? ""} ${check.signal} ${check.caveat ?? ""} ${check.owasp ?? ""}`
          .toLowerCase()
          .includes(term),
      )
  );
}

/** The bounded, local catalogue stays sourced from the engine coverage mirror. */
export function CoverageExplorer() {
  const { get, set } = useUrlState();
  const input = useRef<HTMLInputElement>(null);
  const [draft, setDraft] = useState<string | null>(null);
  const query = draft ?? get("q") ?? "";
  const evidence = get("evidence") ?? "";
  const risk = get("risk") ?? "";
  const plan = get("plan") ?? "";
  const groups = GROUPS.map((group) => ({
    ...group,
    checks: group.checks.filter((check) =>
      matches(check, query, evidence, risk, plan),
    ),
  })).filter((group) => group.checks.length);
  const shown = groups.reduce((sum, group) => sum + group.checks.length, 0);
  const filtered = Boolean(query || evidence || risk || plan);

  function clearAll() {
    setDraft(null);
    set({ q: null, evidence: null, risk: null, plan: null });
    input.current?.focus();
  }

  return (
    <div className={styles.explorer}>
      <div className={styles.filters} role="search" aria-label="Test catalogue">
        <div className={styles.search}>
          <label htmlFor="coverage-query">Search checks</label>
          <div className={styles.searchInput}>
            <input
              id="coverage-query"
              ref={input}
              type="search"
              value={query}
              placeholder="Try BOLA, tokens, headers…"
              onCompositionStart={() => setDraft(query)}
              onCompositionEnd={(event) => {
                setDraft(null);
                set({ q: event.currentTarget.value });
              }}
              onChange={(event) => {
                if (draft !== null) setDraft(event.target.value);
                else set({ q: event.target.value });
              }}
            />
            {query && (
              <button
                type="button"
                aria-label="Clear search"
                onClick={() => {
                  setDraft(null);
                  set({ q: null });
                  input.current?.focus();
                }}
              >
                ×
              </button>
            )}
          </div>
        </div>
        <Select
          label="Evidence"
          value={evidence}
          onChange={(value) => set({ evidence: value })}
          options={[
            { value: "", label: "All evidence" },
            { value: "verified", label: "Verified" },
            { value: "heuristic", label: "Leads" },
            { value: "planned", label: "Planned" },
          ]}
        />
        <Select
          label="Risk area"
          value={risk}
          onChange={(value) => set({ risk: value })}
          options={[
            { value: "", label: "All risk areas" },
            ...apiCoverage().map((area) => ({
              value: area.code,
              label: `${area.code.split(":")[0]} · ${COVERAGE_LABELS[area.code] ?? area.name}`,
              description: area.name,
            })),
          ]}
        />
        <Select
          label="Plan"
          value={plan}
          onChange={(value) => set({ plan: value })}
          options={[
            { value: "", label: "All plans" },
            { value: "free", label: "Free" },
            { value: "premium", label: "Premium" },
          ]}
        />
      </div>
      <div className={styles.resultBar}>
        <span role="status">
          {shown} of {TOTAL} signals{filtered ? " match" : " in the catalogue"}
        </span>
        {filtered && (
          <button type="button" className="btn quiet sm" onClick={clearAll}>
            Clear filters
          </button>
        )}
      </div>
      {shown === 0 ? (
        <div className="empty">
          <h3>No matching checks</h3>
          <p>Try another term or clear the filters to see every signal.</p>
          <button type="button" className="btn quiet" onClick={clearAll}>
            Show all checks
          </button>
        </div>
      ) : (
        groups.map((group) => (
          <details
            className={styles.group}
            key={group.title}
            open={filtered || undefined}
          >
            <summary className={styles.groupHead}>
              <span>{group.title}</span>
              <span>
                {group.checks.length} signal
                {group.checks.length === 1 ? "" : "s"}
              </span>
            </summary>
            {group.checks.map((check) => (
              <details className={styles.check} key={check.name}>
                <summary>
                  <span className={styles.name}>{check.name}</span>
                  <span className={styles.badges}>
                    <TierChip tier={check.confidence}>
                      {LABELS[check.confidence]}
                    </TierChip>
                    {check.premium && (
                      <TierChip tier="premium">Premium</TierChip>
                    )}
                    {check.owasp && (
                      <span className={styles.owasp}>{check.owasp}</span>
                    )}
                  </span>
                </summary>
                <div className={styles.checkBody}>
                  <h4>What we observe</h4>
                  <p>{check.signal}</p>
                  {check.caveat && (
                    <>
                      <h4>Limits &amp; prerequisites</h4>
                      <p>{check.caveat}</p>
                    </>
                  )}
                  <p className={styles.source}>
                    Implementation reference: <code>{check.source}</code>
                  </p>
                </div>
              </details>
            ))}
          </details>
        ))
      )}
    </div>
  );
}
