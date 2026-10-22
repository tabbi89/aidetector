"use client";

import { useId, useState } from "react";
import { TierChip } from "./TierChip";
import styles from "./EvidenceGuide.module.css";

const EXAMPLES = [
  {
    id: "access",
    label: "Wrong account",
    tier: "verified",
    badge: "Verified weakness",
    title: "An order crosses the account boundary.",
    actor: "Bob’s test account",
    request: "GET /orders/42",
    observation: "Alice’s private order returned",
    signal: "Bob receives Alice’s order",
    outcome: "Review the object’s access rules",
    detail:
      "In this example, the scanner created Alice’s order, ruled out public access, then read its unique marker as Bob. That demonstrates cross-account access.",
    needs: "Needs two accounts and Test writes for this create-and-read check.",
  },
  {
    id: "input",
    label: "Risky input",
    tier: "heuristic",
    badge: "Lead to investigate",
    title: "Attack-like text comes back unchanged.",
    actor: "Attack-like input",
    request: "GET /search?q=…",
    observation: "Input echoed in the response",
    signal: "Reflection observed",
    outcome: "Investigate before treating it as a bug",
    detail:
      "An intact payload in a response shows where input travels. It does not prove that a database or command interpreter executed it.",
    needs: "GET query probes do not need Test writes. Body probes do.",
  },
  {
    id: "gap",
    label: "Skipped check",
    tier: null,
    badge: "Not tested",
    title: "A missing prerequisite leaves a gap.",
    actor: "One test account",
    request: "Cross-account check",
    observation: "Second account unavailable",
    signal: "Cross-account proof unavailable",
    outcome: "Add another account and run again",
    detail:
      "Without a second identity, this cross-account check cannot establish an access boundary. A skipped check is untested, even if the scan has no findings.",
    needs: "Your scan’s Endpoint coverage and gaps explain what actually ran.",
  },
] as const;

/** Teaching examples only: these controls never make scanner requests. */
export function EvidenceGuide() {
  const [selected, setSelected] = useState(0);
  const id = useId();
  const example = EXAMPLES[selected];

  return (
    <div className={styles.guide}>
      <div className={styles.toolbar}>
        <div
          className={styles.choices}
          role="group"
          aria-label="Evidence examples"
        >
          {EXAMPLES.map((item, index) => (
            <button
              key={item.id}
              type="button"
              aria-pressed={selected === index}
              aria-controls={id}
              onClick={() => setSelected(index)}
            >
              {item.label}
            </button>
          ))}
        </div>
        <span className={styles.example}>
          Illustrative example · no requests sent
        </span>
      </div>
      <div id={id} className={styles.canvas}>
        <div className={styles.heading}>
          <h3>{example.title}</h3>
          {example.tier ? (
            <TierChip tier={example.tier}>{example.badge}</TierChip>
          ) : (
            <span className={styles.gap}>— {example.badge}</span>
          )}
        </div>
        <ol className={styles.flow} aria-label="Request and observation">
          <li>
            <span>Send as</span>
            <strong>{example.actor}</strong>
          </li>
          <li>
            <span>Request</span>
            <code>{example.request}</code>
          </li>
          <li>
            <span>Observe</span>
            <strong>{example.observation}</strong>
          </li>
        </ol>
        <div
          className={`${styles.verdict} ${example.tier === "verified" ? styles.proof : example.tier === "heuristic" ? styles.lead : ""}`}
        >
          <span className={styles.mark} aria-hidden="true">
            {example.tier === "verified"
              ? "✓"
              : example.tier === "heuristic"
                ? "?"
                : "—"}
          </span>
          <div>
            <strong>{example.signal}</strong>
            <span>{example.outcome}</span>
          </div>
        </div>
        <p className={styles.detail}>{example.detail}</p>
        <p className={styles.needs}>{example.needs}</p>
      </div>
    </div>
  );
}
