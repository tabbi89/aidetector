import Link from "next/link";
import { GROUPS } from "@/lib/coverage";
import styles from "./PlanComparison.module.css";

const ACTIVE = GROUPS.flatMap((group) => group.checks).filter(
  (check) => check.confidence !== "planned",
);
const PREMIUM_CHECKS = ACTIVE.filter((check) => check.premium).length;
const FREE_CHECKS = ACTIVE.length - PREMIUM_CHECKS;
const FREE = [
  {
    t: `${FREE_CHECKS} core detections`,
    d: "The OWASP API Top 10 checks: access between accounts, admin actions, authentication, injection leads, data exposure, headers and TLS.",
  },
  {
    t: "Schema fuzzing and test writes",
    d: "The Standard level adds fuzzing in local CLI runs. Test writes enables create/update authorization, mass assignment and race checks. Some probes attempt cleanup; body-injection writes are not cleaned up.",
  },
  {
    t: "AI passes",
    d: "A risk plan, verdicts on BOLA/BFLA/SSRF findings and a security design review — when the server has an AI key. Tokens are counted per scan.",
  },
  {
    t: "Deep scans",
    d: "ZAP, the Kali tools, sqlmap / dalfox / commix / tplmap confirmation and a testssl audit, inside their own time budget.",
  },
  {
    t: "Local runs, code and CI",
    d: "Traffic from your machine, file:line evidence from your source, the bounded agent, runpentests.yml, runpentests mcp and the CI gate.",
  },
  {
    t: "Results and history",
    d: "Findings, request log, endpoint coverage, triage and run-to-run changes from local CLI runs. PDF, HTML, JSON and SARIF exports.",
  },
];

const PREMIUM = [
  {
    t: "Web scans and schedules",
    d: "Run scans from the browser using the service's worker, or schedule recurring scans. All three scan levels are available. Free workspaces run locally with the CLI and review their results in the web.",
  },
  {
    t: `${PREMIUM_CHECKS} premium detections`,
    d: "JWT key confusion, GraphQL and gRPC exposure, host-header injection, request smuggling, sustained rate limits, an API design review, and callback-confirmed XXE, deserialization and upstream API checks. Callback checks need an OAST service; some also need Test writes.",
  },
  {
    t: "Adaptive validation & resource refinement",
    d: "At the Deep level with AI on, in the browser or CLI: try bounded input variants, and let AI fix rejected setup requests. The runner asks the service to run these, so no model keys are needed on your machine. Refinement also needs Test writes.",
  },
  {
    t: "Pentest report",
    d: "A pentest-grade Markdown deliverable with an executive summary, attack paths and per-finding detail.",
  },
  {
    t: "Ask your scan",
    d: "Ask questions about a scan’s findings in plain language. Answers are commentary on the evidence, never evidence.",
  },
  {
    t: "Assignment & discussion",
    d: "Give each finding an owner and a due date, and discuss it with your team on the finding itself.",
  },
  {
    t: "Database schema context",
    d: "Table structure read by a local run from a schema: block in runpentests.yml, given to the AI passes. Structure only — the password never leaves your machine.",
  },
];

const PLANS = [
  {
    id: "free",
    title: "Free",
    status: "Included in every workspace",
    description: "Run locally with the CLI. Review evidence in the web.",
    features: [
      "Schema fuzzing & optional test writes",
      "Optional AI planning & review",
      "Deep scans with configured tools",
      "Local CLI runs, source context & CI",
      "Results, history & standard exports",
    ],
    action: "Set up a Free scan",
    href: "/scans/new",
    details: FREE,
  },
  {
    id: "premium",
    title: "Premium",
    status: "Everything in Free, plus",
    description: "Add advanced tests and tools for your team.",
    features: [
      "Run from the web & schedule scans",
      "Adaptive AI validation & resource refinement",
      "Pentest report in Markdown",
      "Ask questions about your scan",
      "Finding owners, due dates & discussion",
      "Database schema context for local runs",
    ],
    action: "Explore Premium checks",
    href: "/coverage?plan=premium#check-details",
    details: PREMIUM,
  },
];

/** Plan entitlements are unchanged; writes and token-spending remain opt-ins. */
export function PlanComparison() {
  return (
    <section
      className={`wrap section ${styles.section}`}
      id="plans"
      aria-labelledby="plans-heading"
    >
      <div className={styles.heading}>
        <span className={styles.eyebrow}>Workspace plans</span>
        <h2 id="plans-heading">Start Free. Go deeper with Premium.</h2>
        <p>
          One scanner, in your browser or terminal. Choose the tools your
          workspace needs.
        </p>
      </div>
      <div className={styles.cards}>
        {PLANS.map((plan) => (
          <article
            key={plan.id}
            className={`${styles.card} ${plan.id === "premium" ? styles.premium : ""}`}
            aria-labelledby={`${plan.id}-plan-title`}
          >
            <div className={styles.planTitle}>
              <span className={styles.icon} aria-hidden="true">
                {plan.id === "premium" ? (
                  <svg
                    viewBox="0 0 24 24"
                    fill="none"
                    stroke="currentColor"
                    strokeWidth="1.5"
                  >
                    <path d="m12 3 9 9-9 9-9-9 9-9Z" />
                    <path d="M8 12h8m-4-4v8" />
                  </svg>
                ) : (
                  <svg
                    viewBox="0 0 24 24"
                    fill="none"
                    stroke="currentColor"
                    strokeWidth="1.5"
                    strokeLinecap="round"
                    strokeLinejoin="round"
                  >
                    <path d="m8 7-5 5 5 5m8-10 5 5-5 5m-3-12-2 18" />
                  </svg>
                )}
              </span>
              <h3 id={`${plan.id}-plan-title`}>{plan.title}</h3>
            </div>
            <p className={styles.status}>{plan.status}</p>
            <p className={styles.description}>{plan.description}</p>
            <div className={styles.signalSummary}>
              {plan.id === "premium" ? (
                <>
                  <span className={styles.inherited}>{FREE_CHECKS}</span>
                  <span className={styles.plus}>+</span>
                  <strong>{PREMIUM_CHECKS}</strong>
                  <span className={styles.signalLabel}>
                    core + premium
                    <br />
                    test signals
                  </span>
                </>
              ) : (
                <>
                  <strong>{FREE_CHECKS}</strong>
                  <span className={styles.signalLabel}>
                    core test signals
                    <br />
                    <span>Included with Free</span>
                  </span>
                </>
              )}
            </div>
            <ul className={styles.features}>
              {plan.features.map((feature) => (
                <li key={feature}>
                  <svg viewBox="0 0 16 16" fill="none" aria-hidden="true">
                    <path
                      d="m3 8 3 3 7-7"
                      stroke="currentColor"
                      strokeWidth="1.7"
                      strokeLinecap="round"
                      strokeLinejoin="round"
                    />
                  </svg>
                  <span>{feature}</span>
                </li>
              ))}
            </ul>
            <Link
              className={`btn ${plan.id === "free" ? "quiet" : styles.premiumAction} ${styles.action}`}
              href={plan.href}
            >
              {plan.action}
              <span aria-hidden="true">→</span>
            </Link>
          </article>
        ))}
      </div>
      <p className={styles.guardrail}>
        <span aria-hidden="true">↳</span> Your plan unlocks features. You
        control each run.
        <span>
          Writes change target data. AI spends tokens. Both are opt-in.
        </span>
      </p>
      <details className={styles.details}>
        <summary>
          Compare all included features <span aria-hidden="true">+</span>
        </summary>
        <div className={styles.detailGrid}>
          {PLANS.map((plan) => (
            <div key={plan.id}>
              <h3>
                {plan.title}
                {plan.id === "premium" && <span> · additions to Free</span>}
              </h3>
              <dl>
                {plan.details.map((item) => (
                  <div key={item.t}>
                    <dt>{item.t}</dt>
                    <dd>{item.d}</dd>
                  </div>
                ))}
              </dl>
            </div>
          ))}
        </div>
        <p className={styles.availability}>
          Standard and Deep include premium detections when your plan allows
          them. Checks depend on target prerequisites and configured tools;
          unavailable checks are recorded as skipped.
        </p>
        <Link href="/coverage#premium-tier" className="link-arrow">
          Premium prerequisites and setup →
        </Link>
      </details>
    </section>
  );
}
