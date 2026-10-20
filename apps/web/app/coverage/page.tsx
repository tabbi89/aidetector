import type { Metadata } from "next";
import Link from "next/link";
import {
  AI_CASCADE,
  CONFIDENCE_HELP,
  CONFIDENCE_LABEL,
  COVERAGE_LEVEL_LABEL,
  DISCLOSURE_HEADERS,
  GROUPS,
  HEADER_POLICY,
  HEADERS_NOT_SWEPT,
  LIMITS,
  NOT_COVERED,
  OWASP_2025,
  PREMIUM_HELP,
  PREMIUM_LABEL,
  type Confidence,
} from "@/lib/coverage";
import { SectionLabel } from "../components/SectionLabel";
import { TierChip } from "../components/TierChip";
import { CoverageOverview } from "../components/CoverageOverview";
import {
  AdaptiveValidationGraph,
  ApiCoverageMatrix,
  CheckMechanisms,
  ResourceLifecycleGraph,
  TestingFlowGraph,
} from "../components/Flow";

export const metadata: Metadata = {
  title: "Coverage",
  description:
    "Exactly which vulnerability classes the runpentests engine tests for, how each one is detected, and what it does not cover.",
};

const ORDER: Confidence[] = ["verified", "heuristic", "planned"];

const ALL = GROUPS.flatMap((g) => g.checks);
const count = (c: Confidence) => ALL.filter((x) => x.confidence === c).length;

/* "planned" is documented but not implemented, so it is never counted as
   coverage — the same rule the landing page's stats follow. */
const ACTIVE = ALL.filter((c) => c.confidence !== "planned").length;
const ACTIVE_GROUPS = GROUPS.filter((g) =>
  g.checks.some((c) => c.confidence !== "planned"),
).length;

const TALLY = [
  { n: ACTIVE, k: "implemented signals", s: `across ${ACTIVE_GROUPS} families` },
  { n: count("verified"), k: "verified", s: "evidence demonstrates it" },
  { n: count("heuristic"), k: "leads", s: "signals that need investigation" },
  { n: count("planned"), k: "planned", s: "documented, not implemented" },
];

export default function Coverage() {
  const tiers = ORDER.filter((c) => count(c) > 0);

  return (
    <>
      <section className="cov-head">
        <div className="wrap cov-head-inner">
          <div className="hero-kicker">
            <span>Test coverage</span>
            <i className="dot-sep" aria-hidden="true" />
            <span>A beginner’s guide</span>
          </div>
          <h1>Understand what we can test in your API.</h1>
          <p className="lead">
            Can the wrong person see your data? Does your API reveal secrets or
            accept risky input? Start with the visual guide below, then explore
            the exact checks, evidence and limits. This is what the scanner can
            test; your scan’s Endpoint coverage shows what actually ran.
          </p>
          <p className="cov-xref">
            <Link className="link-arrow" href="/#decide">
              See how each signal is produced →
            </Link>
          </p>
        </div>
      </section>

      <CoverageOverview />

      <div className="stats-band">
        <div className="wrap">
          <dl className="stats">
            {TALLY.map((t) => (
              <div className="stat" key={t.k}>
                <dt>{t.n}</dt>
                <dd>
                  <b>{t.k}</b>
                  <span>{t.s}</span>
                </dd>
              </div>
            ))}
          </dl>
        </div>
      </div>

      <section className="wrap section">
        <SectionLabel>Coverage at a glance</SectionLabel>
        <div className="cov-lead">
          <div>
            <h2 className="h-lg">The OWASP API Top 10, by evidence tier</h2>
            <p className="lead">
              One cell per family in the OWASP API Security Top 10 (2023) — the
              list this scanner is built around — coloured by the strongest
              evidence a check for it produces. Derived from the same registry
              the cards below come from, so it can never drift from what the
              engine actually runs.
            </p>
          </div>
          <span className="mono muted-sm">API1 – API10</span>
        </div>
        <ApiCoverageMatrix />
      </section>

      <section className="wrap section">
        <SectionLabel>Reading a tier</SectionLabel>
        <div className="legend">
          {tiers.map((c) => (
            <div className="legend-item" key={c}>
              <TierChip tier={c}>{CONFIDENCE_LABEL[c]}</TierChip>
              <span className="legend-help">{CONFIDENCE_HELP[c]}</span>
            </div>
          ))}
          <div className="legend-item">
            <TierChip tier="premium">{PREMIUM_LABEL}</TierChip>
            <span className="legend-help">{PREMIUM_HELP}</span>
          </div>
        </div>
      </section>

      <section className="wrap section" id="premium-tier">
        <SectionLabel>The premium tier</SectionLabel>
        <div className="split">
          <div>
            <h2 className="h-lg">What premium unlocks, and how it is enabled</h2>
            <p className="lead">
              Premium is a <strong>per-tenant plan</strong>, not a run setting.
              A premium pass on a free tenant does not run the premium checks —
              the run records them as skipped, and the pentest report answers
              402 — so a locked feature never reads as a clean result.
            </p>
            <p className="lead">{PREMIUM_HELP}</p>
          </div>
          <ul className="ruled">
            <li>
              <span className="t">Premium detections</span>
              <p>
                Host-header/vhost probing, JWT key confusion, GraphQL and gRPC
                exposure, request smuggling, XXE/deserialization confirmation,
                sustained rate limits and the spec design review. Selected with
                the premium pass; only the plan makes it run.
              </p>
            </li>
            <li>
              <span className="t">Pentest report</span>
              <p>
                The pentest-grade Markdown deliverable — executive summary,
                attack paths and per-finding detail. The PDF, HTML and JSON
                exports stay available on every plan.
              </p>
            </li>
            <li>
              <span className="t">Ask your scan</span>
              <p>
                Natural-language questions about a scan&apos;s findings. Tokens
                are metered per scan, and the answer is commentary on evidence,
                never evidence itself.
              </p>
            </li>
          </ul>
        </div>
        <p className="muted-sm" style={{ marginTop: 18 }}>
          <strong>To enable it:</strong> a deployment operator adds this tenant
          to the premium plan (the <code className="mono">premium_tenants</code>{" "}
          setting today), then reload the page so the UI re-reads
          entitlement. The API enforces the same boundary; the checkbox is not
          the gate.
        </p>
      </section>

      <section className="wrap section" id="check-details">
        <SectionLabel>The checks</SectionLabel>
        {GROUPS.map((g) => (
          <div className="cov-group" key={g.title}>
            <div className="cov-group-head">
              <h2>{g.title}</h2>
              <span className="count">
                {g.checks.length} check{g.checks.length === 1 ? "" : "s"}
              </span>
            </div>
            <p className="cov-blurb">{g.blurb}</p>

            <div className="cov-grid">
              {g.checks.map((c) => (
                <article className="cov-card" key={c.name}>
                  <div className="cov-badges">
                    <TierChip tier={c.confidence}>
                      {CONFIDENCE_LABEL[c.confidence]}
                    </TierChip>
                    {c.premium && (
                      <TierChip tier="premium">{PREMIUM_LABEL}</TierChip>
                    )}
                    {c.owasp && <span className="owasp">{c.owasp}</span>}
                  </div>
                  <h3>{c.name}</h3>
                  <p className="cov-signal">{c.signal}</p>
                  {c.caveat && (
                    <p className="cov-caveat">
                      <span className="k">Caveat · </span>
                      {c.caveat}
                    </p>
                  )}
                  <div className="cov-src">{c.source}</div>
                </article>
              ))}
            </div>
          </div>
        ))}
      </section>

      <section className="band">
        <div className="wrap">
          <SectionLabel>How a check proves it</SectionLabel>
          <div className="cov-lead">
            <div>
              <h2 className="h-lg">Four mechanisms, drawn</h2>
              <p className="lead">
                A finding is only as good as the mechanism behind it. These are
                the proof mechanisms the tier labels stand on — the
                cross-identity write oracle, and the three newest checks — each
                showing the exact observation that turns a probe into evidence.
              </p>
            </div>
            <span className="mono muted-sm">engine/checks/</span>
          </div>
          <CheckMechanisms />
        </div>
      </section>

      <section className="band">
        <div className="wrap">
          <SectionLabel>Adaptive validation, visually</SectionLabel>
          <div className="split adaptive-explainer">
            <div>
              <h2 className="h-lg">Why GET and body testing have different gates</h2>
              <p className="lead">
                A GET query or path variant can be tested without changing
                server state. A JSON body variant can create, update, or trigger
                application behavior, so the same bounded loop is available
                only when <strong>writes</strong> are explicitly turned on.
                The planner can choose a next prevalidated variant, but the
                engine owns the method, field, budget, and evidence.
              </p>
            </div>
            <AdaptiveValidationGraph />
          </div>
        </div>
      </section>

      <section className="band">
        <div className="wrap">
          <SectionLabel>Resource lifecycle and the testing flow, visually</SectionLabel>
          <div className="split adaptive-explainer">
            <div>
              <h2 className="h-lg">The resource loop, end to end</h2>
              <p className="lead">
                Supply an existing resource ID, or let the engine try a safe,
                deterministic body first. With <strong>authorized</strong>,{" "}
                <strong>writes</strong>, <strong>premium:true</strong>, and
                the separate refinement switch approved, a 400, 409, or 422 can
                feed a redacted response plus read-only DB schema metadata into
                a maximum of two or three create attempts. A successful ID is
                reused by later tests.
              </p>
            </div>
            <ResourceLifecycleGraph />
          </div>
          <div className="split adaptive-explainer" style={{ marginTop: 32 }}>
            <div>
              <h2 className="h-lg">How a test flows</h2>
              <p className="lead">
                Selection, payload, request and evidence — with the decision kept
                apart from the observed result. The engine owns the method, field,
                budget and gates; the planner only proposes. Every write appears
                in the run&apos;s value-free structural log, without credentials,
                rendered IDs, scalar body values, response text, or database rows.
              </p>
            </div>
            <TestingFlowGraph />
          </div>
        </div>
      </section>

      <section className="band">
        <div className="wrap">
          <SectionLabel>Response headers</SectionLabel>
          <div className="cov-lead">
            <div>
              <h2 className="h-lg">Header by header</h2>
              <p className="lead">
                Every header the per-endpoint sweep scores. Where a bad value is
                listed the check reads the value as well as the presence,
                because a header set to a value that permits everything buys
                nothing. Severities are scaled for a JSON API rather than a
                browser-rendered site.
              </p>
            </div>
            <span className="mono muted-sm">
              {HEADER_POLICY.length} headers
            </span>
          </div>

          <div className="hdr-scroll">
            <table className="hdr-table">
              <thead>
                <tr>
                  <th scope="col">Header</th>
                  <th scope="col">Severity</th>
                  <th scope="col">Why it matters</th>
                  <th scope="col">Good value</th>
                  <th scope="col">Flagged when</th>
                </tr>
              </thead>
              <tbody>
                {HEADER_POLICY.map((h) => (
                  <tr key={h.header}>
                    <td className="hdr-name">{h.header}</td>
                    <td>
                      <span className={`sev-badge ${h.severity}`}>
                        {h.severity}
                      </span>
                    </td>
                    <td>{h.purpose}</td>
                    <td className="hdr-good">{h.good}</td>
                    <td className="hdr-flag">
                      {h.bad ??
                        "Absent (presence only — the value space is too open-ended to score generically)"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <div className="split" style={{ marginTop: 56 }}>
            <div>
              <h2 className="h-lg">Flagged for being present</h2>
              <p className="lead">
                The disclosure half of the same sweep — headers that should not
                be on a response at all. Low severity.
              </p>
            </div>
            <ul className="ruled">
              {DISCLOSURE_HEADERS.map((d) => (
                <li key={d}>{d}</li>
              ))}
            </ul>
          </div>

          <div className="split">
            <div>
              <h2 className="h-lg">Deliberately not scored</h2>
              <p className="lead">
                Two headers from the usual published checklists that this sweep
                leaves alone, and why.
              </p>
            </div>
            <ul className="ruled">
              {HEADERS_NOT_SWEPT.map((h) => (
                <li key={h.header}>
                  <span className="t">{h.header}</span>
                  <p>{h.why}</p>
                </li>
              ))}
            </ul>
          </div>
        </div>
      </section>

      <section className="wrap section">
        <SectionLabel>Cross-walk</SectionLabel>
        <div className="split">
          <div>
            <h2 className="h-lg">OWASP Top 10:2025</h2>
            <p className="lead">
              An API-first scanner built around the OWASP{" "}
              <strong>API Security Top 10 (2023)</strong> — the per-check codes
              above use those. This is the honest cross-walk to the{" "}
              <strong>Top 10:2025</strong> web-app list: no black-box active
              scanner fully supports it, and several categories are not
              observable from the outside.
            </p>
          </div>
          <ul className="ruled">
            {OWASP_2025.map((o) => (
              <li key={o.code}>
                <div className="owasp-head">
                  <span className="owasp-code">{o.code}</span>
                  <span className="owasp-name">{o.name}</span>
                  <span className={`lvl-badge ${o.level}`}>
                    {COVERAGE_LEVEL_LABEL[o.level]}
                  </span>
                </div>
                <p className="owasp-note">{o.note}</p>
              </li>
            ))}
          </ul>
        </div>
      </section>

      <section className="band">
        <div className="wrap">
          <SectionLabel>How AI is used</SectionLabel>
          <div className="split">
            <div>
              <h2 className="h-lg">Opt-in, and never load-bearing</h2>
              <p className="lead">{AI_CASCADE.blurb}</p>
            </div>
            <ol className="rail">
              {AI_CASCADE.steps.map((s) => (
                <li key={s.k}>
                  <div>
                    <h3>{s.k}</h3>
                    <p>{s.v}</p>
                  </div>
                </li>
              ))}
            </ol>
          </div>
        </div>
      </section>

      <section className="wrap section" id="coverage-gaps">
        <SectionLabel>The gaps</SectionLabel>
        <div className="split">
          <div>
            <h2 className="h-lg">Not covered</h2>
            <p className="lead">
              Classes a commercial API scanner typically advertises that this
              engine does <strong>not</strong> test for. Listed so the gap is
              explicit rather than assumed.
            </p>
          </div>
          <ul className="ruled">
            {NOT_COVERED.map((n) => (
              <li key={n}>{n}</li>
            ))}
          </ul>
        </div>
      </section>

      <section className="wrap section">
        <SectionLabel>Engine limits</SectionLabel>
        <div className="split">
          <div>
            <h2 className="h-lg">What bounds a scan</h2>
            <p className="lead">
              The constraints that decide how deep any single run can go — most
              of them deliberate.
            </p>
          </div>
          <ol className="rail quiet">
            {LIMITS.map((l) => (
              <li key={l}>
                <span>{l}</span>
              </li>
            ))}
          </ol>
        </div>
      </section>
    </>
  );
}
