import { GuideNav } from "../components/GuideNav";
import type { Metadata } from "next";
import Link from "next/link";
import {
  AI_CASCADE,
  COVERAGE_LEVEL_LABEL,
  DISCLOSURE_HEADERS,
  HEADER_POLICY,
  HEADERS_NOT_SWEPT,
  LIMITS,
  NOT_COVERED,
  OWASP_2025,
  PREMIUM_HELP,
} from "@/lib/coverage";
import { GuideHero } from "../components/GuideHero";
import { SectionLabel } from "../components/SectionLabel";
import { TierChip } from "../components/TierChip";
import { CoverageOverview } from "../components/CoverageOverview";
import { CoverageExplorer } from "../components/CoverageExplorer";
import { EvidenceGuide } from "../components/EvidenceGuide";
import {
  AdaptiveValidationGraph,
  CheckMechanisms,
  ResourceLifecycleGraph,
  TestingFlowGraph,
} from "../components/Flow";

export const metadata: Metadata = {
  title: "Coverage",
  description:
    "Explore API security checks, learn the difference between proof and leads, and see the scanner’s limits.",
};

export default function Coverage() {
  return (
    <>
      <GuideHero kind="coverage" />
      <GuideNav
        label="Coverage sections"
        sections={[
          { id: "evidence-guide", label: "Read the evidence" },
          { id: "coverage-summary", label: "Risk areas" },
          { id: "check-details", label: "Explore checks" },
          { id: "coverage-gaps", label: "Known gaps" },
          { id: "technical-guide", label: "Technical reference" },
        ]}
      />
      <section
        className="wrap section"
        id="evidence-guide"
        aria-labelledby="evidence-title"
      >
        <SectionLabel>Learn by example</SectionLabel>
        <h2 className="h-lg" id="evidence-title">
          Three outcomes. Three different next steps.
        </h2>
        <p className="lead home-intro">
          Severity says how serious. Evidence says how certain. A skipped test
          says neither.
        </p>
        <EvidenceGuide />
      </section>
      <CoverageOverview />
      <section
        className="wrap section"
        id="check-details"
        aria-labelledby="checks-title"
      >
        <SectionLabel>The catalogue</SectionLabel>
        <h2 className="h-lg" id="checks-title">
          Find the checks that matter to you.
        </h2>
        <p className="lead">
          Search by risk or endpoint behavior, or open a family to browse. Each
          check includes its exact signal and limits.
        </p>
        <CoverageExplorer />
      </section>
      <div className="wrap guide-reference" id="technical-guide">
        <h2 className="h-lg">Go deeper when you need to.</h2>
        <p className="hint">
          Mechanisms, prerequisites and implementation details. Your scan’s
          Endpoint coverage shows what actually ran.
        </p>
        <details className="guide-disclosure" id="premium-tier">
          <summary>
            <span>Premium features &amp; prerequisites</span>
            <span className="muted-sm">Plan and run options</span>
          </summary>
          <div className="guide-disclosure-body">
            {" "}
            <div className="split">
              <div>
                <h2 className="h-lg">
                  What premium unlocks, and how it is enabled
                </h2>
                <p className="lead">
                  Premium is a <strong>per-tenant plan</strong>, not a run
                  setting. A premium pass on a free tenant does not run the
                  premium checks — the run records them as skipped, and the
                  pentest report answers 402 — so a locked feature never reads
                  as a clean result.
                </p>
                <p className="lead">{PREMIUM_HELP}</p>
              </div>
              <ul className="ruled">
                <li>
                  <span className="t">Premium detections</span>
                  <p>
                    Host-header/vhost probing, JWT key confusion, GraphQL and
                    gRPC exposure, request smuggling, XXE/deserialization
                    confirmation, sustained rate limits and the spec design
                    review. Selected with the premium pass; only the plan makes
                    it run.
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
                    Natural-language questions about a scan&apos;s findings.
                    Tokens are metered per scan, and the answer is commentary on
                    evidence, never evidence itself.
                  </p>
                </li>
              </ul>
            </div>
            <p className="muted-sm" style={{ marginTop: 18 }}>
              <strong>To enable it:</strong> a deployment operator adds this
              tenant to the premium plan (the{" "}
              <code className="mono">premium_tenants</code> setting today), then
              reload the page so the UI re-reads entitlement. The API enforces
              the same boundary; the checkbox is not the gate.
            </p>
          </div>
        </details>
        <details className="guide-disclosure">
          <summary>
            <span>How checks collect evidence</span>
            <span className="muted-sm">Request flows and diagrams</span>
          </summary>
          <div className="guide-disclosure-body">
            {" "}
            <section className="band">
              <div className="wrap">
                <SectionLabel>How a check proves it</SectionLabel>
                <div className="cov-lead">
                  <div>
                    <h2 className="h-lg">Four mechanisms, drawn</h2>
                    <p className="lead">
                      A finding is only as good as the mechanism behind it.
                      These are the proof mechanisms the tier labels stand on —
                      the cross-identity write oracle, and the three newest
                      checks — each showing the exact observation that turns a
                      probe into evidence.
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
                    <h2 className="h-lg">
                      Why GET and body testing have different gates
                    </h2>
                    <p className="lead">
                      A GET query or path variant can be tested without changing
                      server state. A JSON body variant can create, update, or
                      trigger application behavior, so the same bounded loop is
                      available only when <strong>writes</strong> are explicitly
                      turned on. The planner can choose a next prevalidated
                      variant, but the engine owns the method, field, budget,
                      and evidence.
                    </p>
                  </div>
                  <AdaptiveValidationGraph />
                </div>
              </div>
            </section>
            <section className="band">
              <div className="wrap">
                <SectionLabel>
                  Resource lifecycle and the testing flow, visually
                </SectionLabel>
                <div className="split adaptive-explainer">
                  <div>
                    <h2 className="h-lg">The resource loop, end to end</h2>
                    <p className="lead">
                      Supply an existing resource ID, or let the engine try a
                      safe, deterministic body first. With{" "}
                      <strong>authorized</strong>, <strong>writes</strong>,{" "}
                      <strong>premium:true</strong>, and the separate refinement
                      switch approved, a 400, 409, or 422 can feed a redacted
                      response plus read-only DB schema metadata into a maximum
                      of two or three create attempts. A successful ID is reused
                      by later tests.
                    </p>
                  </div>
                  <ResourceLifecycleGraph />
                </div>
                <div
                  className="split adaptive-explainer"
                  style={{ marginTop: 32 }}
                >
                  <div>
                    <h2 className="h-lg">How a test flows</h2>
                    <p className="lead">
                      Selection, payload, request and evidence — with the
                      decision kept apart from the observed result. The engine
                      owns the method, field, budget and gates; the planner only
                      proposes. Every write appears in the run&apos;s value-free
                      structural log, without credentials, rendered IDs, scalar
                      body values, response text, or database rows.
                    </p>
                  </div>
                  <TestingFlowGraph />
                </div>
              </div>
            </section>
          </div>
        </details>
        <details className="guide-disclosure">
          <summary>
            <span>Security header reference</span>
            <span className="muted-sm">Scoring and exclusions</span>
          </summary>
          <div className="guide-disclosure-body">
            {" "}
            <section className="band">
              <div className="wrap">
                <SectionLabel>Response headers</SectionLabel>
                <div className="cov-lead">
                  <div>
                    <h2 className="h-lg">Header by header</h2>
                    <p className="lead">
                      Every header the per-endpoint sweep scores. Where a bad
                      value is listed the check reads the value as well as the
                      presence, because a header set to a value that permits
                      everything buys nothing. Severities are scaled for a JSON
                      API rather than a browser-rendered site.
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
                      The disclosure half of the same sweep — headers that
                      should not be on a response at all. Low severity.
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
                      Two headers from the usual published checklists that this
                      sweep leaves alone, and why.
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
          </div>
        </details>
        <details className="guide-disclosure">
          <summary>
            <span>OWASP mapping &amp; optional AI</span>
            <span className="muted-sm">Scope and interpretation</span>
          </summary>
          <div className="guide-disclosure-body">
            {" "}
            <section className="wrap section">
              <SectionLabel>Cross-walk</SectionLabel>
              <div className="split">
                <div>
                  <h2 className="h-lg">OWASP Top 10:2025</h2>
                  <p className="lead">
                    An API-first scanner built around the OWASP{" "}
                    <strong>API Security Top 10 (2023)</strong> — the per-check
                    codes above use those. This is the honest cross-walk to the{" "}
                    <strong>Top 10:2025</strong> web-app list: no black-box
                    active scanner fully supports it, and several categories are
                    not observable from the outside.
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
          </div>
        </details>
      </div>
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
        <details className="guide-disclosure">
          <summary>
            <span>Scan limits &amp; prerequisites</span>
            <span className="muted-sm">
              Accounts, traffic and optional tools
            </span>
          </summary>
          <div className="guide-disclosure-body">
            <div className="split">
              <div>
                <h2 className="h-lg">What bounds a scan</h2>
                <p className="lead">
                  The constraints that decide how deep any single run can go —
                  most of them deliberate.
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
          </div>
        </details>
      </section>

      <div className="wrap guide-cta">
        <Link className="btn" href="/scans/new">
          Set up a scan
        </Link>
        <Link href="/cli">CLI guide →</Link>
      </div>
    </>
  );
}
