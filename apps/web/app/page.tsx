import type { Metadata } from "next";
import Link from "next/link";
import { SignedInRedirect } from "./components/AppHome";
import { HeroStage } from "./components/HeroStage";
import { HowItWorks } from "./components/HowItWorks";
import { TechnologyStrip } from "./components/TechnologyStrip";
import { EvidenceGuide } from "./components/EvidenceGuide";
import { PlanComparison } from "./components/PlanComparison";
import { SectionLabel } from "./components/SectionLabel";
import { GROUPS } from "@/lib/coverage";

export const metadata: Metadata = {
  title: { absolute: "runpentests — Run an API pen test. See what to fix." },
  description:
    "Test your API, understand the evidence, and see what to fix. Guided browser setup, local CLI runs, and shareable reports.",
};
const ACTIVE = GROUPS.flatMap((group) => group.checks).filter(
  (check) => check.confidence !== "planned",
);

export default function Landing() {
  return (
    <>
      <SignedInRedirect />
      <section className="hero">
        <div className="wrap hero-grid">
          <div className="hero-kicker">
            <span>API security testing</span>
            <i className="dot-sep" aria-hidden="true" />
            <span>Browser + CLI</span>
          </div>
          <h1>
            Run an API pen test.{" "}
            <span className="hero-em">See what to fix.</span>
          </h1>
          <p className="lead">
            Give us your API’s URL and a file describing its endpoints. We test
            for security weaknesses and show what happened, why it matters and
            how to fix it. Start in your browser or use one command from your
            terminal.
          </p>
          <div className="hero-cta">
            <Link className="btn lg" href="/scans/new">
              Start a pen test
            </Link>
            <Link className="link-arrow" href="/scans">
              View your results →
            </Link>
          </div>
          <p className="hero-meta">
            <span>Guided setup</span>
            <i className="dot-sep" aria-hidden="true" />
            <span>Evidence with every finding</span>
            <i className="dot-sep" aria-hidden="true" />
            <span>Downloadable reports</span>
          </p>
        </div>
        <div className="wrap hero-stage-wrap">
          <HeroStage />
        </div>
      </section>

      <TechnologyStrip />
      <section className="wrap section" id="how">
        <SectionLabel>From setup to evidence</SectionLabel>
        <h2 className="h-lg">Your API. Three steps to a clearer picture.</h2>
        <p className="lead home-intro">
          Start in the browser. Bring the CLI when you need your code, network
          or CI pipeline.
        </p>
        <HowItWorks />
      </section>
      <section className="band" id="decide">
        <div className="wrap">
          <SectionLabel>Understand the result</SectionLabel>
          <h2 className="h-lg">See the difference between proof and a lead.</h2>
          <p className="lead home-intro evidence-intro">
            Follow the evidence. See what’s proven, what needs a closer look,
            and what to fix.
          </p>
          <EvidenceGuide />
          <p className="home-note">
            <Link href="/coverage">
              Explore all {ACTIVE.length} signals and their limits →
            </Link>
          </p>
        </div>
      </section>
      <section className="wrap section" id="results">
        <SectionLabel>Work from the evidence</SectionLabel>
        <h2 className="h-lg">Find it. Understand it. Check the fix.</h2>
        <div className="product-path">
          <article>
            <span className="path-icon" aria-hidden="true">
              ↳
            </span>
            <h3>Find what needs attention</h3>
            <p>
              Prioritize findings by severity and evidence. Inspect the recorded
              request and response.
            </p>
            <Link href="/scans">Open your scans →</Link>
          </article>
          <article>
            <span className="path-icon" aria-hidden="true">
              ↔
            </span>
            <h3>Verify the fix</h3>
            <p>
              Run again to compare new, fixed and unchanged findings. See checks
              that could not run.
            </p>
            <Link href="/coverage#coverage-gaps">
              Understand coverage gaps →
            </Link>
          </article>
          <article>
            <span className="path-icon" aria-hidden="true">
              ↓
            </span>
            <h3>Share the evidence</h3>
            <p>
              Export PDF, HTML, JSON or SARIF. Premium adds the pentest report
              in Markdown.
            </p>
            <Link href="/cli#results">Reporting guide →</Link>
          </article>
        </div>
      </section>
      <section className="band" id="cli">
        <div className="wrap">
          <SectionLabel>Fits your workflow</SectionLabel>
          <div className="split">
            <div>
              <h2 className="h-lg">One scan history. Browser or terminal.</h2>
              <p className="lead">
                CLI runs appear alongside browser runs when connected to the
                same server.
              </p>
              <Link className="link-arrow" href="/cli">
                Install and use the CLI →
              </Link>
            </div>
            <div className="workflow-links">
              <Link href="/cli#local" id="code">
                <strong>
                  Test from your machine <span aria-hidden="true">↗</span>
                </strong>
                <span>Local network access and source context</span>
              </Link>
              <Link href="/cli#project">
                <strong>
                  Keep setup in your project <span aria-hidden="true">↗</span>
                </strong>
                <span>Reusable runpentests.yml configuration</span>
              </Link>
              <Link href="/cli#ci" id="ci">
                <strong>
                  Check changes in CI <span aria-hidden="true">↗</span>
                </strong>
                <span>Gate builds on findings with evidence</span>
              </Link>
            </div>
          </div>
        </div>
      </section>
      <PlanComparison />
      <section className="band">
        <div className="wrap safety-strip" aria-label="Scan guardrails">
          <div>
            <strong>Explicit authorization</strong>
            <span>Only test targets you own or may test.</span>
          </div>
          <div>
            <strong>Bounded core traffic</strong>
            <span>750-request core cap; extra tools have separate limits.</span>
          </div>
          <div>
            <strong>You control writes and AI</strong>
            <span>Writes modify data. AI spends tokens. Both start off.</span>
          </div>
        </div>
      </section>
      <section className="wrap section">
        <div className="closer">
          <h2>Start with an API you own.</h2>
          <p>
            Bring its URL, an API description and test accounts. We’ll guide you
            from there.
          </p>
          <div className="actions">
            <Link className="btn lg" href="/scans/new">
              Set up a scan
            </Link>
            <Link className="link-arrow" href="/coverage">
              Explore coverage →
            </Link>
          </div>
        </div>
      </section>
    </>
  );
}
