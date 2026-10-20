import type { Metadata } from "next";
import Link from "next/link";
import { SignedInRedirect } from "./components/AppHome";
import { EvidenceTiers } from "./components/Flow";
import { HeroStage } from "./components/HeroStage";
import { HowItWorks } from "./components/HowItWorks";
import { GROUPS, type Confidence } from "@/lib/coverage";
import { SectionLabel } from "./components/SectionLabel";
import { TierChip } from "./components/TierChip";

export const metadata: Metadata = {
  title: "runpentests — Run an API pen test. See what to fix.",
  description:
    "Start an API pen test in your browser or terminal. Review findings, see the requests behind them, and export a report with guidance on what to fix.",
};

const ALL = GROUPS.flatMap((g) => g.checks);

/*
 * "planned" checks are documented but not implemented, so they must never be
 * counted as coverage — the whole point of the evidence tiers is refusing to
 * inflate the number. Everything user-facing here counts ACTIVE only.
 */
const ACTIVE = ALL.filter((c) => c.confidence !== "planned");
const VERIFIED = ACTIVE.filter((c) => c.confidence === "verified").length;
const ACTIVE_GROUPS = GROUPS.filter((g) =>
  g.checks.some((c) => c.confidence !== "planned"),
).length;
const PREMIUM_CHECKS = ACTIVE.filter((c) => c.premium).length;
const FREE_CHECKS = ACTIVE.length - PREMIUM_CHECKS;

const STATS = [
  { n: String(ACTIVE.length), k: "test signals", s: `${VERIFIED} can produce verified evidence` },
  { n: String(ACTIVE_GROUPS), k: "check families", s: "access, input, data and configuration" },
  { n: "750", k: "core request cap", s: "extra tools have separate limits" },
  { n: "1", k: "place for results", s: "browser and CLI runs, side by side" },
];

const BASICS = [
  {
    t: "Can a user see someone else’s data?",
    d: "We try the same request with different test accounts. For example: can a regular user read an order that belongs to another account?",
  },
  {
    t: "Can someone do more than they should?",
    d: "We check whether a regular user, or someone who is not logged in, can reach actions intended for an administrator.",
  },
  {
    t: "Does the API leak data or trust risky input?",
    d: "We look for exposed secrets, weak security settings and responses to attack-like input. Each result explains what we observed and whether it needs further investigation.",
  },
];

/* Labels and locations mirror ResultsWorkspace and FindingsSection. */
const RESULTS = [
  { t: "Findings", d: "Start here: see each issue’s severity, affected endpoint, evidence and suggested fix. Verified means the evidence demonstrates a weakness; a lead needs investigation." },
  { t: "Request log", d: "See what the core scanner sent, which test account it used and what came back. A finding’s Requests button jumps to its recorded calls." },
  { t: "Endpoint coverage", d: "Check which API routes were tested. If a step could not run, look for “What this run could not do” in Scan results." },
  { t: "Changes & Run history", d: "Run again after a fix. Compare new, fixed and unchanged findings, or review the findings saved with an earlier run." },
];

/* The CLI walkthrough. Commands are the real ones from cli/README.md. */
const STEPS: { t: string; d: string; cmd: string[] }[] = [
  {
    t: "Connect once",
    d: "The key is prompted for or read from stdin — never a flag, so it never lands in shell history. CI supplies it through AIDETECTOR_API_KEY.",
    cmd: ["aidetector login"],
  },
  {
    t: "Point it at an API",
    d: "It asks you to confirm you may test that host, reuses the scan you already have for it (identities, triage and history included) or creates one, finds the spec — yours, or the target's own /openapi.json — runs, and prints what it found.",
    cmd: ["aidetector https://api.example.com"],
  },
  {
    t: "Add your code",
    d: "Name a project directory and the scan runs from your machine with the code mounted read-only: the spec is found in the repo, and findings point at the file and line behind them.",
    cmd: ["aidetector https://api.example.com ./my-project"],
  },
  {
    t: "Commit aidetector.yml",
    d: "The target, spec, identities and gate, in the repo — never a secret (each identity names its environment variable) and never consent. What the file sets wins over the web, setting by setting, and the web shows those settings as managed by the file.",
    cmd: [
      "target: https://staging.example.com",
      "spec: openapi.yaml",
      "level: standard",
      "fail_on: high",
      "identities:",
      "  - { name: alice, role: user,  secret_env: ALICE_TOKEN }",
      "  - { name: admin, role: admin, secret_env: ADMIN_TOKEN }",
    ],
  },
  {
    t: "Then just run it",
    d: "Inside the project, a bare command does what the file says. The Deep level the browser leaves out — ZAP, the Kali tools, lead confirmation and a testssl audit — is one flag away. Writes and AI are never part of a level: each is its own switch.",
    cmd: ["aidetector", "aidetector --level deep --ai", "aidetector --writes"],
  },
];

/*
 * `aidetector mcp` — cli/internal/commands/mcp.go. The tool set is pinned by a
 * test; it deliberately has no tool that runs a scan.
 */
const MCP_TOOLS = [
  { t: "find_spec", d: "lists the OpenAPI / Swagger files in the project, most likely first" },
  { t: "suggest_config", d: "drafts aidetector.yml in the shape aidetector init writes" },
  { t: "validate_config", d: "checks the file with the CLI’s own loader and returns the exact error" },
  { t: "server_status", d: "whether you are logged in (never the key) and which passes the server can run" },
  { t: "next_steps", d: "the commands for you to run — env variable names, never values" },
];

/* Whitebox, from inside the project — app/agent/{source,loop,sandbox,memory}.py */
const CODE = [
  {
    t: "Your source, mounted read-only",
    d: "Naming a project directory mounts it into the runner read-only. It indexes application code only — capped in size, honouring .gitignore, never following symlinks. Source indexing does not execute your code.",
  },
  {
    t: "Findings point at the line",
    d: "Each finding gains file:line citations to the handler, query or model behind it, so the fix starts in the right file. Citations are evidence, not identity — triage still matches.",
  },
  {
    t: "A bounded agent confirms and widens leads",
    d: "--agent queues follow-ups — a sqlmap run on an injection lead, a nuclei or ffuf sweep — under hard caps on steps, tool calls and wall-clock. Its findings are graded by the same engine, so a lead stays a lead.",
  },
  {
    t: "It remembers what worked",
    d: "Episodic memory recalls which tools were productive on this target last time and moves them up the queue. Memory steers the order; it never decides a finding.",
  },
  {
    t: "Reaches what only you can reach",
    d: "A local run sends the scan traffic from your machine in a locked-down container, so internal hosts, VPN-only services and localhost are in scope. Cloud metadata is always refused.",
  },
  {
    t: "What leaves the machine",
    d: "Findings, file:line citations and short redacted snippets — never whole files. Secrets reach the container on stdin, and it holds a per-run token, never your API key.",
  },
];

/*
 * Who can do what. Mirrors RunPanel (web = quick/standard levels plus the
 * writes and AI switches) and LOCAL_REFUSED in app/scans/run_levels.py (the
 * CLI runs every scan from your machine; the AI passes that need no target
 * traffic run on the service). "yes" / "no" only — no partial cells to argue about.
 */
const LANES = ["Web UI", "CLI"] as const;
const MATRIX: { cap: string; on: [boolean, boolean] }[] = [
  { cap: "OWASP API Top 10 engine checks", on: [true, true] },
  { cap: "Schema fuzzing", on: [true, true] },
  { cap: "Test writes — create/update authorization, races and mass assignment", on: [true, true] },
  { cap: "Premium detections — JWT, GraphQL/gRPC, host headers and more", on: [true, true] },
  { cap: "AI risk plan and security design review", on: [true, true] },
  { cap: "AI verdicts on BOLA, BFLA and SSRF findings", on: [true, true] },
  { cap: "Findings, evidence, request log and endpoint coverage", on: [true, true] },
  { cap: "Triage, run history and changes between runs", on: [true, true] },
  { cap: "PDF, HTML, Markdown pentest, JSON and SARIF reports", on: [true, true] },
  { cap: "Deep level — ZAP, Kali tools, lead confirmation, testssl audit", on: [false, true] },
  { cap: "Premium adaptive validation and AI resource refinement", on: [false, true] },
  { cap: "CI gate with exit codes", on: [false, true] },
  { cap: "Settings from a committed aidetector.yml", on: [false, true] },
  { cap: "Setup through your coding agent (aidetector mcp)", on: [false, true] },
  { cap: "Traffic from your machine (internal, VPN, localhost)", on: [false, true] },
  { cap: "Whitebox source — file:line evidence", on: [false, true] },
  { cap: "Bounded agent with episodic memory", on: [false, true] },
];

/*
 * Free vs Premium. Premium is a workspace plan (app/scans/workspace.py:is_premium)
 * that gates: engine checks with `premium = True`, the adaptive and
 * resource_refine passes (app/scans/policy.py), the pentest report and Ask
 * (routes/scans/reports.py), finding assignment and comments
 * (routes/scans/findings.py), and schema context for the AI passes. Everything
 * else — including the AI passes and the Deep level — is on every plan.
 */
const FREE = [
  { t: `${FREE_CHECKS} core detections`, d: "The OWASP API Top 10 checks: access between accounts, admin actions, authentication, injection leads, data exposure, headers and TLS." },
  { t: "Schema fuzzing and test writes", d: "The Standard level adds fuzzing. Turn on Test writes for create/update authorization, mass assignment and race checks, with cleanup afterwards." },
  { t: "AI passes", d: "A risk plan, verdicts on BOLA/BFLA/SSRF findings and a security design review — when the server has an AI key. Tokens are counted per scan." },
  { t: "The Deep level, from the CLI", d: "ZAP, the Kali tools, sqlmap / dalfox / commix / tplmap confirmation and a testssl audit, inside their own time budget." },
  { t: "Local runs, code and CI", d: "Traffic from your machine, file:line evidence from your source, the bounded agent, aidetector.yml, aidetector mcp and the CI gate." },
  { t: "Results and history", d: "Findings, request log, endpoint coverage, triage, run-to-run changes and schedules. PDF, HTML, JSON and SARIF exports." },
];

const PREMIUM = [
  { t: `${PREMIUM_CHECKS} premium detections`, d: "JWT key confusion, GraphQL and gRPC exposure, host-header injection, request smuggling, sustained rate limits, an API design review, and callback-confirmed XXE, deserialization and upstream API checks. Callback checks need an OAST service; some also need Test writes." },
  { t: "Adaptive validation & resource refinement", d: "At the Deep level with AI on, from the CLI: try bounded input variants, and let AI fix rejected setup requests. The runner asks the service to run these, so no model keys are needed on your machine. Refinement also needs Test writes." },
  { t: "Pentest report", d: "A pentest-grade Markdown deliverable with an executive summary, attack paths and per-finding detail." },
  { t: "Ask your scan", d: "Ask questions about a scan’s findings in plain language. Answers are commentary on the evidence, never evidence." },
  { t: "Assignment & discussion", d: "Give each finding an owner and a due date, and discuss it with your team on the finding itself." },
  { t: "Database schema context", d: "Table structure read by a local run from a schema: block in aidetector.yml, given to the AI passes. Structure only — the password never leaves your machine." },
];

const EXITS = [
  { c: "0", d: "ran, nothing at or above --fail-on" },
  { c: "1", d: "findings reached --fail-on" },
  { c: "2", d: "usage, config or auth error" },
  { c: "3", d: "the scan failed or was cancelled" },
  { c: "4", d: "waiting for the AI analysis timed out" },
];

const GUARDRAILS = [
  {
    t: "Consent is a hard gate",
    d: "The server returns 403 without an explicit authorized flag. The web asks on every run — a checkbox, or a Run button that says it for a domain you have verified — and the CLI with --authorized or a prompt naming the target. Schedules and local runs answer the same gate.",
  },
  {
    t: "Public targets need proof of ownership",
    d: "Before a public host is scanned, your workspace proves it owns it (unless the operator exempts the host): a DNS TXT record for the name and an HTTP token on the machine. Scan traffic goes to the address that was checked, and cloud metadata is always refused.",
  },
  {
    t: "Limits on scan traffic",
    d: "The core engine has a 750-request budget. Optional external tools run outside that budget with separate time limits. Tests that create or update data need an explicit opt-in and attempt cleanup afterwards.",
  },
  {
    t: "Credentials never come back out",
    d: "Secrets are encrypted at rest and decrypted only where the scan runs. No endpoint echoes one, no CLI flag accepts one, and no report contains one.",
  },
  {
    t: "See what could not run",
    d: "A broken check, a missing tool or an unavailable AI runtime is logged and named as a gap. A tool that did not run never reads as a clean result.",
  },
];

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
            Run an API pen test. <span className="hero-em">See what to fix.</span>
          </h1>
          <p className="lead">
            Give us your API’s URL and a file describing its endpoints. We test
            for security weaknesses and show what happened, why it matters and
            how to fix it. Start in your browser or use one command from your terminal.
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

      <section className="wrap section" id="how">
        <SectionLabel>How it works</SectionLabel>
        <h2 className="h-lg">Two ways in. One set of results.</h2>
        <p className="lead home-intro">
          Set it up in the browser, or run one command from your terminal. Both
          lanes hit the same engine and land on the same scan page — the
          evidence, triage, diffs and reports do not change.
        </p>
        <HowItWorks />
      </section>

      <section className="wrap section" id="web">
        <SectionLabel>New to pen testing?</SectionLabel>
        <h2 className="h-lg">We check whether your API lets the wrong person in.</h2>
        <p className="lead home-intro">
          An API is how your app asks a server for data or actions, like loading an
          order or updating an account. A penetration test tries to misuse those
          requests to uncover security weaknesses. We automate checks for common
          API risks, including these:
        </p>
        <div className="home-basics">
          {BASICS.map((f) => (
            <div className="feat" key={f.t}>
              <h3>{f.t}</h3>
              <p>{f.d}</p>
            </div>
          ))}
        </div>
        <p className="home-note">
          Your API description is the map of what to test. Test accounts let us
          compare who can access what. You choose whether to enable tests that
          create or update data.
        </p>
        <Link className="link-arrow" href="/coverage">Explore the checks and their limits →</Link>
      </section>

      <section className="band" id="results">
        <div className="wrap">
          <SectionLabel>Find your results</SectionLabel>
          <div className="split">
            <div>
              <h2 className="h-lg">Scans → your API → Scan results</h2>
              <p className="lead">
                A browser run opens its scan page automatically. Come back anytime
                through <Link href="/scans">Scans</Link> and select your API. CLI runs
                appear in that same list when connected to the same server.
              </p>
              <div className="home-export">
                <h3>Need a report to share?</h3>
                <p>
                  When findings are available, open <strong>Findings</strong> and use
                  the export buttons above the list: PDF, HTML report, JSON, SARIF
                  for code-scanning tools, or — on <Link href="#plans">Premium</Link> — the
                  Pentest report (Markdown).
                </p>
              </div>
              <div className="hero-cta">
                <Link className="btn" href="/scans">Open your scans</Link>
                <Link className="link-arrow" href="/scans/new">Run your first test →</Link>
              </div>
            </div>
            <div className="feat-grid">
              {RESULTS.map((f) => (
                <div className="feat" key={f.t}>
                  <h3>{f.t}</h3>
                  <p>{f.d}</p>
                </div>
              ))}
            </div>
          </div>
        </div>
      </section>

      <div className="stats-band">
        <div className="wrap">
          <dl className="stats">
            {STATS.map((s) => (
              <div className="stat" key={s.k}>
                <dt>{s.n}</dt>
                <dd><b>{s.k}</b><span>{s.s}</span></dd>
              </div>
            ))}
          </dl>
        </div>
      </div>

      <section className="band" id="cli">
        <div className="wrap">
          <SectionLabel>From the terminal</SectionLabel>
          <h2 className="h-lg">How the CLI works</h2>
          <p className="lead" style={{ maxWidth: "62ch" }}>
            One static binary that talks to the same API the web uses. Give it a
            URL and it does the rest — finds or creates the scan, finds the spec,
            runs it and shows what it found. Give it your project too and it
            reads the code. Results land in the web like any other run.
          </p>
          <ol className="cli-steps">
            {STEPS.map((s, i) => (
              <li key={s.t}>
                <div className="cli-step-copy">
                  <span className="cli-n">{String(i + 1).padStart(2, "0")}</span>
                  <div>
                    <h3>{s.t}</h3>
                    <p>{s.d}</p>
                  </div>
                </div>
                <pre className="shell">
                  <code>{s.cmd.join("\n")}</code>
                </pre>
              </li>
            ))}
          </ol>
          <p className="home-note">
            The CLI prints a findings summary, your scan ID and commands for
            viewing details or exporting an HTML report. To explore the same run
            in your browser, open <Link href="/scans">Scans</Link> on the connected
            server and select your API.
          </p>
          <Link className="link-arrow" href="/cli">Read the full CLI guide →</Link>

          <div className="home-mcp" id="mcp">
            <div>
              <h3>Let your coding agent set it up</h3>
              <p>
                <code>aidetector mcp</code> is a Model Context Protocol server for
                Claude Code, Cursor or any other MCP client. Started in your
                project, it gives the agent the setup guides and the tools to find
                your spec and write a working <code>aidetector.yml</code>. Then ask
                it to “set up aidetector for this project”.
              </p>
              <pre className="shell">
                <code>
                  <span className="c">{"# writes .mcp.json — commit it for the team\n"}</span>
                  {"claude mcp add --scope project aidetector -- aidetector mcp"}
                </code>
              </pre>
              <p className="home-note">
                It cannot start a scan — you still confirm you may test the target.
                It never takes or returns a secret, only environment variable names,
                and reads only inside the folder it started in. The one thing it
                sends is the spec’s text, to your aidetector server, for login hints.
              </p>
            </div>
            <dl className="mcp-tools">
              {MCP_TOOLS.map((m) => (
                <div key={m.t}>
                  <dt>{m.t}</dt>
                  <dd>{m.d}</dd>
                </div>
              ))}
            </dl>
          </div>
        </div>
      </section>

      <section className="wrap section" id="code">
        <SectionLabel>Inside your codebase</SectionLabel>
        <div className="split">
          <div>
            <h2 className="h-lg">Whitebox testing with your code</h2>
            <p className="lead">
              Pass your project directory to the CLI to include source code in
              the test. It sends the traffic from your machine, reads the source
              that serves each endpoint, and lets a bounded agent chase the leads
              — while the engine, not the agent, decides what counts as proof.
            </p>
            <pre className="shell code-cmd">
              <code>
                <span className="c">{"# from your project root\n"}</span>
                {"aidetector https://staging.example.com . \\\n    --authorized --agent --fail-on high"}
              </code>
            </pre>
            <div className="src-card" aria-hidden="true">
              <div className="src-head">
                <span className="sev-badge high">high</span>
                <span className="src-title">BOLA · GET /orders/{"{id}"}</span>
                <TierChip tier="verified">verified</TierChip>
              </div>
              <p className="src-why">
                alice read an order owned by admin — same body, status 200.
              </p>
              <div className="src-file">orders/views.py:88</div>
              <pre className="src-snip">
                <code>
                  <span className="ln">87</span>
                  {"  order_id = request.path_params[\"id\"]\n"}
                  <span className="ln hl">88</span>
                  <mark>{"  order = db.get(Order, order_id)"}</mark>
                  {"\n"}
                  <span className="ln">89</span>
                  {"  return OrderOut.from_orm(order)"}
                </code>
              </pre>
              <p className="src-fix">
                Fix: scope the lookup to the caller — filter by owner, or 404 when
                the order is not theirs.
              </p>
            </div>
          </div>
          <dl className="guards">
            {CODE.map((c) => (
              <div className="guard" key={c.t}>
                <dt>{c.t}</dt>
                <dd>{c.d}</dd>
              </div>
            ))}
          </dl>
        </div>
      </section>

      <section className="band" id="lanes">
        <div className="wrap">
          <SectionLabel>Which lane</SectionLabel>
          <div className="lane-intro">
            <div>
              <h2 className="h-lg">Same engine, same evidence, three ways to run it</h2>
              <p className="lead">
                Results from every lane land on the same server — graded,
                fingerprinted, diffable and triaged the same way. Pick the lane
                by what you need to reach and how deep you want to go.
              </p>
            </div>
          </div>
          <div className="fam-scroll lane-comparison">
            <table className="fam-table lane-table">
              <thead>
                <tr>
                  <th scope="col">Capability</th>
                  {LANES.map((l) => (
                    <th scope="col" className="yn" key={l}>
                      {l}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {MATRIX.map((r) => (
                  <tr key={r.cap}>
                    <td className="name">{r.cap}</td>
                    {r.on.map((v, i) => (
                      <td className={`yn ${v ? "y" : "n"}`} key={LANES[i]}>
                        {v ? "✓" : "—"}
                        <span className="sr-only">{v ? "yes" : "no"}</span>
                      </td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <p className="home-note">
            A checkmark means the feature is available in that mode. Extra passes
            are off until you enable them. Premium features need a workspace on
            the <Link href="#plans">Premium plan</Link>; individual checks also
            need suitable endpoints, credentials or services.
          </p>
        </div>
      </section>

      <section className="wrap section" id="ci">
        <SectionLabel>In your pipeline</SectionLabel>
        <div className="split">
          <div>
            <h2 className="h-lg">Fail the build on what is new and proven</h2>
            <p className="lead">
              <code>--verified-only</code> counts only findings whose evidence
              demonstrates the weakness. <code>--new-only</code> judges only what
              appeared since the previous run. Commit the target and spec in
              <code> aidetector.yml</code> first, then run the command below from
              that project directory. A finding someone dismissed never fails the gate.
            </p>
          </div>
          <div>
            <pre className="shell">
              <code>
                {"aidetector --authorized --fail-on high --verified-only --new-only\n"}
                {"aidetector report SCAN_ID --format sarif -o results.sarif  "}
                <span className="c">{"# → code scanning"}</span>
              </code>
            </pre>
            <p className="home-note">
              Replace <code>SCAN_ID</code> with the ID printed by the CLI. The first
              command exits with 1 when the gate finds a regression; configure
              your CI to collect the report even when that step fails.
            </p>
            <dl className="exit-codes">
              {EXITS.map((e) => (
                <div key={e.c}>
                  <dt>exit {e.c}</dt>
                  <dd>{e.d}</dd>
                </div>
              ))}
            </dl>
          </div>
        </div>
      </section>

      <section className="band" id="decide">
        <div className="wrap">
          <SectionLabel>The evidence</SectionLabel>
          <h2 className="h-lg">How a test decides something is wrong</h2>
          <p className="lead">
            Every lane grades its findings the same way, and labels which kind of
            proof it used every single time.
          </p>
          <EvidenceTiers />
        </div>
      </section>

      <section className="wrap section">
        <SectionLabel>Coverage</SectionLabel>
        <div className="cov-lead">
          <div>
            <h2 className="h-lg">What it actually checks</h2>
            <p className="lead">
              {ACTIVE.length} implemented test signals across {ACTIVE_GROUPS} families,
              each documented with the literal signal it uses to decide and its
              known false-positive caveat.
            </p>
          </div>
          <Link className="link-arrow" href="/coverage">
            Full coverage detail →
          </Link>
        </div>

        <div className="fam-scroll">
          <table className="fam-table">
            <thead>
              <tr>
                <th scope="col">Family</th>
                <th scope="col" className="num">
                  Checks
                </th>
                <th scope="col" className="ev">
                  Evidence
                </th>
              </tr>
            </thead>
            <tbody>
              {GROUPS.map((g) => {
                const by = (c: Confidence) =>
                  g.checks.filter((x) => x.confidence === c).length;
                // Three tiers, never two: folding "planned" into "lead" would
                // report unimplemented checks as findings the engine can make.
                const v = by("verified");
                const h = by("heuristic");
                const p = by("planned");
                return (
                  <tr key={g.title}>
                    <td className="name">{g.title}</td>
                    <td className="num">{g.checks.length}</td>
                    <td className="ev">
                      <span className="fam-tiers">
                        {v > 0 && <TierChip tier="verified">{v} verified</TierChip>}
                        {h > 0 && <TierChip tier="heuristic">{h} lead</TierChip>}
                        {p > 0 && <TierChip tier="planned">{p} planned</TierChip>}
                      </span>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </section>

      <section className="band">
        <div className="wrap">
          <SectionLabel>Guardrails</SectionLabel>
          <div className="split">
            <div>
              <h2 className="h-lg">An active scanner, kept on a leash</h2>
              <p className="lead">
                These hold in every lane. Each exists because the tool sends real
                payloads at a live host.
              </p>
            </div>
            <dl className="guards">
              {GUARDRAILS.map((g) => (
                <div className="guard" key={g.t}>
                  <dt>{g.t}</dt>
                  <dd>{g.d}</dd>
                </div>
              ))}
            </dl>
          </div>
        </div>
      </section>

      <section className="wrap section" id="plans">
        <SectionLabel>Free and Premium</SectionLabel>
        <h2 className="h-lg">The whole scanner is free. Premium goes deeper.</h2>
        <p className="lead home-intro">
          Every lane, every evidence tier, the AI passes and the CLI’s Deep level
          are on every plan. Premium adds detections for newer protocols and
          harder attacks, a pentest-grade report, and tools for working through
          findings as a team.
        </p>
        <div className="plans">
          <div className="plan">
            <div className="plan-head">
              <h3>Free</h3>
              <span>Every workspace</span>
            </div>
            <ul>
              {FREE.map((f) => (
                <li key={f.t}>
                  <b>{f.t}</b>
                  <p>{f.d}</p>
                </li>
              ))}
            </ul>
          </div>
          <div className="plan premium">
            <div className="plan-head">
              <h3>Premium</h3>
              <span>Everything in Free, plus</span>
            </div>
            <ul>
              {PREMIUM.map((f) => (
                <li key={f.t}>
                  <b>{f.t}</b>
                  <p>{f.d}</p>
                </li>
              ))}
            </ul>
          </div>
        </div>
        <p className="home-note">
          Premium is a plan for the whole workspace, not a run setting. The Standard
          level includes the premium detections when your plan does, in the browser
          and on the CLI (<code>--level standard</code>, or <code>--premium</code> on
          its own). On a free workspace a level leaves them out and
          the run records them as skipped, so a locked check never reads as a
          clean result.
        </p>
        <Link className="link-arrow" href="/coverage#premium-tier">
          See every Premium check, its evidence and its limits →
        </Link>
      </section>

      <section className="wrap section">
        <div className="closer">
          <h2>Scan something you own.</h2>
          <p>
            Start with the guided browser setup. Use the CLI when
            you want your code, your network and your pipeline in the loop.
          </p>
          <div className="actions">
            <Link className="btn lg" href="/scans/new">
              Start a scan
            </Link>
            <Link className="link-arrow" href="#cli">
              How the CLI works →
            </Link>
          </div>
        </div>
      </section>
    </>
  );
}
