import { GuideNav } from "../components/GuideNav";
import type { Metadata } from "next";
import Link from "next/link";
import { SCAN_LEVELS } from "../components/scanLevels";
import { GuideHero } from "../components/GuideHero";
import { SectionLabel } from "../components/SectionLabel";
import { Terminal, type TermLine } from "../components/Terminal";
import { PlanBadge } from "../components/PlanBadge";

export const metadata: Metadata = {
  title: "CLI guide",
  description:
    "How to drive runpentests from the terminal: connect, scan an API in one command, commit a project file, read results and gate a pipeline.",
};

/*
 * Every session below is what the CLI prints, captured against the bundled
 * vulnerable target (services/target) with the host renamed and long event
 * logs trimmed. The strings come from cli/internal/commands — run.go, target.go,
 * read.go, local.go — and the progress lines are the server's event log. When
 * the CLI's output changes, update the session here too: nothing generates it.
 */

const TOC = [
  { id: "install", label: "Install & connect" },
  { id: "everyday", label: "Scan an API" },
  { id: "project", label: "runpentests.yml" },
  { id: "results", label: "Read the results" },
  { id: "ci", label: "Gate a pipeline" },
  { id: "local", label: "Local runs" },
  { id: "web-or-cli", label: "Web or CLI" },
  { id: "reference", label: "Command reference" },
];

const SCAN = "645d5118-e36b-42fa-a986-0c8c4c878382";

const INSTALL: TermLine[] = [
  "# connect once — the key is prompted for, never a flag",
  "$ runpentests login",
  "API key (input hidden):",
  { text: "logged in to https://aidetector.com", tone: "ok" },
  "$ runpentests status",
  "cli: 15f5da6",
  "profile: default",
  "server: https://aidetector.com",
  "api key: set",
  { text: "reachable: yes", tone: "ok" },
  "passes:",
  "  --adjudicate       available",
  "  --confirm          available (note: tplmap not installed)",
  "  --kali             available",
  "  --premium          available (plan: premium)",
  "  --zap              available",
];

const PIPE = [
  {
    t: "Consent",
    d: "Names the target and waits for y, or takes --authorized. Nothing is sent before this.",
    src: "the authorization gate",
    gate: true,
  },
  {
    t: "Find the scan",
    d: "Reuses the scan whose target matches, keeping identities, triage and history. --new forces a fresh one.",
    src: "scan: in runpentests.yml pins one",
  },
  {
    t: "Find a spec",
    d: "--spec, then runpentests.yml, then the project tree, the saved spec, and finally the target's own /openapi.json.",
    src: "unchanged specs are not re-uploaded",
  },
  {
    t: "Identities",
    d: "Two users make the authorization checks possible. A terminal prompts for them; the project file lists them.",
    src: "secrets come from env vars",
  },
  {
    t: "Run, wait, print",
    d: "Streams the event log, then prints the findings. --fail-on turns the same call into a CI gate.",
    src: "exit code = the verdict",
  },
];

const FIRST_RUN: TermLine[] = [
  "$ runpentests https://api.example.com",
  "This sends active security tests to https://api.example.com.",
  {
    text: "Type y to confirm you own or are authorized to test it: y",
    tone: "warn",
  },
  `created scan ${SCAN} for https://api.example.com`,
  "spec: https://api.example.com/openapi.json — 11 operations",
  "This scan has no identities. The authorization checks compare two users — for example a normal user and an admin.",
  "Identity name (empty to finish): alice",
  "Role for alice (e.g. user, admin): user",
  "Auth type [bearer]:",
  "Secret for alice (input hidden):",
  { text: "identity alice (user): added", tone: "ok" },
  "Identity name (empty to finish): admin",
  "Role for admin (e.g. user, admin): admin",
  "Auth type [bearer]:",
  "Secret for admin (input hidden):",
  { text: "identity admin (admin): added", tone: "ok" },
  "Identity name (empty to finish):",
  `scan ${SCAN}`,
  { text: "    0%  scanning 11 operations", tone: "accent" },
  {
    text: "    0%  write_authz did not run: writes to the target are off (turn on writes to run it)",
    tone: "dim",
  },
  {
    text: "    0%  ssrf did not run: no url-shaped parameter in the spec — SSRF needs somewhere to put a URL",
    tone: "dim",
  },
  { text: "    4%  completed security_headers", tone: "accent" },
  { text: "   12%  completed broken_auth", tone: "accent" },
  { text: "  …", tone: "dim" },
  { text: "   76%  completed bola", tone: "accent" },
  { text: "   85%  completed signature_injection", tone: "accent" },
  { text: "  100%  complete · 17 findings · 66 requests", tone: "ok" },
  "high     verified  bola                     Cross-identity read (BOLA) on GET /accounts/{account_id}",
  "high     verified  broken_auth              Auth bypass (random_token) on GET /users/me",
  "high     verified  data_exposure            Response exposes payment data on 2 endpoints",
  "medium   verified  security_headers         Missing security headers (4) on all endpoints",
  "medium   heuristic reflected_injection      Reflected CMDI via query 'q' on GET /search",
  "low      heuristic signature_injection      NoSQL injection lead via query 'q' on GET /search",
  { text: "…", tone: "dim" },
  "17 finding(s), 9 verified",
  {
    text: `details: runpentests findings ${SCAN} · report: runpentests report ${SCAN} --format html -o report.html`,
    tone: "dim",
  },
];

const SECOND_RUN: TermLine[] = [
  "# the same command tomorrow: the scan, its identities and its triage are reused",
  "$ runpentests https://api.example.com --authorized",
  `reusing scan ${SCAN} for https://api.example.com`,
  `scan ${SCAN}`,
  { text: "    0%  scanning 11 operations", tone: "accent" },
  { text: "  …", tone: "dim" },
  { text: "  100%  complete · 17 findings · 66 requests", tone: "ok" },
  { text: "…", tone: "dim" },
  "# add a directory and the run happens here, with your code read-only",
  "$ runpentests https://api.example.com ./my-project",
];

const PROJECT_FILE: TermLine[] = [
  "$ cat runpentests.yml",
  "target: https://staging.example.com",
  {
    text: "spec: openapi.yaml            # relative to this file",
    tone: "dim",
  },
  "rps: 5",
  {
    text: "passes: [writes]              # any run flag, without the dashes",
    tone: "dim",
  },
  "checks: [bola, bfla]",
  "fail_on: high",
  "verified_only: true",
  "new_only: true",
  "identities:",
  "  - { name: alice, role: user,  secret_env: ALICE_TOKEN }",
  "  - { name: admin, role: admin, auth: header, header: X-Api-Key, secret_env: ADMIN_TOKEN }",
  "",
  "# inside the project, a bare command does what the file says",
  "$ runpentests --authorized",
  { text: "using runpentests.yml", tone: "dim" },
  `reusing scan ${SCAN} for https://staging.example.com`,
  "spec: openapi.yaml (runpentests.yml) — 11 operations",
  { text: "identity alice (user): updated from runpentests.yml", tone: "ok" },
  { text: "identity admin (admin): updated from runpentests.yml", tone: "ok" },
  `scan ${SCAN}`,
];

/* Which layer supplies each setting in one example run. */
const PREC_ROWS = [
  { layer: "Flags", note: "this command line", cells: ["critical", "—", "—"] },
  {
    layer: "runpentests.yml",
    note: "committed with the code",
    cells: ["high", "5", "—"],
  },
  {
    layer: "Web settings",
    note: "saved on the scan",
    cells: ["—", "10", "uploaded spec"],
  },
  {
    layer: "Defaults",
    note: "when nothing sets it",
    cells: ["no gate", "scan default", "/openapi.json"],
  },
];
/* Index of the winning row for each column: the highest layer that sets it. */
const PREC_WIN = [0, 1, 2];
const PREC_COLS = ["fail_on", "rps", "spec"];

const FINDINGS: TermLine[] = [
  "$ runpentests findings 645d",
  "ID        SEVERITY  EVIDENCE   CHECK                     TITLE",
  "38170cee  high      verified   bola                      Cross-identity read (BOLA) on GET /accounts/{account_id}",
  "5a4f98da  high      verified   bola                      Cross-identity read (BOLA) on GET /notes/{note_id}",
  "8b1dd4db  high      verified   broken_auth               Auth bypass (random_token) on GET /users/me",
  "026c3213  high      verified   data_exposure             Response exposes payment data on 2 endpoints",
  "f8f4fc84  medium    verified   security_headers          Missing security headers (4) on all endpoints",
  "b1f74ea6  medium    verified   tls_config                Target served over plaintext HTTP (target)",
  "1102c699  medium    heuristic  reflected_injection       Reflected CMDI via query 'q' on GET /search",
  "188a6d60  low       heuristic  signature_injection       LDAP injection lead via query 'q' on GET /search",
  { text: "…", tone: "dim" },
  "17 finding(s)",
  { text: "detail: runpentests findings show 645d5118 <ID>", tone: "dim" },
];

const SHOW: TermLine[] = [
  "$ runpentests findings show 645d 3817",
  {
    text: "Cross-identity read (BOLA) on GET /accounts/{account_id}",
    tone: "accent",
  },
  "high · verified · bola · API1:2023 · unreviewed",
  { text: "fingerprint: 52fc07460b6ad9c67e8a1e18fafbbf86", tone: "dim" },
  "",
  "Object at /accounts/1 rejects anonymous access (401) yet returns an identical,",
  "object-specific response to two different identities ('admin' and 'user').",
  "",
  "remediation:",
  "  Authorize the *object*, not just the caller, in the handler for",
  "  GET /accounts/{account_id}. Look up the record and compare its owner …",
  "",
  "evidence:",
  '  { "anon_status": 401, "identity_a": "admin", "identity_b": "user",',
  '    "route": "/accounts/{account_id}", "status_a": 200, "status_b": 200,',
  '    "trace": [1, 4, 7, 10] }',
  "",
  "# the trace rows behind that finding: who sent what, and what came back",
  "$ runpentests runs trace 645d --check bola",
  "SEQ    METHOD   STATUS       MS  IDENTITY      CHECK                 ROUTE",
  "1      GET      401          21  anonymous     bola                  /accounts/{account_id}",
  "4      GET      200           2  admin         bola                  /accounts/{account_id}",
  "7      GET      200           2  alice         bola                  /accounts/{account_id}",
  "10     GET      200           3  admin         bola                  /accounts/{account_id}",
  "8 shown · 8 match · 66 request(s) in the run",
];

const DIFF: TermLine[] = [
  "$ runpentests runs 4e4c",
  "RUN   STATUS     STARTED           DURATION  FINDINGS  REQUESTS  EXECUTOR  PASSES",
  "3     completed  2026-09-25 17:29  15m22s    56        285       server    confirm,kali,writes,zap,…",
  "2     completed  2026-09-22 23:20  9s        18        88        server    confirm,fuzz,kali,zap",
  "1     completed  2026-09-22 22:56  10s       18        88        server    confirm,fuzz,kali,zap",
  { text: "run 2: did not run: kali, zap", tone: "warn" },
  "",
  "$ runpentests diff 4e4c",
  "run 2 -> run 3",
  "  new:          39",
  "  fixed:        1",
  "  not retested: 0",
  "  unchanged:    17",
  {
    text: "note: the runs used different options, so the comparison is partial",
    tone: "warn",
  },
  "  + high     Privileged function open to low privilege (BFLA) on POST /admin/users/{user_id}/promote",
  "  + high     BOLA (write): PUT /notes/{note_id} write by 'user' persisted",
  "  + medium   Reflected CMDI via body '/title' on POST /notes",
  "  - low      Security header gaps (6) on all endpoints",
  {
    text: "  ? low      Undocumented rate-limit behavior: POST /login",
    tone: "warn",
  },
];

const GATE: TermLine[] = [
  `$ runpentests run 645d --authorized --fail-on high --verified-only`,
  { text: "    0%  scanning 11 operations", tone: "accent" },
  { text: "  …", tone: "dim" },
  { text: "  100%  complete · 17 findings · 66 requests", tone: "ok" },
  "high     verified  bola                     Cross-identity read (BOLA) on GET /accounts/{account_id}",
  "high     verified  bola                     Cross-identity read (BOLA) on GET /notes/{note_id}",
  "high     verified  broken_auth              Auth bypass (random_token) on GET /users/me",
  "high     verified  broken_auth              Auth bypass (random_token) on GET /notes/{note_id}",
  "high     verified  broken_auth              Auth bypass (random_token) on GET /accounts/{account_id}",
  "high     verified  data_exposure            Response exposes payment data on 2 endpoints",
  { text: "6 finding(s) at or above high", tone: "err" },
  "$ echo $?",
  { text: "1", tone: "err" },
];

/* The gate on the sample scan above: 17 findings, nothing dismissed. */
const FUNNEL = [
  { label: "every finding of the run", n: 17 },
  {
    label: (
      <>
        minus findings a person <code>dismissed</code>
      </>
    ),
    n: 17,
  },
  {
    label: (
      <>
        <code>--verified-only</code> — evidence, not leads
      </>
    ),
    n: 9,
  },
  {
    label: (
      <>
        <code>--new-only</code> — off in this example
      </>
    ),
    n: 9,
  },
  {
    label: (
      <>
        at or above <code>--fail-on high</code>
      </>
    ),
    n: 6,
    out: true,
  },
];

const EXITS = [
  { n: 0, t: "clean", d: "nothing at or above --fail-on" },
  { n: 1, t: "findings", d: "something reached --fail-on" },
  { n: 2, t: "usage", d: "bad flag, config or auth; the server refused" },
  { n: 3, t: "failed", d: "scan failed or cancelled, server unreachable" },
  {
    n: 4,
    t: "timeout",
    d: "the AI analysis outlasted the wait; it keeps going",
  },
];

const ACTIONS: TermLine[] = [
  "# .github/workflows/api-scan.yml",
  "- name: runpentests",
  "  env:",
  "    RUNPENTESTS_API_KEY: ${{ secrets.RUNPENTESTS_API_KEY }}",
  "    ALICE_TOKEN: ${{ secrets.ALICE_TOKEN }}",
  "    ADMIN_TOKEN: ${{ secrets.ADMIN_TOKEN }}",
  "  run: runpentests --authorized --output github",
  "",
  "# what the job log receives — GitHub turns each line into an annotation",
  {
    text: "::error title=bola%3A high::Cross-identity read (BOLA) on GET /accounts/{account_id}",
    tone: "err",
  },
  {
    text: "::error title=broken_auth%3A high::Auth bypass (random_token) on GET /users/me",
    tone: "err",
  },
  "6 finding(s) at or above high",
];

const LOCAL: TermLine[] = [
  "$ export RUNPENTESTS_SECRET_ALICE=… RUNPENTESTS_SECRET_ADMIN=…",
  "$ runpentests run 645d --authorized --fail-on high --verified-only",
  "running locally in runpentests-runner:latest (the scan traffic comes from this machine)",
  { text: "    0%  scanning 11 operations", tone: "accent" },
  { text: "  …", tone: "dim" },
  { text: "  100%  complete · 17 findings · 66 requests", tone: "ok" },
  { text: "…", tone: "dim" },
  { text: "6 finding(s) at or above high", tone: "err" },
];

/*
 * What one run tests, by lane and level. The passes and which levels the web
 * offers come from SCAN_LEVELS (scanLevels.ts, itself checked against
 * app/scans/run_levels.py by test_coverage_mirror.py); the CLI runs every
 * level, since LOCAL_REFUSED is empty. Only the words live here: a pass with
 * no label still shows, under its key, rather than going missing.
 */
const PASS_LABEL: Record<string, string> = {
  fuzz: "schema fuzzing",
  premium: "premium detections¹",
  zap: "ZAP",
  kali: "Kali: nuclei · ffuf · katana · arjun, then a re-probe of what they found",
  confirm: "sqlmap · dalfox · commix · tplmap",
  testssl: "testssl",
  plan: "risk plan",
  adjudicate: "verdicts on BOLA · BFLA · SSRF",
  security_review: "security review",
  genai_payloads: "generated payloads",
  adaptive: "adaptive¹",
  resource_refine: "resource refinement¹ ²",
};
const label = (p: string) => PASS_LABEL[p] ?? p;

/* Each level's chips are what it adds to the one below. */
const levelRows = SCAN_LEVELS.map((l, i) => {
  const below = new Set(i > 0 ? SCAN_LEVELS[i - 1].passes : []);
  const chips =
    i === 0
      ? ["OWASP API Top 10 engine checks"]
      : l.passes.filter((p) => !below.has(p)).map((p) => `+ ${label(p)}`);
  return {
    k: l.title,
    note: i === 0 ? "the default" : `--level ${l.id}`,
    web: chips,
    cli: chips,
  };
});

/* The AI switch adds the passes that fit the level; Deep adds the in-loop ones. */
const aiOn = (levels: typeof SCAN_LEVELS) => [
  ...new Set(levels.flatMap((l) => l.aiPasses)),
];
const webAi = SCAN_LEVELS[0].aiPasses;
const deepOnlyAi = aiOn(SCAN_LEVELS).filter((p) => !webAi.includes(p));

const WRITES = [
  "write authorization",
  "mass assignment",
  "races",
  "seeded BOLA",
  "body-field injection",
];

const LEVEL_ROWS: {
  k: string;
  note: string;
  web: string[] | null;
  cli: string[];
}[] = [
  ...levelRows,
  {
    k: "AI",
    note: "--ai, spends tokens",
    web: [
      ...webAi.map(label),
      ...(deepOnlyAi.length
        ? [`at Deep: ${deepOnlyAi.map(label).join(", ")}`]
        : []),
    ],
    cli: [
      ...webAi.map(label),
      ...(deepOnlyAi.length
        ? [`at Deep: ${deepOnlyAi.map(label).join(", ")}`]
        : []),
    ],
  },
  { k: "Writes", note: "--writes, changes data", web: WRITES, cli: WRITES },
  {
    k: "CLI only",
    note: "no web switch",
    web: null,
    cli: [
      "source DIR → file:line",
      "runpentests.yml",
      "exit-code gate",
      "database schema context",
      "bounded agent³",
    ],
  },
];

/* Where a CLI run's data goes. Verified against RunnerComplete and the claim. */
const UPLOADED = [
  {
    t: "Before the run",
    d: "the claim (target, level, passes, the runpentests.yml digest), the spec when it changed, each identity's name, role and auth type",
  },
  {
    t: "While it runs",
    d: "events and a heartbeat; the operation list for --plan; redacted evidence (status, field names, error excerpts) for the in-loop AI",
  },
  {
    t: "When it ends",
    d: "findings, endpoint coverage, gaps, the request trace (capped near 1 MB) and the methodology manifest, redacted here and again on the service",
  },
  {
    t: "Only if you ask",
    d: "with a DIR, file:line citations and short redacted snippets; with schema:, a structure-only database snapshot",
  },
];
const STAYS = [
  "identity secrets: stdin to the runner, nowhere else",
  "your API key: the runner holds a per-run token",
  "the database password",
  "your source tree",
  "raw, unredacted responses",
];
const SERVICE = [
  "fingerprints, remediation and triage",
  "the diff between runs",
  "AI verdicts and the security review",
  "reports and the scan page in the web",
];

const COMMANDS: { c: string; d: string }[] = [
  {
    c: "runpentests URL [DIR]",
    d: "Scan an API in one step from this machine; a DIR adds your code.",
  },
  {
    c: "runpentests",
    d: "Inside a project: run what runpentests.yml describes.",
  },
  {
    c: "login --server URL [--profile NAME]",
    d: "Save a server as a profile; logout removes the current one.",
  },
  {
    c: "status",
    d: "Check the connection and which passes this server can run.",
  },
  {
    c: "profile list | use NAME | rm NAME",
    d: "Switch between saved servers; never prints a key.",
  },
  {
    c: "scans list | show [ID] | rm ID",
    d: "Manage scans; IDs may be the first 4+ hex characters.",
  },
  {
    c: "scan create --target URL --spec FILE",
    d: "Create a scan from OpenAPI, Swagger, HAR or Postman.",
  },
  {
    c: "cred add ID … | list | rm",
    d: "Manage identities; the secret is write-only on the server.",
  },
  {
    c: "run ID [pass flags]",
    d: "Run a scan from this machine; --fail-on gates it.",
  },
  {
    c: "wait ID [--fail-on SEV]",
    d: "Attach to a run still going (AI analysis, a web run), then gate.",
  },
  { c: "cancel ID", d: "Stop a run at the next check boundary." },
  {
    c: "findings [ID] · show · dismiss | confirm | reopen",
    d: "List, inspect or triage findings.",
  },
  {
    c: "diff [ID] · runs [ID] · runs trace",
    d: "Compare runs, list history, read the redacted request log.",
  },
  {
    c: "coverage [ID] [--untested] · cost [ID]",
    d: "What each endpoint got; what the AI passes spent.",
  },
  {
    c: "report [ID] --format pdf|html|pentest|sarif|json",
    d: "Download a report, written 0600.",
  },
  {
    c: "completion bash|zsh|fish · version",
    d: "Shell completion; the build's version.",
  },
];

export default function CliGuide() {
  return (
    <>
      <GuideHero kind="cli" />
      <GuideNav label="CLI guide sections" sections={TOC} />

      <section className="wrap guide-sec" id="install">
        <SectionLabel>01 · Install & connect</SectionLabel>
        <h2 className="h-lg">Install it, then log in once</h2>
        <div className="guide-split">
          <div className="guide-copy">
            <p>
              The CLI is one static binary for macOS, Linux and Windows. Put{" "}
              <code>runpentests</code> on your <code>PATH</code>; it needs no
              runtime.
            </p>
            <p>
              <code>login</code> connects to <code>https://aidetector.com</code>{" "}
              and saves a profile: the server and your key, in a file only you
              can read. A self-hosted server takes <code>--server URL</code>;
              save several with <code>--profile</code> and switch with{" "}
              <code>profile use</code>.
            </p>
            <ul>
              <li>
                <b>The key is never a flag.</b> It is prompted for, piped with{" "}
                <code>--key-stdin</code>, or read from{" "}
                <code>RUNPENTESTS_API_KEY</code>. That way it stays out of shell
                history and <code>ps</code>.
              </li>
              <li>
                <code>status</code> shows which optional passes this server can
                actually run before you ask for one.
              </li>
            </ul>
          </div>
          <Terminal title="install" lines={INSTALL} />
        </div>
      </section>

      <section className="wrap guide-sec" id="everyday">
        <SectionLabel>02 · The everyday form</SectionLabel>
        <h2 className="h-lg">
          <code>runpentests URL</code> does five things
        </h2>
        <p className="lead">
          The everyday form chains the subcommands in this order, and the first
          step comes before any request leaves your machine.
        </p>
        <ol className="pipe">
          {PIPE.map((s, i) => (
            <li key={s.t} className={s.gate ? "pipe-gate" : undefined}>
              <span className="pipe-n">{i + 1}</span>
              <h3>{s.t}</h3>
              <p>{s.d}</p>
              <span className="pipe-src">{s.src}</span>
            </li>
          ))}
        </ol>
        <div className="guide-split wide">
          <div className="guide-copy">
            <h3>The first run</h3>
            <p>
              A new target creates a scan. The spec is fetched from the
              target&apos;s own <code>/openapi.json</code>, and with no
              identities the CLI asks for two. The authorization checks (BOLA,
              BFLA, broken auth) compare one user&apos;s view with
              another&apos;s.
            </p>
            <p>
              Progress is the server&apos;s event log. A check that had nothing
              to work against says so (<i>did not run: …</i>), so an empty
              result never quietly stands in for &ldquo;clean&rdquo;.
            </p>
            <h3 style={{ marginTop: 24 }}>Every run after</h3>
            <p>
              The same command reuses the scan for that target. Identities,
              triage and history carry over, which is what makes{" "}
              <code>diff</code> and <code>--new-only</code> meaningful.
            </p>
            <p>
              Add a directory and the run happens on your machine, with the code
              mounted read-only. Findings then cite the <code>file:line</code>{" "}
              behind them.
            </p>
          </div>
          <div style={{ display: "grid", gap: 20, minWidth: 0 }}>
            <Terminal title="first run" lines={FIRST_RUN} highlight />
            <Terminal title="next day" lines={SECOND_RUN} />
          </div>
        </div>
      </section>

      <section className="wrap guide-sec" id="project">
        <SectionLabel>03 · The project file</SectionLabel>
        <h2 className="h-lg">Commit runpentests.yml</h2>
        <p className="lead">
          The target, spec, identities and gate live in the repository, so a
          bare <code>runpentests</code> (or{" "}
          <code>runpentests --authorized</code> in CI) does the right thing.
        </p>
        <div className="guide-split">
          <div className="guide-copy">
            <h3>Which value wins</h3>
            <p>
              Precedence is decided per setting, not per file. In this example a
              flag overrides <code>fail_on</code>, the file sets{" "}
              <code>rps</code>, and with no <code>spec:</code> the spec uploaded
              in the web stands.
            </p>
            <div className="prec-wrap" style={{ marginTop: 16 }}>
              <table className="prec">
                <caption className="sr-only">
                  Which configuration value wins for this run
                </caption>
                <colgroup>
                  <col />
                  <col />
                  <col />
                  <col />
                </colgroup>
                <thead>
                  <tr>
                    <th scope="col">layer</th>
                    {PREC_COLS.map((c) => (
                      <th scope="col" key={c}>
                        {c}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {PREC_ROWS.map((r, ri) => (
                    <tr key={r.layer}>
                      <th scope="row">
                        {r.layer}
                        <small>{r.note}</small>
                      </th>
                      {r.cells.map((cell, ci) => (
                        <td
                          key={ci}
                          className={PREC_WIN[ci] === ri ? "win" : undefined}
                        >
                          {cell}
                        </td>
                      ))}
                    </tr>
                  ))}
                </tbody>
                <tfoot>
                  <tr>
                    <th scope="row">This run uses</th>
                    <td>critical</td>
                    <td>5</td>
                    <td>uploaded spec</td>
                  </tr>
                </tfoot>
              </table>
            </div>
            <h3 style={{ marginTop: 24 }}>What the file can never hold</h3>
            <ul>
              <li>
                <b>Secrets.</b> A <code>token:</code> or <code>password:</code>{" "}
                key is refused; each identity names its <code>secret_env</code>{" "}
                instead.
              </li>
              <li>
                <b>Consent.</b> There is no <code>authorized:</code> key. A
                committed file travels into forks, and the person running the
                command answers the gate.
              </li>
              <li>
                <b>More than the server allows.</b> The request budget, rate
                ceiling and target guard are the server&apos;s. The file can ask
                for less, never more.
              </li>
            </ul>
            <p className="guide-note">
              Settings the file owns show read-only in the web, marked
              &ldquo;set by runpentests.yml&rdquo;, until someone hands them
              back.
            </p>
          </div>
          <Terminal title="my-project" lines={PROJECT_FILE} />
        </div>
      </section>

      <section className="wrap guide-sec" id="results">
        <SectionLabel>04 · Read the results</SectionLabel>
        <h2 className="h-lg">Findings, evidence, and what changed</h2>
        <p className="lead">
          Where an ID is optional, <code>runpentests.yml</code> picks the scan,
          and any ID can be shortened to its first four hex characters.{" "}
          <code>verified</code> means the evidence demonstrates the weakness;{" "}
          <code>heuristic</code> marks a lead worth checking.
        </p>
        <div className="guide-split wide">
          <div className="guide-copy">
            <h3>List, then open one</h3>
            <p>
              <code>findings</code> lists every finding, with a{" "}
              <code>--check</code>, <code>--min-severity</code> or{" "}
              <code>--verified</code> filter. <code>findings show</code> takes
              an ID or a fingerprint prefix and prints the description,
              remediation, references and redacted evidence.
            </p>
            <p>
              The evidence&apos;s <code>trace</code> lists the request numbers
              behind the finding. <code>runs trace</code> prints those rows:
              which identity sent each request and what status came back.
              Credentials are always masked.
            </p>
            <p>
              Triage from here with <code>findings dismiss 645d 1102</code>. A
              dismissed finding stays dismissed on later runs, because triage
              follows the finding&apos;s fingerprint.
            </p>
          </div>
          <div style={{ display: "grid", gap: 20, minWidth: 0 }}>
            <Terminal title="findings" lines={FINDINGS} highlight />
            <Terminal title="one finding" lines={SHOW} highlight />
          </div>
        </div>
        <div className="guide-split wide">
          <div className="guide-copy">
            <h3>Compare runs</h3>
            <p>
              <code>runs</code> is the history, including passes that did not
              run. <code>diff</code> sorts the latest run against the one before
              it:
            </p>
            <ul>
              <li>
                <code>+</code> new since the previous run
              </li>
              <li>
                <code>-</code> fixed: the check ran again and stayed quiet
              </li>
              <li>
                <code>?</code> not retested. The newer run skipped the pass that
                found it, so it cannot count as fixed.
              </li>
            </ul>
            <p>
              The diff also warns when the two runs used different options or a
              different executor (the web&apos;s server run vs. a CLI run),
              because either can make a finding look new or fixed.
            </p>
          </div>
          <Terminal title="history" lines={DIFF} highlight />
        </div>
      </section>

      <section className="wrap guide-sec" id="ci">
        <SectionLabel>05 · Gate a pipeline</SectionLabel>
        <h2 className="h-lg">The exit code is the verdict</h2>
        <p className="lead">
          <code>--fail-on</code> turns a run into a check. Progress goes to
          stderr and the gate to stdout, so <code>--output json</code>,{" "}
          <code>github</code> and <code>junit</code> stay machine-readable.
        </p>
        <div className="guide-split wide">
          <div className="guide-copy">
            <h3>What reaches the gate</h3>
            <p>
              Each filter narrows the findings that can fail the build. Here is
              the sample scan run through{" "}
              <code>--fail-on high --verified-only</code>:
            </p>
            <ol className="funnel" style={{ marginTop: 16 }}>
              {FUNNEL.map((f, i) => (
                <li key={i} className={f.out ? "funnel-out" : undefined}>
                  <div className="funnel-bar">
                    <b style={{ width: `${(f.n / FUNNEL[0].n) * 100}%` }} />
                    <span>{f.label}</span>
                  </div>
                  <span className="funnel-n">{f.n}</span>
                </li>
              ))}
            </ol>
            <p className="funnel-verdict">
              6 findings reach the threshold, so the command exits <b>1</b> and
              the build fails.
            </p>
            <p className="guide-note">
              <code>--new-only</code> judges only what is new since the previous
              run, so a pipeline fails on regressions rather than known debt.
            </p>
          </div>
          <Terminal title="ci gate" lines={GATE} highlight />
        </div>
        <ul className="exits" aria-label="Exit codes">
          {EXITS.map((x) => (
            <li key={x.n} className={`x${x.n}`}>
              <b>{x.n}</b>
              <strong>{x.t}</strong>
              <span>{x.d}</span>
            </li>
          ))}
        </ul>
        <div className="guide-split wide">
          <div className="guide-copy">
            <h3>In GitHub Actions</h3>
            <p>
              With a committed <code>runpentests.yml</code> the step is one
              line. The API key and each identity&apos;s secret come from
              repository secrets, and <code>--authorized</code> is the
              pipeline&apos;s explicit consent. Without a terminal, the CLI
              refuses to run unless that flag is given.
            </p>
            <p>
              <code>--output github</code> prints one workflow command per
              failing finding, and GitHub turns each into an annotation on the
              job. For code scanning, upload <code>report --format sarif</code>.
              Only verified evidence maps to the <code>error</code> level.
            </p>
            <p>
              The scan runs on the CI machine, so the job needs Docker and the
              runner image. To gate again later without re-running, use{" "}
              <code>wait ID --fail-on high</code>.
            </p>
          </div>
          <Terminal title="github actions" lines={ACTIONS} />
        </div>
      </section>

      <section className="wrap guide-sec" id="local">
        <SectionLabel>06 · How a run works</SectionLabel>
        <h2 className="h-lg">The traffic leaves from your machine</h2>
        <p className="lead">
          Every CLI run sends its traffic from your machine, so it reaches an
          API only you can see: an internal host, a service behind a VPN,{" "}
          <code>localhost</code>. The results and the full request log go to the
          service, which grades, fingerprints and diffs them, runs the AI
          analysis and renders the reports. A run needs Docker on your machine.
        </p>
        <div className="lanes">
          <div className="lane lane-mine">
            <h3>Your machine</h3>
            <div className="lane-box">
              <strong>runpentests CLI</strong>
              <span>
                Finds each secret locally: a <code>--secrets-file</code>,{" "}
                <code>secret_env</code> or{" "}
                <code>RUNPENTESTS_SECRET_&lt;NAME&gt;</code>.
              </span>
            </div>
            <div className="lane-box locked">
              <strong>Runner container</strong>
              <span>
                Read-only, non-root, no capabilities, no Docker socket. Holds a
                per-run token, never the API key.
              </span>
            </div>
          </div>
          <ol className="lane-flows" aria-label="What travels where">
            <li data-n="1">
              <b>Claim</b> → server: answers the authorization gate, target
              guard and premium check; issues the budget and a token
            </li>
            <li data-n="2" className="back">
              <b>Secrets</b> → container on stdin only: never argv, env or the
              server
            </li>
            <li data-n="3">
              <b>Scan traffic</b> → target, within the server&apos;s request
              budget; cloud metadata always refused
            </li>
            <li data-n="4">
              <b>AI asks</b> → server: the plan and in-loop AI run there, on
              redacted evidence; the answer comes back, the traffic stays here
            </li>
            <li data-n="5">
              <b>Results</b> → server: findings, coverage, gaps and the request
              trace, redacted here and again there, on the run token alone
            </li>
          </ol>
          <div style={{ display: "grid", gap: 14 }}>
            <div className="lane">
              <h3>runpentests server</h3>
              <div className="lane-box">
                <strong>Grades the run</strong>
                <span>
                  Fingerprints, remediation, triage and the diff are the
                  server&apos;s, whichever machine sent the traffic.
                </span>
              </div>
            </div>
            <div className="lane">
              <h3>Target API</h3>
              <div className="lane-box">
                <strong>Private or internal</strong>
                <span>
                  Reachable from your machine, not the server&apos;s worker.
                </span>
              </div>
            </div>
          </div>
        </div>
        <div className="guide-split wide">
          <div className="guide-copy">
            <h3>What runs where</h3>
            <p>
              Every pass that sends traffic runs here: the engine checks and, at{" "}
              <code>--level deep</code>, the tools. ZAP and Kali start as
              sibling containers on your <code>--docker-network</code>; sqlmap,
              dalfox, commix, tplmap and testssl run inside the runner. The
              model calls happen on the service, which holds the keys and the
              spend cap: <code>--plan</code> before the first check, the in-loop
              AI while the run asks, then verdicts and the security review after
              the upload, while the CLI waits.
            </p>
            <p>
              A loopback server or target is rewritten to{" "}
              <code>host.docker.internal</code>, because <code>localhost</code>{" "}
              inside the container is the container itself. Override this with{" "}
              <code>--runner-server</code> and <code>--docker-network</code>.
            </p>
            <p>
              Ctrl-C stops the container and the run ends <code>cancelled</code>
              . If the container dies, the CLI closes the run so the scan is
              never left locked.
            </p>
          </div>
          <Terminal title="local run" lines={LOCAL} highlight />
        </div>
      </section>

      <section className="wrap guide-sec" id="web-or-cli">
        <SectionLabel>07 · Web or CLI</SectionLabel>
        <h2 className="h-lg">What a run tests, by where you start it</h2>
        <p className="lead">
          Both lanes run the same engine and land on the same scan page. The
          difference is where the traffic comes from and whether local source
          code is available. A run from the web is sent by the service&apos;s
          own worker, so the target must be reachable from the service; an
          internal host only your machine can see is a CLI run. In either lane a
          public host needs a verified domain. Local CLI execution is available
          on Free; web execution and server schedules require Premium.
        </p>
        <div
          className="lvl"
          role="table"
          aria-label="What each lane runs at each level"
        >
          <div className="lvl-row lvl-head" role="row">
            <span role="columnheader">Level / switch</span>
            <span role="columnheader">
              <b>Run from the web <PlanBadge premium /></b>
              <small>traffic from the service&apos;s worker</small>
            </span>
            <span role="columnheader">
              <b>Run from the CLI</b>
              <small>traffic from your machine</small>
            </span>
          </div>
          {LEVEL_ROWS.map((r) => (
            <div className="lvl-row" role="row" key={r.k}>
              <span className="lvl-k" role="rowheader">
                <b>{r.k}</b>
                <small>{r.note}</small>
              </span>
              <span className="lvl-cell" role="cell" data-lane="Web">
                {r.web ? (
                  r.web.map((p) => (
                    <span className="lvl-chip" key={p}>
                      {p}
                    </span>
                  ))
                ) : (
                  <span className="lvl-chip off">
                    not offered — use the CLI
                  </span>
                )}
              </span>
              <span className="lvl-cell" role="cell" data-lane="CLI">
                {r.cli.map((p) => (
                  <span className="lvl-chip" key={p}>
                    {p}
                  </span>
                ))}
              </span>
            </div>
          ))}
        </div>
        <p className="guide-note">
          Levels add up: Deep includes Standard, which includes Quick. A level
          never turns on writes or AI; each is its own switch. ¹ Premium plan
          only, left out otherwise. ² Needs <code>--writes</code> too. ³ Its
          tool sandbox is off unless the operator enables one. Blind
          (out-of-band) checks run in either lane when the service runs a
          callback collector and the target can reach it.
        </p>

        <h3 className="flow-h">
          What goes to the service, and what never leaves your machine
        </h3>
        <div className="flow">
          <div className="flow-col flow-up">
            <h4>Uploaded to the service</h4>
            <ol>
              {UPLOADED.map((u) => (
                <li key={u.t}>
                  <b>{u.t}</b>
                  <span>{u.d}</span>
                </li>
              ))}
            </ol>
          </div>
          <div className="flow-col flow-stay">
            <h4>Stays on your machine</h4>
            <ul>
              {STAYS.map((s) => (
                <li key={s}>{s}</li>
              ))}
            </ul>
          </div>
          <div className="flow-col flow-svc">
            <h4>Then the service does</h4>
            <ul>
              {SERVICE.map((s) => (
                <li key={s}>{s}</li>
              ))}
            </ul>
            <p>
              The same for a web run. The diff notes when two runs came from
              different lanes, since a new vantage point can make a finding look
              new or fixed.
            </p>
          </div>
        </div>
      </section>

      <section className="wrap guide-sec guide-end" id="reference">
        <SectionLabel>08 · Command reference</SectionLabel>
        <h2 className="h-lg">Every command</h2>
        <p className="lead">
          <code>runpentests help &lt;command&gt;</code> prints a command&apos;s
          flags, what each pass costs, and examples. Every pass flag (
          <code>--writes</code>, <code>--zap</code>, <code>--adjudicate</code>,
          …) is off unless you ask for it.
        </p>
        <div className="cmd-table-wrap">
          <table className="cmd-table">
            <thead>
              <tr>
                <th scope="col">command</th>
                <th scope="col">does</th>
              </tr>
            </thead>
            <tbody>
              {COMMANDS.map((c) => (
                <tr key={c.c}>
                  <td>
                    <code>{c.c}</code>
                  </td>
                  <td>{c.d}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <p className="guide-note">
          Prefer the browser? The same scans open under{" "}
          <Link href="/scans">Scans</Link>, and{" "}
          <Link href="/coverage">Coverage</Link> explains what each check looks
          for.
        </p>
      </section>
    </>
  );
}
