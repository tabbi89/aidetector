/**
 * Static, server-rendered explainers for the landing page.
 *
 * These mirror the engine described in CLAUDE.md — the scan lifecycle in
 * `app/engine/runner.py` and the three evidence tiers documented in
 * `lib/coverage.ts`. They are hand-maintained, like coverage.ts: if the engine
 * changes how it decides, the pictures change with it.
 */

import { apiCoverage } from "@/lib/coverage";
import { TierChip } from "./TierChip";

export interface Stage {
  n: string;
  title: string;
  body: string;
  note?: string;
}

export const STAGES: Stage[] = [
  {
    n: "01",
    title: "Describe the API",
    body: "Upload an OpenAPI or Swagger spec. The parser flattens it into concrete operations — method, path, parameters, auth scope — so every later step works from a real endpoint list, not a crawl.",
    note: "POST /scans/{id}/spec",
  },
  {
    n: "02",
    title: "Hand over two identities",
    body: "A high-privilege and a low-privilege credential profile. Authorization bugs only show up as a difference between two roles, so the second identity is what makes the interesting checks possible.",
    note: "Encrypted at rest · decrypted only in the worker",
  },
  {
    n: "03",
    title: "Authorise the run",
    body: "The run endpoint refuses without an explicit authorized flag, and the UI asks for it again with a checkbox. Active scanning fires real payloads at a live host, so consent is a hard gate, not a setting.",
    note: "403 without authorized: true",
  },
  {
    n: "04",
    title: "Probe",
    body: "Each check replays your operations with mutated inputs and watches what comes back. The whole scan is capped at 750 requests, a broken check can never abort the run, and cancellation lands at the next check boundary.",
    note: "750-request budget per scan",
  },
  {
    n: "05",
    title: "Adapt the validation test",
    body: "Premium runs select the highest-risk spec-shaped parameter. GET query/path probes stay read-only; JSON fields on POST, PUT and PATCH are tested only when the explicit Test writes gate is on. A valid control comes first, then a bounded variant loop inspects response structure only.",
    note: "2–3 variants · body tests need writes",
  },
  {
    n: "06",
    title: "Grade the evidence",
    body: "Every finding carries the literal signal that produced it, graded into one of three tiers. Opt-in Kali tools re-test leads to promote them to confirmations, and the Opus + DeepSeek cascade adjudicates the judgment-heavy classes with a rationale plus a token-cost ledger.",
    note: "Verdict · rationale · cost",
  },
  {
    n: "07",
    title: "Read the report",
    body: "Findings arrive live: severity, the request and response that proved it, a streaming event log, and an HTML or JSON export when the run finishes. An optional DeepSeek design review compares the OpenAPI structure with available database metadata and saves security improvement suggestions separately.",
    note: "GET /scans/{id}/findings",
  },
];

export type GlKey = "gl-read" | "gl-ok" | "gl-gate" | "gl-tgt" | "gl-ev" | "gl-ai";

/** A keyed swatch row under each flow diagram, so the colour code is explicit. */
function GraphLegend({ items }: { items: { cls: GlKey; label: string }[] }) {
  return (
    <figcaption className="graph-legend">
      {items.map((i) => (
        <span className={`gl ${i.cls}`} key={i.label}>
          {i.label}
        </span>
      ))}
    </figcaption>
  );
}

/**
 * The adaptive pass in one picture. One left-to-right spine — pick a field,
 * choose the sink, send a valid control, then a bounded variant loop — with the
 * one intentional branch drawn as two lanes: GET query/path is read-only, a JSON
 * body field needs the explicit mutation gate. The engine, not the model, owns
 * the allowlist, the request budget and the final evidence.
 */
export function AdaptiveValidationGraph() {
  return (
    <figure className="graph-fig">
      <svg
        viewBox="0 0 900 320"
        role="img"
        className="probe-svg adaptive-graph"
        aria-label="Adaptive validation: select a spec-shaped field, branch into a read-only GET sink or a mutation-gated JSON body sink, send a valid control, then run a bounded variant loop the optional planner can steer — inspecting response structure only."
      >
        <defs>{arrow("fa-adaptive")}</defs>

        <g className="node">
          <rect x="20" y="118" width="152" height="60" rx="10" />
          <text x="96" y="144" className="lbl">OpenAPI field</text>
          <text x="96" y="160" className="sub">type · bounds · enum</text>
        </g>
        <g className="node target">
          <rect x="204" y="118" width="152" height="60" rx="10" />
          <text x="280" y="144" className="lbl">Select one field</text>
          <text x="280" y="160" className="sub">risk-ranked · bounded</text>
        </g>
        <g className="node ok-node">
          <rect x="404" y="44" width="190" height="56" rx="10" />
          <text x="499" y="68" className="lbl">GET query / path</text>
          <text x="499" y="84" className="sub">read-only branch</text>
        </g>
        <g className="node gate-node">
          <rect x="404" y="196" width="190" height="56" rx="10" />
          <text x="499" y="220" className="lbl">JSON body field</text>
          <text x="499" y="236" className="sub">needs writes</text>
        </g>
        <g className="node">
          <rect x="636" y="118" width="120" height="60" rx="10" />
          <text x="696" y="144" className="lbl">valid control</text>
          <text x="696" y="160" className="sub">baseline first</text>
        </g>
        <g className="node target">
          <rect x="788" y="118" width="96" height="60" rx="10" />
          <text x="836" y="144" className="lbl">v1·v2·v3</text>
          <text x="836" y="160" className="sub">max 2–3</text>
        </g>

        <g className="wire">
          <path d="M172 148 H204" markerEnd="url(#fa-adaptive)" />
          <path d="M356 148 H380 V72 H404" markerEnd="url(#fa-adaptive)" />
          <path d="M356 148 H380 V224 H404" markerEnd="url(#fa-adaptive)" />
          <path d="M594 72 H616 V148 H636" markerEnd="url(#fa-adaptive)" />
          <path d="M594 224 H616 V148 H636" markerEnd="url(#fa-adaptive)" />
          <path d="M756 148 H788" markerEnd="url(#fa-adaptive)" />
          <path d="M792 118 C 788 84 880 84 876 118" markerEnd="url(#fa-adaptive)" />
        </g>
        <text x="836" y="78" className="sub">iterate</text>

        <g className="node ai-node">
          <rect x="300" y="276" width="300" height="30" rx="6" />
          <text x="450" y="295" className="tiny">optional planner · proposes the next variant</text>
        </g>
        <g className="wire dashed ai-wire">
          <path d="M600 291 H836 V180" markerEnd="url(#fa-adaptive)" />
        </g>

        <text x="636" y="206" className="verdict">Evidence: status · shape · size · latency</text>
        <text x="20" y="304" className="verdict warn">
          Accepted invalid shape → validation-gap lead
        </text>
        <text x="520" y="304" className="verdict ok">
          No body values or samples persisted
        </text>
      </svg>
      <GraphLegend
        items={[
          { cls: "gl-read", label: "Read-only (GET)" },
          { cls: "gl-gate", label: "Gated (writes)" },
          { cls: "gl-tgt", label: "Engine-owned" },
          { cls: "gl-ai", label: "Optional planner" },
        ]}
      />
    </figure>
  );
}

/**
 * Resource setup as a spine with one loop. A predefined id or a deterministic,
 * spec-shaped body feeds an authorized create; a 2xx is registered and reused,
 * while a rejection can enter an explicitly approved, bounded analyse → refine →
 * recreate loop. Every retry stays inside its cap.
 */
export function ResourceLifecycleGraph() {
  return (
    <figure className="graph-fig">
      <svg
        viewBox="0 0 900 300"
        role="img"
        className="probe-svg adaptive-graph"
        aria-label="Resource lifecycle: a predefined id or a deterministic OpenAPI body feeds an authorized create; an accepted resource is registered and reused, and a rejection can enter a bounded analyse, refine, and recreate loop."
      >
        <defs>{arrow("fa-lifecycle")}</defs>

        <g className="node">
          <rect x="20" y="40" width="150" height="56" rx="10" />
          <text x="95" y="64" className="lbl">OpenAPI schema</text>
          <text x="95" y="80" className="sub">required · enum · format</text>
        </g>
        <g className="node target">
          <rect x="196" y="40" width="160" height="56" rx="10" />
          <text x="276" y="64" className="lbl">deterministic body</text>
          <text x="276" y="80" className="sub">safe generated values</text>
        </g>
        <g className="node gate-node">
          <rect x="382" y="40" width="150" height="56" rx="10" />
          <text x="457" y="64" className="lbl">POST create</text>
          <text x="457" y="80" className="sub">authorized + writes</text>
        </g>
        <g className="node ok-node">
          <rect x="564" y="40" width="160" height="56" rx="10" />
          <text x="644" y="64" className="lbl">create response</text>
          <text x="644" y="80" className="sub">status + structure</text>
        </g>
        <g className="node ok-node">
          <rect x="750" y="40" width="140" height="56" rx="10" />
          <text x="820" y="64" className="lbl">register · reuse id</text>
          <text x="820" y="80" className="sub">2xx → further checks</text>
        </g>
        <g className="node">
          <rect x="20" y="150" width="150" height="56" rx="10" />
          <text x="95" y="174" className="lbl">predefined id</text>
          <text x="95" y="190" className="sub">no create needed</text>
        </g>
        <g className="node">
          <rect x="400" y="206" width="180" height="56" rx="10" />
          <text x="490" y="230" className="lbl">analyse rejection + DB</text>
          <text x="490" y="246" className="sub">400 · 409 · 422 · metadata</text>
        </g>
        <g className="node ai-node">
          <rect x="612" y="206" width="180" height="56" rx="10" />
          <text x="702" y="230" className="lbl">AI refine + recreate</text>
          <text x="702" y="246" className="sub">premium · max 2–3</text>
        </g>

        <g className="wire">
          <path d="M170 68 H196" markerEnd="url(#fa-lifecycle)" />
          <path d="M356 68 H382" markerEnd="url(#fa-lifecycle)" />
          <path d="M532 68 H564" markerEnd="url(#fa-lifecycle)" />
          <path d="M724 68 H750" markerEnd="url(#fa-lifecycle)" />
          <path d="M170 178 H362 V68 H382" markerEnd="url(#fa-lifecycle)" />
          <path d="M644 96 V180 H490 V206" markerEnd="url(#fa-lifecycle)" />
          <path d="M580 234 H612" markerEnd="url(#fa-lifecycle)" />
        </g>
        <g className="wire dashed ai-wire">
          <path d="M702 206 V150 H457 V96" markerEnd="url(#fa-lifecycle)" />
        </g>
        <text x="632" y="146" className="sub">recreate ≤ 3</text>

        <text x="20" y="286" className="verdict">
          Every core POST / PUT / PATCH / DELETE → sanitized structural log
        </text>
        <text x="560" y="286" className="verdict ok">
          No headers, ids, values, or DB rows persisted
        </text>
      </svg>
      <GraphLegend
        items={[
          { cls: "gl-tgt", label: "Deterministic body" },
          { cls: "gl-gate", label: "Gated write" },
          { cls: "gl-ok", label: "Accepted (2xx)" },
          { cls: "gl-ai", label: "AI refine (opt)" },
        ]}
      />
    </figure>
  );
}

/**
 * The flow of one test end to end: select, resolve, build, request, then the
 * evidence and the finding on a second row — with the decision (which test,
 * which payload) kept visually apart from the observed result. A valid resource
 * is captured and reused; a create rejection can take the bounded refine loop.
 */
export function TestingFlowGraph() {
  return (
    <figure className="graph-fig">
      <svg
        viewBox="0 0 900 300"
        role="img"
        className="probe-svg adaptive-graph"
        aria-label="Testing flow: select a spec operation, resolve a provided or created resource id, build a spec-shaped payload, send a gated request, capture redacted evidence and a finding, reuse the valid resource, and take a bounded refine loop only on a create rejection."
      >
        <defs>{arrow("fa-testflow")}</defs>

        <g className="node">
          <rect x="20" y="44" width="132" height="54" rx="10" />
          <text x="86" y="67" className="lbl">spec</text>
          <text x="86" y="83" className="sub">operations + schemas</text>
        </g>
        <g className="node ai-node">
          <rect x="174" y="44" width="150" height="54" rx="10" />
          <text x="249" y="67" className="lbl">select test</text>
          <text x="249" y="83" className="sub">engine or AI plan</text>
        </g>
        <g className="node target">
          <rect x="346" y="44" width="158" height="54" rx="10" />
          <text x="425" y="67" className="lbl">resolve resource</text>
          <text x="425" y="83" className="sub">provided or created id</text>
        </g>
        <g className="node">
          <rect x="526" y="44" width="138" height="54" rx="10" />
          <text x="595" y="67" className="lbl">build payload</text>
          <text x="595" y="83" className="sub">spec-shaped values</text>
        </g>
        <g className="node gate-node">
          <rect x="686" y="44" width="150" height="54" rx="10" />
          <text x="761" y="67" className="lbl">request</text>
          <text x="761" y="83" className="sub">gated + budgeted</text>
        </g>

        <g className="node">
          <rect x="40" y="176" width="150" height="54" rx="10" />
          <text x="115" y="199" className="lbl">valid resource</text>
          <text x="115" y="215" className="sub">reuse in later tests</text>
        </g>
        <g className="node ai-node">
          <rect x="270" y="176" width="170" height="54" rx="10" />
          <text x="355" y="199" className="lbl">optional refine</text>
          <text x="355" y="215" className="sub">create rejection only</text>
        </g>
        <g className="node ok-node">
          <rect x="520" y="176" width="160" height="54" rx="10" />
          <text x="600" y="199" className="lbl">safe evidence</text>
          <text x="600" y="215" className="sub">status · shape · timing</text>
        </g>
        <g className="node warn-node">
          <rect x="716" y="176" width="150" height="54" rx="10" />
          <text x="791" y="199" className="lbl">finding</text>
          <text x="791" y="215" className="sub">evidence → verdict</text>
        </g>

        <g className="wire">
          <path d="M152 71 H174" markerEnd="url(#fa-testflow)" />
          <path d="M324 71 H346" markerEnd="url(#fa-testflow)" />
          <path d="M504 71 H526" markerEnd="url(#fa-testflow)" />
          <path d="M664 71 H686" markerEnd="url(#fa-testflow)" />
          <path d="M761 98 V140 H600 V176" markerEnd="url(#fa-testflow)" />
          <path d="M680 203 H716" markerEnd="url(#fa-testflow)" />
          <path d="M540 203 V246 H115 V230" markerEnd="url(#fa-testflow)" />
          <path d="M115 176 V120 H425 V98" markerEnd="url(#fa-testflow)" />
        </g>
        <g className="wire dashed ai-wire">
          <path d="M520 190 H440" markerEnd="url(#fa-testflow)" />
          <path d="M355 176 V120 H595 V98" markerEnd="url(#fa-testflow)" />
        </g>
        <text x="250" y="116" className="sub">reuse valid id</text>
        <text x="480" y="172" className="sub">create rejection</text>

        <text x="20" y="286" className="verdict">
          Approval = authorized run + Test writes; AI refine adds Premium + explicit refine
        </text>
        <text x="600" y="286" className="verdict ok">No body values or rows persisted</text>
      </svg>
      <GraphLegend
        items={[
          { cls: "gl-ai", label: "Engine / AI" },
          { cls: "gl-tgt", label: "Resolve resource" },
          { cls: "gl-gate", label: "Gated request" },
          { cls: "gl-ok", label: "Evidence" },
          { cls: "gl-ev", label: "Finding" },
        ]}
      />
    </figure>
  );
}

/** Arrowhead marker. Each diagram gets its own id — inline SVGs share a DOM. */
const arrow = (id: string) => (
  <marker
    id={id}
    key={id}
    viewBox="0 0 8 8"
    refX="6.5"
    refY="4"
    markerWidth="6"
    markerHeight="6"
    orient="auto"
  >
    <path d="M0.5 1 L7 4 L0.5 7 z" fill="currentColor" />
  </marker>
);

/**
 * 01 → 06, as a rail of numbered stages. The number is its own grid column so
 * the six bodies share a left edge; the separators are hairlines rather than
 * card borders, so the sequence reads as one list instead of six tiles.
 */
export function Pipeline() {
  return (
    <ol className="flow">
      {STAGES.map((s) => (
        <li className="flow-step" key={s.n}>
          <div className="flow-n" aria-hidden="true">
            {s.n}
          </div>
          <div>
            <h3>{s.title}</h3>
            <p>{s.body}</p>
            {s.note && <div className="flow-note">{s.note}</div>}
          </div>
        </li>
      ))}
    </ol>
  );
}

/**
 * Tier 1 — differential authorization. Two identities, one object, compare the
 * bodies. This is the shape of the BOLA/BFLA checks in engine/checks/authz.py.
 */
function DiffSvg() {
  return (
    <svg viewBox="0 0 320 168" role="img" className="probe-svg" aria-label="Two identities request the same object; identical responses prove broken object level authorization.">
      <defs>{arrow("fa-diff")}</defs>
      <g className="node">
        <rect x="4" y="18" width="86" height="30" rx="7" />
        <text x="47" y="33" className="lbl">Role A</text>
        <text x="47" y="44" className="sub">owner token</text>
      </g>
      <g className="node">
        <rect x="4" y="104" width="86" height="30" rx="7" />
        <text x="47" y="119" className="lbl">Role B</text>
        <text x="47" y="130" className="sub">other user</text>
      </g>

      <g className="wire">
        <path d="M92 33 H126 V70 H150" markerEnd="url(#fa-diff)" />
        <path d="M92 119 H126 V98 H150" markerEnd="url(#fa-diff)" />
      </g>

      <g className="node target">
        <rect x="152" y="60" width="104" height="48" rx="8" />
        <text x="204" y="79" className="code">GET /orders/42</text>
        <text x="204" y="94" className="sub">same object id</text>
      </g>

      <g className="wire">
        <path d="M258 74 H286" markerEnd="url(#fa-diff)" />
        <path d="M258 94 H286" markerEnd="url(#fa-diff)" />
      </g>
      <g className="node ok-node">
        <rect x="288" y="62" width="28" height="20" rx="5" />
        <text x="302" y="76" className="tiny">200</text>
        <rect x="288" y="86" width="28" height="20" rx="5" />
        <text x="302" y="100" className="tiny">200</text>
      </g>

      <text x="160" y="150" className="verdict">
        Identical bodies → Role B reads Role A&apos;s object
      </text>
    </svg>
  );
}

/** Tier 2 — marker reflection. engine/payloads.py + signatures.py. */
function ReflectSvg() {
  return (
    <svg viewBox="0 0 320 168" role="img" className="probe-svg" aria-label="A payload carrying a unique marker is sent; the marker coming back proves input reaches the response.">
      <defs>{arrow("fa-reflect")}</defs>
      <g className="node">
        <rect x="4" y="26" width="150" height="42" rx="7" />
        <text x="79" y="43" className="sub">request</text>
        <text x="79" y="58" className="code">?q=&lt;aidx7f2c&gt;</text>
      </g>

      <g className="wire">
        <path d="M156 47 H196 V64" markerEnd="url(#fa-reflect)" />
      </g>

      <g className="node target">
        <rect x="168" y="66" width="148" height="36" rx="8" />
        <text x="242" y="89" className="lbl">your API</text>
      </g>

      <g className="wire">
        <path d="M196 104 V118 H160" markerEnd="url(#fa-reflect)" />
      </g>

      <g className="node warn-node">
        <rect x="4" y="100" width="152" height="38" rx="7" />
        <text x="80" y="115" className="sub">response body</text>
        <text x="80" y="129" className="code hit">…aidx7f2c…</text>
      </g>

      <text x="160" y="158" className="verdict warn">
        Marker echoed → input reaches the response
      </text>
    </svg>
  );
}

/** Tier 3 — out-of-band callback. engine/checks/oob_injection.py. */
function OobSvg() {
  return (
    <svg viewBox="0 0 320 168" role="img" className="probe-svg" aria-label="A payload embeds a callback URL; the target contacting our collector confirms execution.">
      <defs>{arrow("fa-oob")}</defs>
      <g className="node">
        <rect x="4" y="20" width="150" height="42" rx="7" />
        <text x="79" y="37" className="sub">request</text>
        <text x="79" y="52" className="code">?url=oast.tld/k9</text>
      </g>

      <g className="wire">
        <path d="M156 41 H198 V64" markerEnd="url(#fa-oob)" />
      </g>

      <g className="node target">
        <rect x="170" y="66" width="146" height="34" rx="8" />
        <text x="243" y="88" className="lbl">your API</text>
      </g>

      <g className="wire dashed">
        <path d="M198 102 V122 H160" markerEnd="url(#fa-oob)" />
      </g>

      <g className="node ok-node">
        <rect x="4" y="104" width="152" height="36" rx="7" />
        <text x="80" y="118" className="sub">our collector</text>
        <text x="80" y="132" className="code">inbound hit · k9</text>
      </g>

      <text x="160" y="158" className="verdict ok">
        Callback received → the payload executed
      </text>
    </svg>
  );
}

export interface Tier {
  key: string;
  kicker: string;
  title: string;
  body: string;
  svg: React.ReactNode;
  tone: "verified" | "heuristic";
}

export const TIERS: Tier[] = [
  {
    key: "diff",
    kicker: "Differential",
    title: "Two identities, one object",
    body: "The scanner replays the same request as both roles and compares the answers. When the low-privilege role gets a byte-identical body, the authorization boundary is missing — no interpretation required.",
    svg: <DiffSvg />,
    tone: "verified",
  },
  {
    key: "reflect",
    kicker: "Reflection → confirmation",
    title: "A payload that signs itself",
    body: "Injection probes carry a unique aidx marker. If the marker comes back, your input reached the response — a lead, deliberately not reported as proof. Opt-in Kali tools then re-test just those leads: sqlmap, dalfox, commix and tplmap promote a reproduced bug to a verified finding.",
    svg: <ReflectSvg />,
    tone: "heuristic",
  },
  {
    key: "oob",
    kicker: "Out-of-band",
    title: "Make the target phone home",
    body: "Opt-in probes embed a URL only we can observe. If your server fetches it, the payload was executed — blind SSRF, RFI, RCE and ESI stop being guesses and become confirmations.",
    svg: <OobSvg />,
    tone: "verified",
  },
];

export function EvidenceTiers() {
  return (
    <div className="tiers">
      {TIERS.map((t) => (
        <article className="tier" key={t.key}>
          <div className="tier-art">{t.svg}</div>
          <div className="tier-body">
            <div className="tier-tags">
              {/* Same chip the coverage table and the findings list use, so
                  "verified" means one thing everywhere on the site. */}
              <TierChip tier={t.tone}>
                {t.tone === "verified" ? "verified" : "lead"}
              </TierChip>
              <span className="tier-kicker">{t.kicker}</span>
            </div>
            <h3>{t.title}</h3>
            <p>{t.body}</p>
          </div>
        </article>
      ))}
    </div>
  );
}

/* ===========================================================================
   Mechanism gallery — how a check actually proves a finding.

   Four detection archetypes the landing page's three tiers do not draw: the
   cross-identity write oracle (the write-side authz checks) and the three
   Change Set K additions. Each mirrors one engine mechanism; like the rest of
   this file they are hand-maintained, so if a check changes how it decides the
   picture changes with it.
   =========================================================================== */

/** Write oracle — a low-priv write read back by the owner. authz + write_oracle. */
function WriteOracleSvg() {
  return (
    <svg viewBox="0 0 320 176" role="img" className="probe-svg" aria-label="A low-privilege identity writes a canary into an object; the owner reads the object back and the canary is present, proving the write crossed the identity boundary.">
      <defs>{arrow("fa-writeoracle")}</defs>
      <g className="node">
        <rect x="6" y="24" width="104" height="40" rx="7" />
        <text x="58" y="42" className="lbl">Role B</text>
        <text x="58" y="55" className="sub">low-priv identity</text>
      </g>
      <g className="wire">
        <path d="M110 44 H150" markerEnd="url(#fa-writeoracle)" />
      </g>
      <g className="node gate-node">
        <rect x="152" y="24" width="162" height="40" rx="7" />
        <text x="233" y="42" className="code">PUT /widgets/42</text>
        <text x="233" y="55" className="sub">body: {"{ owner: aidx }"}</text>
      </g>
      <g className="wire">
        <path d="M233 64 V94" markerEnd="url(#fa-writeoracle)" />
      </g>
      <g className="node ok-node">
        <rect x="92" y="96" width="222" height="40" rx="7" />
        <text x="203" y="114" className="lbl">Role A (owner) reads it back</text>
        <text x="203" y="127" className="code hit">GET → {"{ owner: aidx }"}</text>
      </g>
      <text x="6" y="160" className="verdict">
        Canary written as Role B, present for the owner → verified write BOLA
      </text>
    </svg>
  );
}

/** Business flow — an identical burst mints distinct objects. business_flow. */
function BusinessFlowSvg() {
  return (
    <svg viewBox="0 0 320 176" role="img" className="probe-svg" aria-label="Five identical requests to a checkout flow each create a distinct object with no throttle or idempotency, proving the flow has no anti-automation.">
      <defs>{arrow("fa-bizflow")}</defs>
      <g className="node">
        <rect x="6" y="28" width="120" height="44" rx="7" />
        <text x="66" y="48" className="lbl">×5 identical</text>
        <text x="66" y="62" className="sub">burst, same body</text>
      </g>
      <g className="wire">
        <path d="M126 50 H166" markerEnd="url(#fa-bizflow)" />
      </g>
      <g className="node gate-node">
        <rect x="168" y="28" width="120" height="44" rx="7" />
        <text x="228" y="48" className="code">POST /checkout</text>
        <text x="228" y="62" className="sub">no idempotency key</text>
      </g>
      <g className="wire">
        <path d="M228 72 V98" markerEnd="url(#fa-bizflow)" />
      </g>
      <g className="node warn-node">
        <rect x="120" y="100" width="200" height="42" rx="7" />
        <text x="220" y="119" className="lbl">5 distinct objects created</text>
        <text x="220" y="133" className="code">id 1 · 2 · 3 · 4 · 5</text>
      </g>
      <text x="6" y="164" className="verdict warn">
        Each replay mints a new object, no throttle → API6 lead
      </text>
    </svg>
  );
}

/** Resource consumption — the count tracks the requested size. resource_consumption. */
function ResourceConsumptionSvg() {
  return (
    <svg viewBox="0 0 320 176" role="img" className="probe-svg" aria-label="Two probes at limit 1000 and 5000 return 1000 and 5000 records; the response count tracks the requested size, so there is no server-side page cap.">
      <defs>{arrow("fa-resource")}</defs>
      <g className="node">
        <rect x="6" y="20" width="112" height="36" rx="7" />
        <text x="62" y="42" className="code">?limit=1000</text>
      </g>
      <g className="node">
        <rect x="6" y="104" width="112" height="36" rx="7" />
        <text x="62" y="126" className="code">?limit=5000</text>
      </g>
      <g className="wire">
        <path d="M118 38 H134 V72 H150" markerEnd="url(#fa-resource)" />
        <path d="M118 122 H134 V88 H150" markerEnd="url(#fa-resource)" />
      </g>
      <g className="node target">
        <rect x="152" y="58" width="110" height="44" rx="8" />
        <text x="207" y="77" className="lbl">GET /catalog</text>
        <text x="207" y="93" className="sub">no page cap</text>
      </g>
      <g className="wire">
        <path d="M207 102 V112" markerEnd="url(#fa-resource)" />
      </g>
      <g className="node warn-node">
        <rect x="120" y="114" width="188" height="40" rx="7" />
        <text x="214" y="132" className="lbl">count tracks size</text>
        <text x="214" y="146" className="code">1000→1000 · 5000→5000</text>
      </g>
      <text x="6" y="170" className="verdict warn">
        Response grows with the client&apos;s limit → API4
      </text>
    </svg>
  );
}

/** Unsafe consumption — callback AND reflected marker. unsafe_consumption. */
function UnsafeConsumptionSvg() {
  return (
    <svg viewBox="0 0 320 176" role="img" className="probe-svg" aria-label="An upstream URL parameter both produces an out-of-band callback and has its marker relayed back in the response; the conjunction confirms the target consumed and relayed an unvalidated upstream.">
      <defs>{arrow("fa-unsafe")}</defs>
      <g className="node">
        <rect x="84" y="6" width="152" height="34" rx="7" />
        <text x="160" y="27" className="code">?source=oast/k9</text>
      </g>
      <g className="wire">
        <path d="M160 40 V52" markerEnd="url(#fa-unsafe)" />
      </g>
      <g className="node target">
        <rect x="100" y="54" width="120" height="34" rx="8" />
        <text x="160" y="75" className="lbl">your API</text>
      </g>
      <g className="wire dashed">
        <path d="M140 88 V106 H84" markerEnd="url(#fa-unsafe)" />
      </g>
      <g className="wire">
        <path d="M180 88 V106 H236" markerEnd="url(#fa-unsafe)" />
      </g>
      <g className="node ok-node">
        <rect x="6" y="108" width="150" height="40" rx="7" />
        <text x="81" y="126" className="sub">our collector</text>
        <text x="81" y="140" className="code">callback · k9</text>
      </g>
      <g className="node warn-node">
        <rect x="164" y="108" width="150" height="40" rx="7" />
        <text x="239" y="126" className="sub">response body</text>
        <text x="239" y="140" className="code hit">…k9… relayed</text>
      </g>
      <text x="6" y="168" className="verdict ok">
        Callback AND reflected marker → unsafe consumption
      </text>
    </svg>
  );
}

export interface Mechanism {
  key: string;
  kicker: string;
  title: string;
  body: string;
  source: string;
  tone: "verified" | "heuristic";
  svg: React.ReactNode;
}

export const MECHANISMS: Mechanism[] = [
  {
    key: "write-oracle",
    kicker: "Cross-identity write",
    title: "A write that outlives its writer",
    body: "The write-side authorization checks send a write as the low-privilege identity, tagged with a unique canary, then read the object back as the owner. The canary persisting across the identity boundary is a verified BOLA/BFLA-on-write — not an inference from two look-alike bodies. Only with writes on, and every write is restored or deleted.",
    source: "engine/checks/write_oracle.py · seeded_bola.py",
    tone: "verified",
    svg: <WriteOracleSvg />,
  },
  {
    key: "business-flow",
    kicker: "API6 · anti-automation",
    title: "A flow with no brake",
    body: "A sensitive flow — checkout, redeem, invite — is replayed with an identical body. When every replay mints a distinct new object with no throttle, no idempotency key and no challenge, the flow can be driven at machine speed. A flow that returns the same object on a replay is idempotent and stays quiet.",
    source: "engine/checks/business_flow.py",
    tone: "heuristic",
    svg: <BusinessFlowSvg />,
  },
  {
    key: "resource-consumption",
    kicker: "API4 · response volume",
    title: "A page size with no ceiling",
    body: "Only endpoints that declare a page-size parameter are probed, at two above-normal sizes. When the record count tracks the requested size — 1000 for 1000, 5000 for 5000 — there is no effective cap and one request can pull the whole table. A server capped at 100 returns 100 for both and is not flagged.",
    source: "engine/checks/resource_consumption.py",
    tone: "heuristic",
    svg: <ResourceConsumptionSvg />,
  },
  {
    key: "unsafe-consumption",
    kicker: "API10 · trust the upstream",
    title: "Relaying what it did not validate",
    body: "The trust mirror of SSRF. An upstream-URL parameter is pointed at our collector, and the finding needs both proofs: an out-of-band callback (the fetch left the server) and the collector's marker reflected back in the response (the target relayed downstream content). A callback alone is blind SSRF; reflection alone is a reflection lead. Premium, OOB-confirmed.",
    source: "engine/checks/unsafe_consumption.py",
    tone: "verified",
    svg: <UnsafeConsumptionSvg />,
  },
];

/** The mechanism gallery rendered on the coverage page. */
export function CheckMechanisms() {
  return (
    <div className="mechs">
      {MECHANISMS.map((m) => (
        <article className="mech" key={m.key}>
          <div className="mech-art">{m.svg}</div>
          <div className="mech-body">
            <div className="mech-tags">
              <TierChip tier={m.tone}>
                {m.tone === "verified" ? "verified" : "lead"}
              </TierChip>
              <span className="mech-kicker">{m.kicker}</span>
            </div>
            <h3>{m.title}</h3>
            <p>{m.body}</p>
            <div className="mech-src">{m.source}</div>
          </div>
        </article>
      ))}
    </div>
  );
}

/* ===========================================================================
   OWASP API Top-10 (2023) coverage matrix — one cell per family, coloured by
   the strongest evidence tier a check for it produces. Derived from GROUPS via
   `apiCoverage()`, so it can never drift from the registry.
   =========================================================================== */

const MATRIX_TONE: Record<"verified" | "heuristic" | "gap", string> = {
  verified: "mx-verified",
  heuristic: "mx-heuristic",
  gap: "mx-gap",
};

export function ApiCoverageMatrix() {
  const cells = apiCoverage();
  return (
    <div className="api-matrix-wrap">
      <ol className="api-matrix">
        {cells.map((c) => {
          const tone = c.best ?? "gap";
          return (
            <li
              className={`api-cell ${MATRIX_TONE[tone]}`}
              key={c.code}
              title={`${c.code}: ${c.name} — ${
                c.best
                  ? `${c.count} ${c.best} check${c.count === 1 ? "" : "s"}`
                  : "not covered"
              }`}
            >
              <div className="api-cell-top">
                <span className="api-code">{c.code}</span>
                {c.premiumOnly && <span className="api-prem">Premium</span>}
              </div>
              <span className="api-short">{c.short}</span>
              <span className="api-meta">
                {c.best ? (
                  <>
                    <b>{c.count}</b>{" "}
                    {c.best === "verified"
                      ? "verified"
                      : `lead${c.count === 1 ? "" : "s"}`}
                  </>
                ) : (
                  <em>not covered</em>
                )}
              </span>
            </li>
          );
        })}
      </ol>
      <div className="api-matrix-legend">
        <span className="api-key mx-verified">Verified evidence</span>
        <span className="api-key mx-heuristic">Heuristic lead</span>
        <span className="api-key mx-gap">Not covered</span>
      </div>
    </div>
  );
}
