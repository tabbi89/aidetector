"use client";

import { memo, useCallback, useEffect, useMemo, useState } from "react";
import { api, configSourceOf } from "@/lib/api";
import type { CoverageRow, MutationRow, PlanRow, ResourceRow, RunDiff, RunFinding, ScanEvent, ScanRun } from "@/lib/api";
import { describePasses } from "./SchedulePanel";
import { clock, gapCountLabel } from "../../components/scanShared";
import { GROUPS } from "@/lib/coverage";

/** The project file a run recorded, or nothing when the web owned its settings. */
function ConfigSourceChip({ value }: { value: Record<string, unknown> }) {
  const source = configSourceOf(value);
  if (!source) return null;
  return (
    <span className="gap-chip" title={`Settings came from ${source.path}`}>
      {source.path}
      {source.commit ? ` @ ${source.commit.slice(0, 7)}` : ""}
    </span>
  );
}

/**
 * Engine-check key → its human name + detection signal, from the coverage
 * mirror (`lib/coverage.ts`). Used to explain each key in the per-endpoint
 * "Checks exercised" column on hover. First entry carrying a key wins — payload
 * families share one key and only the representative entry declares it.
 */
const CHECK_INFO: Map<string, { name: string; signal: string }> = new Map();
for (const group of GROUPS) {
  for (const check of group.checks) {
    if (check.key && !CHECK_INFO.has(check.key)) {
      CHECK_INFO.set(check.key, { name: check.name, signal: check.signal });
    }
  }
}

/** Click-to-open explanation for one engine-check key. */
function CheckPopover({ check }: { check: string }) {
  const info = CHECK_INFO.get(check);
  if (!info) return <span>{check}</span>;
  const signal = info.signal.length > 260 ? `${info.signal.slice(0, 259)}…` : info.signal;

  return (
    <details className="cov-check-popover">
      <summary className="cov-check" title="Click to view detection details">
        {check}
      </summary>
      <div className="cov-tip" role="tooltip">
        <strong>{info.name}</strong>
        <span>{signal}</span>
      </div>
    </details>
  );
}

/** The AI pre-scan plan, present only when the latest run used `plan: true`. */
function PlanTableImpl({ plan }: { plan: PlanRow[] }) {
  if (plan.length === 0) return null;
  return (
    <div className="specbox">
      <div className="spec-head">
        <h2>AI scan plan</h2>
        <span className="muted-sm">risk-ranked endpoints · budget hits these first</span>
      </div>
      <div className="cov-scroll" role="region" aria-label="AI scan plan table" tabIndex={0}>
        <table className="cov-table plan-table">
          <colgroup>
            <col className="endpoint-column" />
            <col className="priority-column" />
            <col />
          </colgroup>
          <thead>
            <tr>
              <th>Endpoint</th>
              <th>Priority</th>
              <th>Rationale</th>
            </tr>
          </thead>
          <tbody>
            {plan.map((p, i) => (
              <tr key={p.operation_id ?? `${p.method} ${p.path} ${i}`}>
                <td>
                  <code className="cov-ep">
                    <span className="cov-method">{p.method}</span> {p.path}
                  </code>
                </td>
                <td>
                  <span className={`prio-badge ${p.priority}`}>{p.priority}</span>
                </td>
                <td className="cov-checks">{p.rationale || "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

/**
 * What the engine actually did to each endpoint on the latest run. A row with
 * zero requests was in scope but untouched; an excluded row was opted out.
 */
function CoverageTableImpl({ coverage }: { coverage: CoverageRow[] }) {
  if (coverage.length === 0) return null;
  return (
    <div className="specbox">
      <div className="spec-head">
        <h2>Per-endpoint coverage</h2>
        <span className="muted-sm">
          what the engine did to each endpoint · latest run
        </span>
      </div>
      <div className="cov-scroll" role="region" aria-label="Endpoint coverage table" tabIndex={0}>
        <table className="cov-table coverage-table">
          <colgroup>
            <col className="endpoint-column" />
            <col className="count-column" />
            <col className="count-column" />
            <col />
          </colgroup>
          <thead>
            <tr>
              <th>Endpoint</th>
              <th className="num">Requests</th>
              <th className="num">Findings</th>
              <th>Checks exercised</th>
            </tr>
          </thead>
          <tbody>
            {coverage.map((r) => (
              <tr
                key={r.operation_id ?? `${r.method} ${r.path}`}
                className={
                  !r.enabled ? "cov-off" : r.requests === 0 ? "cov-untouched" : ""
                }
              >
                <td>
                  <code className="cov-ep">
                    <span className="cov-method">{r.method}</span> {r.path}
                  </code>
                  {!r.enabled && <span className="muted-sm"> (excluded)</span>}
                </td>
                <td className="num">{r.requests}</td>
                <td className={`num${r.findings > 0 ? " cov-hasfindings" : ""}`}>
                  {r.findings}
                </td>
                <td className="cov-checks">
                  {r.checks.length > 0
                    ? r.checks.map((c, i) => {
                        return (
                          <span key={c}>
                            {i > 0 && ", "}
                            <CheckPopover check={c} />
                          </span>
                        );
                      })
                    : "—"}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

/**
 * Resources the setup pass created or the caller supplied for dependent endpoint
 * probes. Sanitized: resource name and routes only — never the concrete id.
 */
function ResourceTableImpl({ resources }: { resources: ResourceRow[] }) {
  if (resources.length === 0) return null;
  const createdCount = resources.filter((resource) => resource.source !== "predefined").length;
  const suppliedCount = resources.length - createdCount;
  return (
    <div className="specbox">
      <div className="spec-head">
        <h2>Prepared resources</h2>
        <span className="muted-sm">
          {createdCount} created during scan · {suppliedCount} supplied ID{suppliedCount === 1 ? "" : "s"}
        </span>
      </div>
      <div className="cov-scroll" role="region" aria-label="Prepared resources table" tabIndex={0}>
        <table className="cov-table coverage-table">
          <colgroup>
            <col className="endpoint-column" />
            <col />
            <col />
            <col className="count-column" />
          </colgroup>
          <thead>
            <tr>
              <th>Resource</th>
              <th>Source / create</th>
              <th>Verification</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            {resources.map((r, i) => (
              <tr
                key={`${r.resource} ${i}`}
                className={r.source === "predefined" ? "" : "resource-created-row"}
              >
                <td>
                  <code className="cov-ep">{r.resource}</code>
                </td>
                <td>
                  {r.source === "predefined" ? (
                    <span className="resource-origin supplied">Supplied ID</span>
                  ) : (
                    <div className="resource-origin created">
                      <span>Created during scan</span>
                      <code className="cov-ep">
                        <span className="cov-method">{r.create_method}</span> {r.create_path}
                      </code>
                      <span className="muted-sm">
                        {r.via_ai ? "AI-refined body" : "Spec-shaped body"}
                      </span>
                    </div>
                  )}
                </td>
                <td>
                  {r.read_method && r.read_path ? (
                    <code className="cov-ep">
                      <span className="cov-method">{r.read_method}</span> {r.read_path}
                    </code>
                  ) : <span className="muted-sm">No item GET selected</span>}
                </td>
                <td className="cov-checks">
                  <span className={`resource-status ${r.status}`}>
                    {r.status.replaceAll("_", " ")}
                  </span>
                  {r.attempts.length ? ` · ${r.attempts.length} attempt${r.attempts.length === 1 ? "" : "s"}` : ""}
                  <span className="resource-cleanup">
                    {r.cleanup === "queued"
                      ? "cleanup queued"
                      : r.cleanup === "not_needed"
                        ? "no create performed"
                        : r.cleanup === "deleted"
                          ? "deleted after run"
                          : r.cleanup === "failed"
                            ? "cleanup failed"
                            : "persists (no DELETE)"}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

/**
 * Stages that mean the run could not do something, with the heading each row is
 * grouped under. A stage absent from this table is progress, not a caveat.
 */
export const GAP_GROUPS: { heading: string; stages: string[] }[] = [
  {
    // Blocked egress stops the engine's own traffic, so its checks never ran.
    heading: "Checks that did not run",
    stages: ["check_skipped", "egress_blocked"],
  },
  {
    // Started, then raised part-way — a timeout on a slow host, or a bug. Its
    // silence is not a clean result, and the diff treats it that way.
    heading: "Checks that did not finish",
    stages: ["check_failed"],
  },
  {
    heading: "External tools that did not run",
    stages: [
      "zap_skipped",
      "kali_skipped",
      "testssl_skipped",
      "sqlmap_skipped",
      "dalfox_skipped",
      "commix_skipped",
      "tplmap_skipped",
      "adjuncts_skipped",
      "kali_partial",
    ],
  },
  {
    heading: "AI steps that did not run",
    stages: [
      "ai_skipped",
      "plan_skipped",
      "genai_payloads_skipped",
      "security_review_skipped",
    ],
  },
  {
    heading: "Identities",
    stages: [
      "credential_unreadable",
      "auth_grant_failed",
      "egress_blocked",
      "identities_unavailable",
    ],
  },
  { heading: "Cleanup", stages: ["cleanup_failed"] },
  { heading: "Request budget", stages: ["budget_exhausted"] },
];

/** The stages the page extracts into this panel. */
export const GAP_STAGES = new Set(GAP_GROUPS.flatMap((group) => group.stages));

/**
 * What the run could not do, and what was missing.
 *
 * "We looked and found nothing" and "we never looked" produce the same empty
 * result, and only one is good news. Each row is the engine's own event message,
 * so a reader sees whether a gap was a missing credential, a missing tool or a
 * budget that ran out — the three call for different responses.
 */
function RunGapsImpl({ events, notRun }: { events: ScanEvent[]; notRun: string[] }) {
  if (events.length === 0 && notRun.length === 0) return null;
  return (
    <div className="specbox skipped-checks run-gaps">
      <div className="spec-head">
        <h2>What this run could not do</h2>
        <span className="muted-sm">
          {events.length
            ? gapCountLabel(events)
            : "Requested tools did not run"}
        </span>
      </div>
      <p className="muted-sm skipped-intro">
        A step that never ran and a step that found nothing leave the same empty
        result, and only one is good news. Each line is the engine&rsquo;s own
        reason.
      </p>
      {events.some((e) => e.stage === "budget_exhausted") && (
        <p className="run-gap-budget" role="alert">
          The run spent its request budget, so results after that point are
          incomplete. Raising the budget is not an option — narrow the scope
          (fewer operations or checks) or re-run.
        </p>
      )}
      {notRun.length > 0 && (
        <p className="muted-sm run-gap-notrun">
          Requested but not run: <code>{notRun.join(", ")}</code>
        </p>
      )}
      {GAP_GROUPS.map(({ heading, stages }) => {
        const rows = events.filter((e) => stages.includes(e.stage));
        if (rows.length === 0) return null;
        return (
          <section className="run-gap-group" key={heading}>
            <h3>{heading}</h3>
            <ul className="skipped-list">
              {rows.map((e, i) => {
                // A skipped check's message names the check, so show it as the
                // check it is rather than repeating "did not run" under a
                // heading that already says it.
                const [check, reason] = e.message.split(
                  e.stage === "check_failed" ? " did not finish: " : " did not run: ",
                );
                return (
                  <li key={`${e.stage}-${i}`}>
                    {(e.stage === "check_skipped" || e.stage === "check_failed") && reason ? (
                      <>
                        <code>{check}</code>
                        <span>{reason}</span>
                      </>
                    ) : (
                      <span>{e.message}</span>
                    )}
                  </li>
                );
              })}
            </ul>
          </section>
        );
      })}
    </div>
  );
}

export const RunGaps = memo(RunGapsImpl);

type StatusBucket = "2xx" | "3xx" | "4xx" | "5xx" | "error";

function statusBucket(status: number | null): StatusBucket {
  if (status == null || status === 0) return "error";
  if (status < 300) return "2xx";
  if (status < 400) return "3xx";
  if (status < 500) return "4xx";
  return "5xx";
}

const TRACE_PAGE = 100;

/** Canonical HTTP-method order for the method filter; anything else trails. */
const METHOD_ORDER = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"];

/**
 * A finding handing its evidence to the request log: which calls the finding's
 * `evidence.trace` names, and what to call them in the log's header.
 */
export interface RequestLogFocus {
  title: string;
  sequences: number[];
}

let requestLogFocus: RequestLogFocus | null = null;
const requestLogListeners = new Set<(focus: RequestLogFocus | null) => void>();

/** Filter the request log to one finding's calls; null clears the filter. */
export function focusRequestLog(focus: RequestLogFocus | null) {
  requestLogFocus = focus;
  for (const listener of requestLogListeners) listener(focus);
}

/**
 * Show the request log filtered to a finding: activate its workspace tab — the
 * ids are the ones ResultsWorkspace declares — and scroll it into view. The
 * two sections are siblings whose parent is owned elsewhere, so the handoff
 * goes through the store above rather than through props.
 */
export function revealRequestLog(focus: RequestLogFocus) {
  focusRequestLog(focus);
  document.getElementById("results-tab-mutations")?.click();
  requestAnimationFrame(() =>
    document.getElementById("results-panel-mutations")?.scrollIntoView({ block: "start" }),
  );
}

function useRequestLogFocus(): RequestLogFocus | null {
  const [focus, setFocus] = useState(requestLogFocus);
  useEffect(() => {
    requestLogListeners.add(setFocus);
    setFocus(requestLogFocus);
    return () => {
      requestLogListeners.delete(setFocus);
      // No log is showing it any more; do not carry the filter into the next one.
      if (requestLogListeners.size === 0) requestLogFocus = null;
    };
  }, []);
  return focus;
}

/**
 * The run's request log, fetched a page at a time.
 *
 * A run archives one row per outbound call — hundreds of them, each with a body
 * sample — so the rows are not carried on the run object and are not loaded
 * until this panel mounts. Filtering applies to what has been loaded; the header
 * always states the run's true total so a filtered view is never mistaken for
 * the whole log.
 */
function MutationTableImpl({
  scanId, runNumber, total,
}: { scanId: string; runNumber: number; total: number }) {
  const [statusFilter, setStatusFilter] = useState<StatusBucket | "all">("all");
  const [methodFilter, setMethodFilter] = useState<string>("all");
  const [checkFilter, setCheckFilter] = useState<string>("all");
  const [routeQuery, setRouteQuery] = useState("");
  const [mutations, setMutations] = useState<MutationRow[]>([]);
  const [loading, setLoading] = useState(true);
  const [ended, setEnded] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const focus = useRequestLogFocus();

  const loadPage = useCallback(
    async (offset: number) => {
      setLoading(true);
      try {
        const page = await api.getRunTrace(scanId, runNumber, offset, TRACE_PAGE);
        setMutations((prev) => (offset === 0 ? page.rows : [...prev, ...page.rows]));
        // A short page means the trace ended early; stop paging rather than
        // asking for offsets the API will answer with nothing.
        setEnded(page.rows.length < TRACE_PAGE);
        setError(null);
      } catch (e) {
        setError((e as Error).message);
      } finally {
        setLoading(false);
      }
    },
    [scanId, runNumber],
  );

  useEffect(() => {
    setMutations([]);
    setEnded(false);
    void loadPage(0);
  }, [loadPage]);

  const buckets = useMemo(() => {
    const c: Record<StatusBucket, number> = { "2xx": 0, "3xx": 0, "4xx": 0, "5xx": 0, error: 0 };
    for (const m of mutations) c[statusBucket(m.response.status)] += 1;
    return c;
  }, [mutations]);

  // Method facet: count per method over everything loaded (like the status
  // buckets), then order canonically so the chip row is stable across pages.
  const methodCounts = useMemo(() => {
    const c = new Map<string, number>();
    for (const m of mutations) {
      const k = (m.method || "?").toUpperCase();
      c.set(k, (c.get(k) ?? 0) + 1);
    }
    return c;
  }, [mutations]);

  const methodsPresent = useMemo(
    () =>
      [...methodCounts.keys()].sort((a, b) => {
        const ia = METHOD_ORDER.indexOf(a);
        const ib = METHOD_ORDER.indexOf(b);
        return (ia === -1 ? 99 : ia) - (ib === -1 ? 99 : ib) || a.localeCompare(b);
      }),
    [methodCounts],
  );

  // Which check made the call — one option per check seen, so a finding's
  // evidence can be read in the context of the rest of that check's traffic.
  const checkCounts = useMemo(() => {
    const c = new Map<string, number>();
    for (const m of mutations) c.set(m.check, (c.get(m.check) ?? 0) + 1);
    return c;
  }, [mutations]);

  const checksPresent = useMemo(
    () => [...checkCounts.keys()].sort((a, b) => a.localeCompare(b)),
    [checkCounts],
  );

  const wantedSequences = useMemo(
    () => (focus ? new Set(focus.sequences) : null),
    [focus],
  );

  const visible = useMemo(() => {
    const q = routeQuery.trim().toLowerCase();
    return mutations.filter(
      (m) =>
        (!wantedSequences || wantedSequences.has(m.sequence)) &&
        (statusFilter === "all" || statusBucket(m.response.status) === statusFilter) &&
        (methodFilter === "all" || (m.method || "?").toUpperCase() === methodFilter) &&
        (checkFilter === "all" || m.check === checkFilter) &&
        (!q || m.route.toLowerCase().includes(q)),
    );
  }, [mutations, wantedSequences, statusFilter, methodFilter, checkFilter, routeQuery]);

  // A finding's calls can sit anywhere in the trace, so pull pages until every
  // wanted sequence is loaded or the trace runs out.
  useEffect(() => {
    if (!focus || loading || ended || mutations.length >= total) return;
    const loaded = new Set(mutations.map((m) => m.sequence));
    if (focus.sequences.every((sequence) => loaded.has(sequence))) return;
    void loadPage(mutations.length);
  }, [focus, loading, ended, mutations, total, loadPage]);

  const payloadPreview = (value: unknown): unknown => {
    if (value === undefined || value === null) return "—";
    if (Array.isArray(value)) return value.map(payloadPreview);
    if (typeof value !== "object") return "<value omitted>";

    const shape = value as Record<string, unknown>;
    if (typeof shape.type === "string") {
      switch (shape.type) {
        case "string":
          return `<string${typeof shape.length === "number" ? `, ${shape.length} chars` : ""}>`;
        case "number":
          return "<number>";
        case "boolean":
          return "<boolean>";
        case "null":
          return "<null>";
        case "array":
          return shape.sample === null || shape.sample === undefined
            ? `<array${typeof shape.items === "number" ? `, ${shape.items} items` : ""}>`
            : [payloadPreview(shape.sample)];
        case "truncated":
          return "<truncated>";
        default:
          return `<${shape.type}>`;
      }
    }

    return Object.fromEntries(Object.entries(shape).map(([key, child]) => [key, payloadPreview(child)]));
  };

  const formatPayload = (entry: MutationRow) => {
    const lines: string[] = [];
    if (entry.request.query_fields.length) {
      lines.push(`query fields: ${entry.request.query_fields.join(", ")}`);
    }
    if (entry.request.json_shape !== null && entry.request.json_shape !== undefined) {
      lines.push(JSON.stringify(payloadPreview(entry.request.json_shape), null, 2) ?? "—");
    }
    if (entry.request.content_bytes > 0) {
      lines.push(`content bytes: ${entry.request.content_bytes}`);
    }
    return lines.join("\n") || "No payload recorded.";
  };

  const prettyJson = (raw: string) => {
    try {
      return JSON.stringify(JSON.parse(raw), null, 2);
    } catch {
      return raw;
    }
  };

  const formatResponse = (entry: MutationRow) => {
    const r = entry.response;
    const meta = [
      `status: ${r.status == null ? `no response (${entry.error || "transport error"})` : r.status}`,
      `content-type: ${r.content_type || "—"}`,
      `body bytes: ${r.body_bytes}`,
    ];
    if (entry.elapsed_ms != null) meta.push(`took: ${entry.elapsed_ms} ms`);
    let body: string;
    if (r.body_omitted) {
      body = r.body_bytes
        ? "(body not retained — not a textual response, or the run's body budget was spent)"
        : "(empty body)";
    } else if (r.body) {
      body = prettyJson(r.body);
      if (r.truncated) body += "\n… (truncated)";
    } else {
      body = "(empty body)";
    }
    return `${meta.join("\n")}\n\n${body}`;
  };

  const formatRequestBody = (entry: MutationRow) =>
    entry.request.json_body ? prettyJson(entry.request.json_body) : "";

  const payloadNotice = "Values omitted; typed placeholders preserve the request fields without retaining data.";

  const requestBodyNotice = "The payload this scan generated, with secrets and PII masked.";

  const responseNotice = "Redacted sample — secrets and PII are masked, and long bodies are cut.";

  function HeaderList({
    headers,
    empty,
  }: {
    headers: Record<string, string> | undefined;
    empty: string;
  }) {
    const entries = Object.entries(headers ?? {});
    if (entries.length === 0) return <p className="mutation-empty">{empty}</p>;
    return (
      <div className="mutation-headers">
        {entries.map(([name, value]) => (
          <div className="mutation-header" key={name}>
            <code>{name}</code>
            <span>{value}</span>
          </div>
        ))}
      </div>
    );
  }

  const FILTERS: { key: StatusBucket | "all"; label: string }[] = [
    { key: "all", label: "all" },
    { key: "2xx", label: "2xx accepted" },
    { key: "3xx", label: "3xx" },
    { key: "4xx", label: "4xx" },
    { key: "5xx", label: "5xx" },
    { key: "error", label: "error" },
  ];

  const activeFilters = [
    methodFilter !== "all" ? methodFilter : null,
    statusFilter !== "all" ? statusFilter : null,
    checkFilter !== "all" ? `check ${checkFilter}` : null,
    routeQuery.trim() ? `route “${routeQuery.trim()}”` : null,
  ].filter((label): label is string => label !== null);

  return (
    <div className="specbox">
      <div className="spec-head">
        <h2>Request log</h2>
        <span className="muted-sm">
          {mutations.length === total
            ? `${total} call${total === 1 ? "" : "s"}`
            : `${mutations.length} of ${total} calls loaded`}{" "}
          · bodies redacted
        </span>
      </div>

      {focus && (
        <p className="muted-sm request-focus" role="status">
          Showing requests for <strong>{focus.title}</strong>
          <button className="btn quiet sm" onClick={() => focusRequestLog(null)}>
            clear
          </button>
        </p>
      )}

      <div className="mutation-filters" role="group" aria-label="Search requests">
        <div className="searchbox">
          <span className="icon" aria-hidden="true">⌕</span>
          <input
            type="search"
            value={routeQuery}
            onChange={(e) => setRouteQuery(e.target.value)}
            placeholder="Search route…"
            aria-label="Search requests by route"
          />
          {routeQuery && (
            <button
              className="clear"
              onClick={() => setRouteQuery("")}
              aria-label="Clear route search"
            >
              ✕
            </button>
          )}
        </div>
        {checksPresent.length > 1 && (
          <select
            className="check-pick"
            value={checkFilter}
            onChange={(e) => setCheckFilter(e.target.value)}
            aria-label="Filter requests by check"
          >
            <option value="all">any check ({mutations.length})</option>
            {checksPresent.map((c) => (
              <option key={c} value={c}>
                {c} ({checkCounts.get(c) ?? 0})
              </option>
            ))}
          </select>
        )}
      </div>

      <div className="mutation-filters" role="group" aria-label="Filter requests by status">
        {FILTERS.map(({ key, label }) => {
          const count = key === "all" ? mutations.length : buckets[key];
          return (
            <button
              key={key}
              className={`chipbtn ${statusFilter === key ? "on" : ""}`}
              onClick={() => setStatusFilter(key)}
              aria-pressed={statusFilter === key}
            >
              {label}
              <span className="c">{count}</span>
            </button>
          );
        })}
      </div>

      {methodsPresent.length > 1 && (
        <div className="mutation-filters" role="group" aria-label="Filter requests by method">
          <button
            className={`chipbtn ${methodFilter === "all" ? "on" : ""}`}
            onClick={() => setMethodFilter("all")}
            aria-pressed={methodFilter === "all"}
          >
            any method
            <span className="c">{mutations.length}</span>
          </button>
          {methodsPresent.map((m) => (
            <button
              key={m}
              className={`chipbtn ${methodFilter === m ? "on" : ""}`}
              onClick={() => setMethodFilter(m)}
              aria-pressed={methodFilter === m}
            >
              {m}
              <span className="c">{methodCounts.get(m) ?? 0}</span>
            </button>
          ))}
        </div>
      )}

      <div className="mutation-log" role="region" aria-label="Request log" tabIndex={0}>
        {visible.map((entry) => {
          const status = entry.response.status;
          const statusClass = status == null ? "unknown" : status >= 500 ? "error" : status >= 400 ? "warn" : "ok";
          const requestHeaders = entry.request.headers ?? {};
          const responseHeaders = entry.response.headers ?? {};
          return (
            <details className="mutation-entry" key={entry.sequence}>
              <summary>
                <span className="mutation-number">{entry.sequence}</span>
                <span className={`method ${entry.method.toLowerCase()}`}>{entry.method}</span>
                <code className="mutation-route">{entry.route}</code>
                <span className="mutation-check">{entry.check}</span>
                <span className="mutation-identity" title="Identity whose credentials were sent">
                  {entry.identity}
                </span>
                {entry.pass !== "engine" && (
                  <span className="mutation-pass" title="Which pass made this call">
                    {entry.pass}
                  </span>
                )}
                <span className={`mutation-status ${statusClass}`}>
                  {status == null ? entry.error || "transport error" : status}
                </span>
                <span className="mutation-summary">
                  {Object.keys(requestHeaders).length} sent · {Object.keys(responseHeaders).length} received
                </span>
              </summary>
              <div className="mutation-detail">
                <section className="mutation-pane">
                  <div className="mutation-pane-head">
                    <h3>Request sent</h3>
                    <span>{Object.keys(requestHeaders).length} headers</span>
                  </div>
                  <HeaderList headers={entry.request.headers} empty="No request headers recorded." />
                  {formatRequestBody(entry) && (
                    <>
                      <div className="mutation-subhead">Payload sent</div>
                      <p className="mutation-note">{requestBodyNotice}</p>
                      <pre className="mutation-code">{formatRequestBody(entry)}</pre>
                    </>
                  )}
                  <div className="mutation-subhead">Payload · structure</div>
                  <p className="mutation-note">{payloadNotice}</p>
                  <pre className="mutation-code">{formatPayload(entry)}</pre>
                </section>
                <section className="mutation-pane">
                  <div className="mutation-pane-head">
                    <h3>Response received</h3>
                    <span>
                      {status == null ? "transport error" : `${status} · ${entry.response.content_type || "no content-type"}`}
                    </span>
                  </div>
                  <HeaderList headers={entry.response.headers} empty="No response headers recorded." />
                  <div className="mutation-subhead">Response body</div>
                  <p className="mutation-note">{responseNotice}</p>
                  <pre className="mutation-code">{formatResponse(entry)}</pre>
                </section>
              </div>
            </details>
          );
        })}
      </div>

      {visible.length === 0 && !loading && (
        <p className="muted-sm" style={{ margin: "10px 0 0" }}>
          {focus
            ? `None of the ${focus.sequences.length} request(s) this finding cites are in the trace.`
            : activeFilters.length === 0
              ? "No calls recorded."
              : `No calls match ${activeFilters.join(" · ")} among the ${mutations.length} loaded.`}
        </p>
      )}

      {error && <p className="err" role="alert">Could not load the request log: {error}</p>}

      {!ended && mutations.length < total && (
        <button
          className="btn ghost"
          style={{ marginTop: "10px" }}
          onClick={() => void loadPage(mutations.length)}
          disabled={loading}
        >
          {loading ? "Loading…" : `Load ${Math.min(TRACE_PAGE, total - mutations.length)} more`}
        </button>
      )}
    </div>
  );
}

/**
 * What changed since the previous run — the question a team fixing things
 * actually asks. Null until the scan has two runs to compare, which is a normal
 * state rather than an error, so nothing is rendered then.
 */
/** A run's archived finding: its triage and taxonomy travel with it, so a
 *  dismissed finding in history does not read as an unreviewed one. */
function RunFindingMeta({ f }: { f: RunFinding }) {
  return (
    <>
      {f.owasp_id && <span className="muted-sm">{f.owasp_id}</span>}
      {f.verdict === "confirmed" && <span className="verdict-chip confirmed">confirmed</span>}
      {f.verdict === "dismissed" && <span className="verdict-chip dismissed">false positive</span>}
    </>
  );
}

function duration(start: string, end: string | null): string | null {
  if (!end) return null;
  const seconds = Math.round((Date.parse(end) - Date.parse(start)) / 1000);
  if (!Number.isFinite(seconds) || seconds < 0) return null;
  return seconds < 90 ? `${seconds}s` : `${Math.round(seconds / 60)} min`;
}

function RunDiffPanelImpl({ diff }: { diff: RunDiff | null }) {
  if (!diff) return null;
  const quiet =
    diff.added.length === 0 && diff.resolved.length === 0 && diff.not_retested.length === 0;
  return (
    <div className="specbox">
      <div className="spec-head">
        <h2>Since run {diff.from_run}</h2>
        <span className="muted-sm">
          run {diff.from_run} → {diff.to_run}
          {diff.options_changed && " · runs used different options"}
          {diff.executor_changed && " · runs used different executors"}
          {diff.config_changed &&
            " · settings changed between these runs (different project file or web)"}
          {diff.unmatchable > 0 &&
            ` · ${diff.unmatchable} finding(s) predate change tracking`}
        </span>
      </div>

      <div className="diff-stats">
        <div className="diff-stat added">
          <span className="n">{diff.added.length}</span>
          <span className="l">new</span>
        </div>
        <div className="diff-stat resolved">
          <span className="n">{diff.resolved.length}</span>
          <span className="l">fixed</span>
        </div>
        {diff.not_retested.length > 0 && (
          <div className="diff-stat">
            <span className="n">{diff.not_retested.length}</span>
            <span className="l">not re-tested</span>
          </div>
        )}
        <div className="diff-stat">
          <span className="n">{diff.unchanged.length}</span>
          <span className="l">still there</span>
        </div>
      </div>

      {quiet ? (
        <p className="muted-sm" style={{ margin: "10px 0 0" }}>
          Nothing changed between these runs.
        </p>
      ) : (
        <>
        <div className="legend" aria-label="Diff legend">
          <span className="item">
            <span className="diff-mark added">+</span> new this run
          </span>
          <span className="item">
            <span className="diff-mark resolved">−</span> fixed since last run
          </span>
          {diff.not_retested.length > 0 && (
            <span className="item">
              <span className="diff-mark">?</span> not re-tested — the newer run
              left that pass off, or it did not run
            </span>
          )}
          <span className="item">
            <span className="conf-badge verified">verified</span> proven — the
            rest are heuristic leads
          </span>
        </div>
        <ul className="run-snap diff-list">
          {diff.added.map((f) => (
            <li key={`a-${f.fingerprint}`}>
              <span className="diff-mark added" aria-label="new">+</span>
              <span className={`sev-badge ${f.severity}`}>{f.severity}</span>
              {f.confidence === "verified" && (
                <span className="conf-badge verified">verified</span>
              )}
              <span>{f.title}</span>
              <RunFindingMeta f={f} />
            </li>
          ))}
          {diff.resolved.map((f) => (
            <li key={`r-${f.fingerprint}`} className="dim">
              <span className="diff-mark resolved" aria-label="fixed">−</span>
              <span className={`sev-badge ${f.severity}`}>{f.severity}</span>
              <span>{f.title}</span>
              <RunFindingMeta f={f} />
            </li>
          ))}
          {diff.not_retested.map((f) => (
            <li key={`n-${f.fingerprint}`} className="dim">
              <span className="diff-mark" aria-label="not re-tested">?</span>
              <span className={`sev-badge ${f.severity}`}>{f.severity}</span>
              <span>{f.title}</span>
              <RunFindingMeta f={f} />
            </li>
          ))}
        </ul>
        </>
      )}
    </div>
  );
}

/** Past runs with their archived findings snapshot — re-runs replace live findings. */
function RunHistoryImpl({
  runs,
  hasMore = false,
  loadingMore = false,
  onLoadMore,
}: {
  runs: ScanRun[];
  hasMore?: boolean;
  loadingMore?: boolean;
  onLoadMore?: () => void;
}) {
  if (runs.length === 0) return null;
  return (
    <div className="specbox">
      <div className="spec-head">
        <h2>History</h2>
        <span className="muted-sm">
          {runs.length} run{runs.length === 1 ? "" : "s"} — newest first
        </span>
      </div>
      <div className="runs">
        {runs.map((r) => (
          <details className="run-row" key={r.id}>
            <summary>
              <span className={`st-chip ${r.status}`}>#{r.run_number}</span>
              <span className="muted-sm">{r.status}</span>
              {r.executor?.kind === "local_runner" && (
                <span className="gap-chip">local runner</span>
              )}
              {/* Where this run's settings came from. `{}` means the web, and
                  the executor chip above already says who ran it. */}
              <ConfigSourceChip value={r.config_source} />
              <span className="muted-sm">
                {r.findings_count} finding{r.findings_count === 1 ? "" : "s"} ·{" "}
                {r.requests} req
              </span>
              {r.adaptive?.enabled && (
                <span className="muted-sm">· adaptive {r.adaptive.tests.length} tests</span>
              )}
              {Boolean(r.gaps?.not_run?.length) && (
                <span className="gap-chip">not run: {r.gaps!.not_run!.join(", ")}</span>
              )}
              {Boolean(r.gaps?.failed_checks?.length) && (
                <span className="gap-chip">did not finish: {r.gaps!.failed_checks!.join(", ")}</span>
              )}
              {r.gaps?.budget_exhausted && <span className="gap-chip">request budget ran out</span>}
              <span className="grow" />
              <span className="muted-sm">
                {clock(r.started_at)}
                {duration(r.started_at, r.finished_at) && ` · took ${duration(r.started_at, r.finished_at)}`}
              </span>
            </summary>
            {Object.keys(r.options ?? {}).length > 0 && (
              <p className="muted-sm" style={{ margin: "8px 0 0" }}>
                Ran as: {describePasses(r.options)}
                {Array.isArray(r.options.checks) && r.options.checks.length > 0
                  ? ` · ${r.options.checks.length} selected check${r.options.checks.length === 1 ? "" : "s"}`
                  : ""}
              </p>
            )}
            {r.adaptive?.enabled && (
              <p className="muted-sm" style={{ margin: "8px 0 0" }}>
                Adaptive validation: {r.adaptive.stop_reason}; {r.adaptive.requests} bounded requests
                {r.adaptive.tests.some((t) => t.schema_status === "available")
                  ? " · schema facts available"
                  : " · schema facts unavailable"}
              </p>
            )}
            {Boolean(r.manifest?.metrics) && (
              <p className="muted-sm" style={{ margin: "8px 0 0" }}>
                Reproducibility seed: {String(r.manifest.seed ?? "not recorded")} · valid-request
                coverage: {String((r.manifest.metrics as Record<string, unknown>).valid_request_coverage ?? "n/a")} · cleanup: {String((r.manifest.metrics as Record<string, unknown>).cleanup_success_rate ?? "n/a")}
              </p>
            )}
            {r.findings_snapshot.length > 0 ? (
              <ul className="run-snap">
                {r.findings_snapshot.map((f, i) => (
                  <li key={i} className={f.verdict === "dismissed" ? "dim" : undefined}>
                    <span className={`sev-badge ${f.severity}`}>{f.severity}</span>
                    {f.confidence === "verified" && (
                      <span className="conf-badge verified">verified</span>
                    )}
                    <span className="muted-sm">{f.check}</span>
                    <span>{f.title}</span>
                    <RunFindingMeta f={f} />
                  </li>
                ))}
              </ul>
            ) : (
              <p className="muted-sm" style={{ margin: "8px 0 0" }}>
                No findings in this run.
              </p>
            )}
          </details>
        ))}
      </div>

      {hasMore && onLoadMore && (
        <button
          className="btn quiet show-more"
          type="button"
          onClick={onLoadMore}
          disabled={loadingMore}
        >
          {loadingMore
            ? "Loading older runs…"
            : `Load older runs (${runs.length} loaded)`}
        </button>
      )}
    </div>
  );
}

export const PlanTable = memo(PlanTableImpl);
export const CoverageTable = memo(CoverageTableImpl);
export const ResourceTable = memo(ResourceTableImpl);
export const MutationTable = memo(MutationTableImpl);
export const RunDiffPanel = memo(RunDiffPanelImpl);
export const RunHistory = memo(RunHistoryImpl);
