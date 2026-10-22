"use client";

import { ExpandingTextarea } from "../../components/ExpandingTextarea";

import { ValidatedForm } from "../../components/ValidatedForm";
import { useConfirmation } from "../../components/Confirmation";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { use, useCallback, useEffect, useState, type CSSProperties, type ReactNode } from "react";
import {
  api,
  type ClientFlag,
  type InfrastructureMonitor,
  type MonitoringBots,
  type MonitoringBriefing,
  type MonitoringClients,
  type MonitoringRoutes,
  type MonitoringRun,
  type MonitoringPulse,
  type MonitoringRapidRun,
  type MonitoringSetupUpdate,
  type MonitoringSetupView,
  type RouteDay,
} from "@/lib/api";
import { usePageTitle } from "../../components/usePageTitle";

type CodeRef = { path: string; line: number | null; note: string };
type Explanation = {
  status?: "pending" | "complete" | "unavailable";
  requested_at?: string;
  log?: { at: string; text: string }[];
  reason?: string;
  model?: string;
  text?: string;
  structured?: { summary?: string; code_refs?: CodeRef[]; remediation?: string; questions?: string[] } | null;
};
type Alert = { id: string; state: string; observation_date: string; acknowledged: boolean };

// AWS Bot Control's category vocabulary, in full. This started as five entries and
// everything else fell through to one grey, which on real traffic meant `http_library`,
// `miscellaneous` and `social_media` were three indistinguishable grey blocks in the
// same stack. Only `uncategorized` -- the absence of a category -- is grey now.
const CATEGORY_COLORS: Record<string, string> = {
  // Categories that usually appear together get base hues far apart. Teal reads as "fine"
  // elsewhere on the page, which suits uptime checks; red is kept for scanners, because
  // red means "look at this" everywhere else and monitoring traffic almost never does.
  ai: "var(--violet)",
  search_engine: "var(--accent)",
  monitoring: "var(--teal)",
  seo: "var(--amber)",
  security: "var(--red)",
  content_fetcher: "color-mix(in srgb, var(--accent) 55%, var(--teal))",
  // Script clients (curl, go-http) turn up beside content fetchers on real traffic, so
  // they get opposite sides of the wheel; advertising bots rarely do.
  http_library: "color-mix(in srgb, var(--amber) 60%, var(--red))",
  social_media: "color-mix(in srgb, var(--violet) 55%, var(--red))",
  advertising: "color-mix(in srgb, var(--accent) 70%, var(--ink-soft))",
  scraping_framework: "color-mix(in srgb, var(--teal) 55%, var(--amber))",
  link_checker: "color-mix(in srgb, var(--red) 50%, var(--ink-soft))",
  archiver: "color-mix(in srgb, var(--teal) 50%, var(--ink-soft))",
  education: "color-mix(in srgb, var(--amber) 50%, var(--ink-soft))",
  miscellaneous: "var(--ink-soft)",
  uncategorized: "var(--muted)",
};
// AWS sets the category, so the list above can still be outrun by a new one. Fall back
// to a stable pick from the same palette rather than to a grey that collides with
// `miscellaneous`: the same category then keeps one colour across days and renders.
const CATEGORY_FALLBACKS = [
  CATEGORY_COLORS.http_library,
  CATEGORY_COLORS.social_media,
  CATEGORY_COLORS.advertising,
  CATEGORY_COLORS.scraping_framework,
  CATEGORY_COLORS.security,
  CATEGORY_COLORS.link_checker,
  CATEGORY_COLORS.archiver,
  CATEGORY_COLORS.education,
];
const OBSERVATIONS: Record<string, string> = {
  enumeration_anomaly: "Possible object enumeration",
  account_enumeration_lead: "Account enumeration lead",
  sensitive_request_metadata: "Sensitive data in request metadata",
  shadow_route: "Route missing from the API contract",
  response_size_drift: "Response size drift",
  unverified_ai_surge: "Surge in unverified AI crawlers",
  bot_identity_spoof: "Possible crawler impersonation",
  bot_on_protected_route: "Bot allowed on an authenticated route",
  high_volume_client: "One client dominating an hour",
  ja4_endpoint_probing: "One TLS client probing endpoints",
  ja4_identifier_enumeration: "One TLS client walking identifiers",
  ja4_request_manipulation: "One TLS client sending attack payloads",
  lb_client_error_surge: "App refusing far more requests than usual",
  lb_server_error_surge: "App failing far more requests than usual",
  lb_latency_surge: "App responding far slower than usual",
  path_discovery: "Paths outside the supplied API contract",
  resource_id_enumeration: "Denied object ID enumeration",
  foreign_object_access: "Foreign object served by the application",
  credential_stuffing: "Login failures across accounts",
  distributed_brute_force: "One account attacked from multiple IPs",
  auth_success_after_attack: "Login succeeded after attack pattern",
  injection_attempts: "WAF payload-rule matches",
  slow_recon_ip: "Slow path reconnaissance by IP",
  slow_recon_ja4: "Slow path reconnaissance across IPs",
};
const CLIENT_FLAGS: Record<ClientFlag, string> = {
  ja4_endpoint_probing: "probing paths",
  ja4_identifier_enumeration: "walking ids",
  ja4_request_manipulation: "attack payloads",
};
const ALERT_STATES: Record<string, string> = {
  degraded: "Collection failed",
  anomaly: "New leads",
  baseline_ready: "Baseline ready",
  no_data: "No usable evidence",
  rapid_anomaly: "New short-window leads",
};
const RAPID_SKIPPED: Record<string, string> = {
  path_discovery: "Path discovery not evaluated",
  slow_recon: "Slow reconnaissance not evaluated",
  coverage: "Window coverage",
};

/** What the monitor's latest state means, in a sentence. */
function stateSummary(run: MonitoringRun | undefined, minimumDays: number) {
  if (!run) return "No collection run yet.";
  switch (run.state) {
    case "anomaly": return `Leads found on ${run.observation_date}.`;
    case "baseline_ready": return `Baseline ready; no leads on ${run.observation_date}.`;
    case "warming_up": return `Building the baseline: ${run.baseline_days_available} of ${minimumDays} consecutive days collected. Until then only leads one day supports on its own are shown.`;
    case "degraded": return `Collection failed for ${run.observation_date}.`;
    default: return "No usable evidence for this day.";
  }
}
const AI_REASONS: Record<string, string> = {
  disabled: "AI explanations are off. Set MONITORING_AI_PROVIDER=cursor.",
  not_configured: "CURSOR_API_KEY is not set.",
  runtime_missing: "The Cursor runtime is not installed. Build with WITH_CURSOR=1.",
  github_not_configured: "This monitor's repository has no read-only GitHub token.",
  repository_unavailable: "This monitor's repository source was revoked or changed.",
  credential_unavailable: "The repository token cannot be decrypted; check VAULT_KEY.",
  invalid_configuration: "CURSOR_MCP_SERVERS_JSON is invalid.",
  timeout: "The agent timed out.",
  agent_failed: "The agent run failed.",
  queue_unavailable: "The worker queue is unavailable.",
  provider_error: "The provider failed.",
};
const COLLECTION_ERRORS: Record<string, string> = {
  source_not_allowed: "Add the log group ARN to MONITORING_AWS_LOG_GROUPS.",
  credential_unavailable: "The worker has no AWS identity. Start it with make up-aws, or give it a role.",
  access_denied: "The worker's AWS identity needs logs:FilterLogEvents on this log group.",
  log_group_not_found: "The log group does not exist in that account and region.",
  row_limit: "The day has more events than MONITORING_AWS_MAX_EVENTS.",
  deadline_exceeded: "Collection ran past MONITORING_COLLECT_SECONDS.",
  call_limit: "Collection needed more pages than MONITORING_AWS_MAX_CALLS.",
  source_timeout: "CloudWatch Logs kept timing out after retries. Try again; the worker log shows how far it got.",
  source_connection: "CloudWatch Logs kept dropping the connection after retries. Try again.",
  source_unavailable: "CloudWatch Logs could not be read. The worker log (docker compose logs worker) names the error type.",
  cancelled: "Collection was cancelled.",
};

function categoryColor(category: string) {
  const known = CATEGORY_COLORS[category];
  if (known) return known;
  let hash = 0;
  for (let i = 0; i < category.length; i += 1) hash = (hash * 31 + category.charCodeAt(i)) | 0;
  return CATEGORY_FALLBACKS[Math.abs(hash) % CATEGORY_FALLBACKS.length];
}
const categoryLabel = (category: string) =>
  category === "ai" ? "AI" : category.replace(/_/g, " ").replace(/^./, (s) => s.toUpperCase());

function compact(n: number) {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(2).replace(/\.?0+$/, "")}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(2).replace(/\.?0+$/, "")}K`;
  return String(n);
}
const percent = (value: number | null) => (value === null ? "—" : `${value}%`);
// Cohorts are HMACs of clients; only bot names are meaningful to show.
function cohortLabel(cohort: unknown) {
  const value = String(cohort ?? "");
  if (value.startsWith("bot:")) return `claims to be ${value.slice(4)}`;
  if (value === "bots") return "all unverified AI crawlers";
  if (value === "load_balancer") return "whole load balancer";
  if (value.startsWith("ja4:")) return <>TLS client <code>{value.slice(4)}</code></>;
  return "one client";
}

// Every other path on this page is templated, because a path segment can carry a
// customer's name or slug. A payload-matched path is the sender's own string, so the
// normalizer keeps it verbatim and it is shown as received -- as text, never a link.
type Observation = Record<string, unknown>;

const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"] as const;
type SeverityName = (typeof SEVERITY_ORDER)[number];
const severityOf = (o: Observation): SeverityName =>
  (SEVERITY_ORDER as readonly string[]).includes(String(o.severity)) ? (o.severity as SeverityName) : "info";
const isSuppressed = (o: Observation) => o.disposition === "suppressed";

// One issue, however many times the detectors reported it. `sensitive_request_metadata`
// fires once per client and hour, so a single leaky route used to arrive as five
// identical cards. Grouping is presentation only: each member keeps its own fingerprint,
// so triage and AI explanations still attach to exactly what the detector produced.
interface ObservationGroup {
  key: string;
  type: string;
  method: string;
  route: string;
  members: Observation[];
  severity: SeverityName;
  verified: boolean;
  baseline: boolean;
  suppressed: boolean;
  cohorts: unknown[];
  hours: number[];
}

function groupObservations(observations: Observation[]): ObservationGroup[] {
  const groups = new Map<string, ObservationGroup>();
  for (const o of observations) {
    const type = String(o.type), method = String(o.method ?? "*"), route = String(o.route_family ?? "*");
    const key = `${type}|${method}|${route}`;
    let group = groups.get(key);
    if (!group) {
      group = { key, type, method, route, members: [], severity: "info", verified: false,
        baseline: false, suppressed: true, cohorts: [], hours: [] };
      groups.set(key, group);
    }
    group.members.push(o);
    if (SEVERITY_ORDER.indexOf(severityOf(o)) < SEVERITY_ORDER.indexOf(group.severity)) group.severity = severityOf(o);
    group.verified ||= o.confidence === "verified";
    group.baseline ||= o.basis !== "single_day";
    // A group is answered only when every member is; one open member keeps it open.
    group.suppressed &&= isSuppressed(o);
    if (o.cohort !== undefined && !group.cohorts.includes(o.cohort)) group.cohorts.push(o.cohort);
    const current = (o.current ?? {}) as Record<string, unknown>;
    for (const h of [...(Array.isArray(o.hours) ? o.hours : []), current.hour]) {
      if (typeof h === "number" && !group.hours.includes(h)) group.hours.push(h);
    }
  }
  // The API already returns worst-first; a Map keeps first-seen order, so groups inherit it.
  return [...groups.values()].map((g) => ({ ...g, hours: g.hours.sort((a, b) => a - b) }));
}

// Fingerprints name what and where, never the day, so the same lead on an earlier day
// carries the same fingerprint. What a reader needs from that is whether a lead is news
// or the same thing again: only complete days before `day` count as having looked.
type Recurrence = { earlier: string[]; looked: number };
function recurrence(group: ObservationGroup, runs: MonitoringRun[], day: string): Recurrence {
  const prints = new Set(group.members.map((o) => String(o.fingerprint)));
  const before = runs.filter((run) => run.status === "complete" && run.observation_date < day);
  return {
    earlier: before
      .filter((run) => run.observations.some((o) => prints.has(String(o.fingerprint))))
      .map((run) => run.observation_date),
    looked: before.length,
  };
}

function evidenceLabel(group: ObservationGroup) {
  if (group.verified) return "verified";
  return group.baseline ? "vs. baseline" : "single-day lead";
}

// The load balancer's CloudWatch metrics: one point per UTC hour, for the whole load
// balancer. No route and no client -- so a lead's hours are read against them as timing
// ("the app refused more than usual in that hour"), never as "this client got data".
interface LbHour {
  hour: number; requests: number;
  target_2xx: number; target_3xx: number; target_4xx: number; target_5xx: number;
  elb_4xx: number; elb_5xx: number; rejected_connections: number; target_connection_errors: number;
  response_avg: number | null; response_p99: number | null;
}
interface LbMetrics { error?: string; hours?: LbHour[]; total?: { requests?: number } }

const LB_ERRORS: Record<string, string> = {
  access_denied: "the worker's AWS identity lacks cloudwatch:GetMetricData",
  source_not_allowed: "the load balancer is not in MONITORING_AWS_LOAD_BALANCERS",
  credential_unavailable: "the worker has no usable AWS credentials",
  no_time_left: "the WAF read used the collection's time",
  invalid_source_data: "CloudWatch returned data that could not be read",
  incomplete_pagination: "CloudWatch's result ended early",
  binding_changed: "the load balancer changed during collection",
  invalid_configuration: "the load balancer ARN is incomplete",
};

const lbOf = (run: MonitoringRun | undefined) => (run?.metrics?.origin ?? null) as LbMetrics | null;

interface SampleMetrics { per_hour: number; limit: number; kept: number; read: number }

// Present only when the daily read kept the newest events of each UTC hour. A sampled
// day's event_count is the sample size, not how many requests the day carried.
const sampleOf = (run: MonitoringRun | undefined) =>
  (run?.metrics?.sample ?? null) as SampleMetrics | null;

interface LbWindow { requests: number; answered: number; ok: number; client: number; server: number; stopped: number; p99: number | null }

function lbWindow(metrics: LbMetrics | null, hours: number[] | null): LbWindow | null {
  const points = (metrics?.hours ?? []).filter((h) => hours === null || hours.includes(h.hour));
  if (!points.length) return null;
  const sum = (key: keyof LbHour) => points.reduce((total, h) => total + (Number(h[key]) || 0), 0);
  const p99s = points.map((h) => h.response_p99).filter((v): v is number => v !== null);
  return {
    requests: sum("requests"),
    answered: sum("target_2xx") + sum("target_3xx") + sum("target_4xx") + sum("target_5xx"),
    ok: sum("target_2xx"), client: sum("target_4xx"), server: sum("target_5xx"),
    stopped: sum("elb_4xx"),
    p99: p99s.length ? Math.max(...p99s) : null,
  };
}

const share = (part: number, whole: number) => (whole ? part / whole : null);
const median = (values: number[]) => {
  if (!values.length) return null;
  const sorted = [...values].sort((a, b) => a - b), mid = Math.floor(sorted.length / 2);
  return sorted.length % 2 ? sorted[mid] : (sorted[mid - 1] + sorted[mid]) / 2;
};

// "Usual" is the median over earlier collected days of the same hours, so an hour that is
// always busy with refusals (a nightly job) is compared with itself, not with the day.
function usualShare(runs: MonitoringRun[], latest: MonitoringRun, hours: number[] | null,
  pick: (w: LbWindow) => number | null): number | null {
  return median(runs
    .filter((r) => r.status === "complete" && r.observation_date < latest.observation_date)
    .map((r) => lbWindow(lbOf(r), hours))
    .map((w) => (w ? pick(w) : null))
    .filter((v): v is number => v !== null));
}

const pct = (value: number | null) =>
  value === null ? "—" : `${(value * 100).toFixed(value > 0 && value < 0.01 ? 2 : 1).replace(/\.0$/, "")}%`;
const usualNote = (value: number | null) => (value === null ? null : <small> (usual {pct(value)})</small>);

function LbLine({ runs, latest, hours, scope }: {
  runs: MonitoringRun[]; latest: MonitoringRun; hours: number[] | null; scope: string;
}) {
  const w = lbWindow(lbOf(latest), hours);
  if (!w) return null;
  if (!w.requests) return <p className="origin-line">{scope}: no requests recorded.</p>;
  const clientShare = (x: LbWindow) => share(x.client, x.answered);
  const serverShare = (x: LbWindow) => share(x.server, x.answered);
  return <p className="origin-line">
    {scope}: app answered <strong>{compact(w.answered)}</strong>
    {" · "}4XX <strong>{pct(clientShare(w))}</strong>{usualNote(usualShare(runs, latest, hours, clientShare))}
    {" · "}<span className={w.server ? "origin-5xx" : undefined}>5XX {pct(serverShare(w))}</span>
    {usualNote(usualShare(runs, latest, hours, serverShare))}
    {w.stopped > 0 && <> · {compact(w.stopped)} stopped at the load balancer</>}
    {w.p99 !== null && <> · p99 {Math.round(w.p99 * 1000)} ms</>}
  </p>;
}

// One UTC day of the load balancer, hour by hour. "Error rates" puts each hour's 4XX and
// 5XX share beside what that same hour usually is, which is exactly what the load
// balancer leads compare; "Responses" shows the volume those shares are taken of.
// Hours a lead named are banded, so the chart and the observations point at one thing.
function LoadBalancerChart({ runs, latest, flaggedHours }: {
  runs: MonitoringRun[]; latest: MonitoringRun; flaggedHours: Set<number>;
}) {
  const [mode, setMode] = useState<"rates" | "responses">("rates");
  const hours = lbOf(latest)?.hours ?? [];
  if (!hours.length) return null;
  const width = 640, height = 180, left = 52, right = 30, top = 10;
  const slot = (width - left - right) / 24;
  const x = (hour: number) => left + slot * hour + slot / 2;
  const answered = (h: LbHour) => h.target_2xx + h.target_3xx + h.target_4xx + h.target_5xx;
  const rate = (h: LbHour, key: "target_4xx" | "target_5xx") => (answered(h) ? h[key] / answered(h) : null);
  const usual = (hour: number, key: "target_4xx" | "target_5xx") =>
    usualShare(runs, latest, [hour], (w) => share(key === "target_4xx" ? w.client : w.server, w.answered));
  const series = (["target_4xx", "target_5xx"] as const).map((key) => ({
    key,
    label: key === "target_4xx" ? "4XX" : "5XX",
    color: key === "target_4xx" ? "var(--amber)" : "var(--red)",
    now: hours.map((h) => rate(h, key)),
    usual: hours.map((h) => usual(h.hour, key)),
  }));
  const hasUsual = series.some((s) => s.usual.some((v) => v !== null));
  const max = mode === "rates"
    ? niceMax(Math.max(0.01, ...series.flatMap((s) => [...s.now, ...s.usual]).filter((v): v is number => v !== null)))
    : niceMax(Math.max(1, ...hours.map(answered)));
  const y = (v: number) => top + height - (v / max) * height;
  const label = (v: number) => (mode === "rates" ? axisPct(v) : compact(Math.round(v)));
  const path = (values: (number | null)[]) => values
    .map((v, hour) => (v === null ? null : `${x(hour)},${y(v)}`))
    .reduce<string[][]>((runs, point) => {
      // A quiet hour breaks the line rather than drawing it down to zero.
      if (point === null) { if (runs[runs.length - 1]?.length) runs.push([]); return runs; }
      runs[runs.length - 1].push(point);
      return runs;
    }, [[]])
    .filter((run) => run.length);
  const stack: [keyof LbHour, string, string][] = [
    ["target_2xx", "var(--teal)", "2XX"], ["target_3xx", "var(--accent)", "3XX"],
    ["target_4xx", "var(--amber)", "4XX"], ["target_5xx", "var(--red)", "5XX"],
  ];
  const tip = (h: LbHour) => {
    const parts = series.map((s) => {
      const u = usual(h.hour, s.key);
      return `${s.label} ${pct(rate(h, s.key))}${u === null ? "" : ` (usual ${pct(u)})`}`;
    });
    return `${String(h.hour).padStart(2, "0")}:00 UTC · ${parts.join(" · ")} · answered ${compact(answered(h))}`
      + (h.elb_4xx ? ` · ${compact(h.elb_4xx)} stopped at the load balancer` : "")
      + (h.response_p99 !== null ? ` · p99 ${Math.round(h.response_p99 * 1000)} ms` : "");
  };

  return <div className="monitor-card lb-chart">
    <div className="bot-head route-trends-head">
      <h3>{mode === "rates" ? `Error rates by hour, ${latest.observation_date}` : `Responses by hour, ${latest.observation_date}`}</h3>
      <div className="bot-range" role="group" aria-label="Measure">{(["rates", "responses"] as const).map((option) => (
        <button key={option} className={`btn quiet sm${option === mode ? " active" : ""}`} aria-pressed={option === mode} onClick={() => setMode(option)}>
          {option === "rates" ? "Error rates" : "Responses"}
        </button>
      ))}</div>
    </div>
    <figure className="bot-chart">
      <svg viewBox={`0 0 ${width} ${top + height + 26}`} role="img" aria-label={`Load balancer ${mode} by UTC hour`}>
        {hours.filter((h) => flaggedHours.has(h.hour)).map((h) => (
          <rect key={`band-${h.hour}`} x={left + slot * h.hour} y={top} width={slot} height={height} style={{ fill: "var(--red-soft)" }} />
        ))}
        {[max, max / 2, 0].map((tick) => <g key={tick}>
          <line x1={left} x2={width - right} y1={y(tick)} y2={y(tick)} style={{ stroke: "var(--line)" }} />
          <text x={left - 6} y={y(tick) + 4} textAnchor="end" style={{ fill: "var(--muted)", fontSize: 11 }}>{label(tick)}</text>
        </g>)}
        {mode === "rates" ? series.map((s) => <g key={s.key}>
          {path(s.usual).map((run, i) => run.length > 1 && <polyline key={`u${i}`} points={run.join(" ")}
            style={{ fill: "none", stroke: s.color, strokeWidth: 1.5, strokeDasharray: "4 4", opacity: 0.55 }} />)}
          {path(s.now).map((run, i) => run.length > 1 && <polyline key={`n${i}`} points={run.join(" ")}
            style={{ fill: "none", stroke: s.color, strokeWidth: 2 }} />)}
          {s.now.map((v, hour) => v !== null && <circle key={hour} cx={x(hour)} cy={y(v)} r={2.5} style={{ fill: s.color }}>
            <title>{tip(hours[hour])}</title>
          </circle>)}
        </g>) : hours.map((h) => {
          let base = top + height;
          const bar = Math.max(2, slot * 0.68);
          return <g key={h.hour}>
            <title>{tip(h)}</title>
            {stack.map(([key, color]) => {
              const value = Number(h[key]) || 0;
              if (!value) return null;
              const barHeight = (value / max) * height;
              base -= barHeight;
              return <rect key={key} x={x(h.hour) - bar / 2} y={base} width={bar} height={barHeight} style={{ fill: color }} />;
            })}
          </g>;
        })}
        {[0, 4, 8, 12, 16, 20, 23].map((hour) => (
          <text key={hour} x={x(hour)} y={top + height + 18} textAnchor="middle" style={{ fill: "var(--muted)", fontSize: 11 }}>
            {String(hour).padStart(2, "0")}
          </text>
        ))}
      </svg>
      <figcaption className="bot-legend">
        {mode === "rates"
          ? <>
            {series.map((s) => <span key={s.key}><i style={{ background: s.color }} />{s.label} share of answers</span>)}
            {hasUsual
              ? <span><i className="legend-dashed" />usual for that hour (median of earlier days)</span>
              : <span>no earlier days with metrics yet, so no usual line</span>}
          </>
          : stack.map(([key, color, name]) => <span key={key}><i style={{ background: color }} />{name}</span>)}
        {flaggedHours.size > 0 && <span><i style={{ background: "var(--red-soft)" }} />hour named by a lead</span>}
      </figcaption>
    </figure>
    <p className="muted-sm">Whole load balancer, UTC hours. Shares are of what the app answered; requests the load balancer answered itself (a WAF block shows as ELB 403) are not in them.</p>
  </div>;
}

// The page's answer, before any evidence: is anything wrong on the latest day, and --
// just as important -- what was looked at and found fine. An empty list alone cannot
// say that: "we checked and it is clean" and "we never checked" render identically.
function Verdict({ run, runs, groups, routes, clients, minimumDays }: {
  run: MonitoringRun;
  runs: MonitoringRun[];
  groups: ObservationGroup[];
  // Null for a past day: route shares and TLS clients are read for the latest day only,
  // so they would describe a different day than the one on screen.
  routes: MonitoringRoutes | null;
  clients: MonitoringClients | null;
  minimumDays: number;
}) {
  const open = groups.filter((g) => !g.suppressed);
  const answered = groups.length - open.length;
  const previous = runs.find((r) => r.status === "complete" && r.observation_date < run.observation_date);
  const fresh = previous ? open.filter((g) => !recurrence(g, [previous], run.observation_date).earlier.length).length : null;
  const worst = open[0]?.severity;
  const judged = routes?.routes.filter((r) => r.state !== "warming_up") ?? [];
  const normalRoutes = judged.filter((r) => r.state === "normal").length;
  // `clients` is one page (50 by default), sorted flagged-first -- so every flagged client
  // is on it, and the quiet count is the population minus those, not the page minus them.
  // If the whole page is flagged there may be more beyond it, so claim nothing then.
  const listed = clients?.clients ?? [];
  const flaggedClients = listed.filter((c) => c.flags.length).length;
  const pageIsAllFlagged = listed.length > 0 && flaggedClients === listed.length
    && (clients?.clients_total ?? 0) > listed.length;
  const quietClients = (clients?.clients_total ?? 0) - flaggedClients;
  const baselineReady = run.data_quality === "sufficient";
  const lb = lbOf(run);
  const lbDay = lbWindow(lb, null);
  const tone = !open.length ? "clear" : worst === "critical" || worst === "high" ? "alert" : "warn";

  return <div className={`monitor-verdict ${tone}`} role="status">
    <div className="verdict-headline">
      <strong>
        {open.length
          ? `${open.length} issue${open.length === 1 ? "" : "s"} need${open.length === 1 ? "s" : ""} attention`
          : "Nothing needs attention"}
      </strong>
      <span>on {run.observation_date}</span>
    </div>
    <ul className="verdict-facts">
      {open.length > 0 && <li className="verdict-bad">
        {SEVERITY_ORDER.filter((sev) => open.some((g) => g.severity === sev)).map((sev) => (
          <span key={sev} className={`sev-chip ${sev}`}>{open.filter((g) => g.severity === sev).length} {sev}</span>
        ))}
      </li>}
      {open.length > 0 && fresh !== null && <li className={fresh ? "verdict-bad" : undefined}>
        {fresh ? `${fresh} new since ${previous!.observation_date}` : `All also open on ${previous!.observation_date}`}
      </li>}
      {answered > 0 && <li>{answered} answered (suppressed)</li>}
      {/* Only claim "normal" for what was actually judged against a baseline. */}
      {!routes ? null : baselineReady && judged.length > 0
        ? <li className="verdict-good">{normalRoutes} of {judged.length} routes within their usual share</li>
        : <li className="verdict-pending">Routes not judged yet: baseline {run.baseline_days_available} of {minimumDays} days</li>}
      {clients && clients.clients_total > 0 && !pageIsAllFlagged
        ? <li className="verdict-good">{compact(quietClients)} of {compact(clients.clients_total)} TLS clients met no lead</li>
        : null}
      {lb?.error
        ? <li className="verdict-pending">Load balancer metrics unavailable: {LB_ERRORS[lb.error] ?? lb.error}</li>
        : lbDay && lbDay.requests > 0
          // A day's average can hide the hour that failed: a HIGH 5XX lead in one hour is
          // still under 1% of the day. So an open load balancer lead decides the tone too.
          ? <li className={lbDay.server / Math.max(1, lbDay.answered) >= 0.01 || open.some((g) => g.type.startsWith("lb_")) ? "verdict-bad" : "verdict-good"}>
              App 5XX {pct(share(lbDay.server, lbDay.answered))}, 4XX {pct(share(lbDay.client, lbDay.answered))} of {compact(lbDay.answered)} answered
            </li>
          : null}
    </ul>
  </div>;
}

// Edits send only what changed: the API reads a key left out as "unchanged" and `null`
// as "remove", so re-sending an untouched field would be a no-op at best and, for the
// token, would need the secret the server deliberately never returns.
function SetupEditor({ monitorId, onSaved }: { monitorId: string; onSaved: () => void }) {
  const [view, setView] = useState<MonitoringSetupView | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const [spec, setSpec] = useState("");
  const [contract, setContract] = useState<"keep" | "replace" | "remove">("keep");

  const open = async () => {
    if (view) return;
    try { setView(await api.getMonitorSetup(monitorId)); } catch (e) { setError((e as Error).message); }
  };

  async function save(form: HTMLFormElement) {
    if (!view) return;
    const data = new FormData(form);
    const text = (name: string) => String(data.get(name) ?? "").trim();
    const update: MonitoringSetupUpdate = {};
    if (text("name") !== view.name) update.name = text("name");
    if ((data.get("daily") === "on") !== view.schedule_enabled) update.schedule_enabled = data.get("daily") === "on";
    if ((data.get("rapid") === "on") !== view.rapid_enabled) update.rapid_enabled = data.get("rapid") === "on";
    if (text("alb") !== (view.alb_arn ?? "")) update.alb_arn = text("alb") || null;
    const repoChanged = text("repository") !== (view.github_repository ?? "");
    if (repoChanged) update.github_repository = text("repository") || null;
    // A new repository gets the branch as typed; otherwise the server would default it.
    if (text("repository") && text("ref") && (repoChanged || text("ref") !== (view.github_ref ?? ""))) {
      update.github_ref = text("ref");
    }
    if (text("token")) update.github_token = text("token");
    if (contract === "replace") update.openapi = spec;
    if (contract === "remove") update.scan_id = null;
    if (!Object.keys(update).length) { setError("Nothing changed."); return; }
    setSaving(true); setError(null);
    try {
      setView(await api.updateMonitorSetup(monitorId, update));
      setContract("keep"); setSpec("");
      form.reset();
      onSaved();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setSaving(false);
    }
  }

  return <details className="monitor-card setup-editor" onToggle={(e) => { if ((e.target as HTMLDetailsElement).open) void open(); }}>
    <summary>Monitor settings</summary>
    {!view ? <p className="muted-sm">{error ?? "Loading…"}</p> : <ValidatedForm key={JSON.stringify(view)} onSubmit={(e) => { e.preventDefault(); void save(e.currentTarget); }}>
      <label>Name<input name="name" defaultValue={view.name} required maxLength={160} /></label>
      {/* The baseline compares one traffic stream day to day. A different target or WAF
          log group is a different stream, so it needs a new monitor, not an edit. */}
      <div className="setup-locked">
        <span>API base URL <code>{view.target_binding}</code></span>
        <span>AWS WAF log group <code>{view.waf_log_group_arn ?? "—"}</code></span>
        <small>Fixed for this monitor: its baseline compares days of this traffic. Create a new monitor to watch a different target or log group.</small>
      </div>
      <label>Application Load Balancer ARN
        <input name="alb" defaultValue={view.alb_arn ?? ""} spellCheck={false} placeholder="arn:aws:elasticloadbalancing:…:loadbalancer/app/<name>/<id>" />
      </label>
      <p className="muted-sm">Adds the HTTP status your app returned, which WAF logs lack. Clear it to detach; the monitor&apos;s history is kept.</p>
      <div className="monitor-setup-grid">
        <label>GitHub repository<input name="repository" defaultValue={view.github_repository ?? ""} spellCheck={false} placeholder="owner/repository" /></label>
        <label>Branch<input name="ref" defaultValue={view.github_ref ?? ""} spellCheck={false} placeholder="main" /></label>
      </div>
      <label>GitHub token
        <input name="token" type="password" autoComplete="off"
          placeholder={view.github_token_set ? "Stored — leave blank to keep it" : "github_pat_…"} />
      </label>
      <p className="muted-sm">Changing the repository never carries the old token over: a fine-grained token only covers the repository it was made for.</p>
      <fieldset>
        <legend>API contract</legend>
        <div className="contract-mode">
          <label><input type="radio" name="contract-edit" checked={contract === "keep"} onChange={() => setContract("keep")} /> {view.scan_id ? "Keep current" : "None"}</label>
          <label><input type="radio" name="contract-edit" checked={contract === "replace"} onChange={() => setContract("replace")} /> Replace with OpenAPI spec</label>
          {view.scan_id && <label><input type="radio" name="contract-edit" checked={contract === "remove"} onChange={() => setContract("remove")} /> Remove</label>}
        </div>
        {contract === "replace" && <>
          <label>Spec file<input type="file" accept=".json,.yaml,.yml,application/json,text/yaml" onChange={async (e) => { const file = e.target.files?.[0]; if (file) setSpec(await file.text()); }} /></label>
          <label>Spec contents<ExpandingTextarea value={spec} onChange={(e) => setSpec(e.target.value)} required spellCheck={false} /></label>
        </>}
      </fieldset>
      <label className="monitor-check"><input type="checkbox" name="daily" defaultChecked={view.schedule_enabled} /> Collect the previous UTC day every day after 02:00 UTC</label>
      <label className="monitor-check"><input type="checkbox" name="rapid" defaultChecked={view.rapid_enabled} /> Refresh every 5 minutes: publish an exact five-minute pulse and evaluate the rolling hour for slower reconnaissance</label>
      {error && <p className="monitor-error" role="alert">{error}</p>}
      <button className="btn" disabled={saving}>{saving ? "Saving…" : "Save settings"}</button>
    </ValidatedForm>}
  </details>;
}

// Pause, retention and deletion. The PATCH replaces all three fields, so every change
// re-sends the other two as the monitor has them.
function MonitorLifecycle({ monitor, onChanged, onDeleted }: {
  monitor: InfrastructureMonitor; onChanged: () => void; onDeleted: () => void;
}) {
  const confirmAction = useConfirmation();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const paused = monitor.status === "paused";
  async function run(work: () => Promise<unknown>, then: () => void) {
    setBusy(true); setError(null);
    try { await work(); then(); } catch (e) { setError((e as Error).message); } finally { setBusy(false); }
  }
  const patch = (change: Partial<{ status: "active" | "paused"; retention_days: number }>) =>
    run(() => api.updateMonitor(monitor.id, {
      status: monitor.status, schedule_enabled: monitor.schedule_enabled, retention_days: monitor.retention_days, ...change,
    }), onChanged);
  return <div className="monitor-card monitor-lifecycle">
    <div className="lifecycle-row">
      <div>
        <strong>{paused ? "Paused" : "Active"}</strong>
        <p className="muted-sm">{paused
          ? "No daily collection, no five-minute pulse and no new alerts. Retained evidence stays readable."
          : "Pausing stops daily collection and the five-minute pulse until you resume. A paused monitor raises no alerts, so its silence is not an all-clear."}</p>
      </div>
      <button className="btn quiet" disabled={busy} onClick={() => void patch({ status: paused ? "active" : "paused" })}>
        {paused ? "Resume monitoring" : "Pause monitoring"}
      </button>
    </div>
    <div className="lifecycle-row">
      <label>Keep evidence for
        <select value={monitor.retention_days} disabled={busy} onChange={(e) => {
          const days = Number(e.target.value);
          if (days < monitor.retention_days) {
            void confirmAction({ title: "Delete older monitoring evidence?", description: `Delete every day, alert and five-minute window older than ${days} days for ${monitor.name} now? This cannot be undone.`, actionLabel: "Delete older evidence", action: async () => {
              setBusy(true); setError(null);
              try { await api.updateMonitor(monitor.id, { status: monitor.status, schedule_enabled: monitor.schedule_enabled, retention_days: days }); onChanged(); }
              finally { setBusy(false); }
            } });
          } else void patch({ retention_days: days });
        }}>
          {[...new Set([31, 45, 60, 90, monitor.retention_days])].sort((a, b) => a - b).map((d) => <option key={d} value={d}>{d} days</option>)}
        </select>
      </label>
      <p className="muted-sm">The 28-day baseline needs at least 31. Shortening it deletes older evidence immediately.</p>
    </div>
    <div className="lifecycle-row danger">
      <div>
        <strong>Delete monitor</strong>
        <p className="muted-sm">Removes the monitor with its collected days, alerts, triage and AI commentary.</p>
      </div>
      <button className="btn quiet danger" disabled={busy} onClick={() => void confirmAction({ title: "Delete monitor permanently?", description: `Delete ${monitor.name} with all collected days, alerts, triage and AI commentary. This cannot be undone.`, actionLabel: "Delete monitor", confirmText: monitor.name, action: async () => {
        setBusy(true); setError(null);
        try { await api.deleteMonitor(monitor.id); onDeleted(); }
        finally { setBusy(false); }
      } })}>Delete monitor</button>
    </div>
    {error && <p className="monitor-error" role="alert">{error}</p>}
  </div>;
}

function AttackPaths({ evidence }: { evidence: unknown }) {
  const current = (evidence ?? {}) as Record<string, unknown>;
  const rows = (Array.isArray(current.attack_paths) ? current.attack_paths : [])
    .filter((row): row is Record<string, unknown> => !!row && typeof row === "object");
  if (!rows.length) return null;
  const total = Number(current.attack_paths_total ?? rows.length);
  const more = total - rows.length;
  return <div className="observation-paths">
    <p className="muted-sm">Paths it sent, as received (query strings are not kept):</p>
    <ul>{rows.map((row) => (
      <li key={String(row.path)}>
        <code>{String(row.path)}</code> <small>{compact(Number(row.requests) || 0)}&times;</small>
      </li>
    ))}</ul>
    {more > 0 && <p className="muted-sm">{compact(more)} more distinct path{more === 1 ? "" : "s"}.</p>}
  </div>;
}

function ClientFingerprints({ data }: { data: MonitoringClients }) {
  const shown = data.clients.slice(0, 15);
  return <div className="monitor-card">
    <p className="muted-sm">
      {data.day}: {data.clients_total} fingerprint{data.clients_total === 1 ? "" : "s"}{data.sampled ? " in the sample" : ""}.
      A browser build shares one JA4 across all its users, so breadth is judged per request and per address.
      Traffic your allow rules let through and verified bots never count toward a lead.
    </p>
    <div className="bot-table-wrap"><table className="bot-table">
      <thead><tr><th>JA4</th><th className="num">Requests</th><th className="num">Addresses</th><th className="num">Distinct paths</th><th>Most identifiers on one route</th><th className="num">Payload matches</th><th>Leads</th></tr></thead>
      <tbody>{shown.map((row) => (
        <tr key={row.ja4} className={row.flags.length ? "flagged" : undefined}>
          <td className="ja4-cell"><code>{row.ja4}</code>
            {(row.trusted > 0 || row.verified_bot > 0 || row.bot) && <small>
              {[row.trusted && `${compact(row.trusted)} via allow rules`, row.verified_bot && `${compact(row.verified_bot)} verified bot`, row.bot && `labelled ${row.bot}`].filter(Boolean).join(" · ")}
            </small>}
          </td>
          {/* What the WAF actually did with these requests. The table is already wider
              than its card, so this rides under Requests rather than adding a column;
              silence here means every one of them reached the origin. */}
          <td className="num">{compact(row.requests)}
            {row.blocked + row.challenged > 0
              ? <small title={`${row.blocked} blocked, ${row.challenged} challenged`}>
                  {compact(row.blocked + row.challenged)} stopped
                </small>
              : <small className="all-allowed">all allowed</small>}
          </td>
          <td className="num">{compact(row.addresses)}</td>
          <td className="num" title={row.eligible ? `${Math.round(100 * row.paths / row.eligible)}% of its requests asked for a new path` : undefined}>{compact(row.paths)}</td>
          <td>{row.identifiers
            ? <><code>{row.identifiers.route}</code> {compact(row.identifiers.distinct)} ids{row.identifiers.parameters.length ? ` (${row.identifiers.parameters.join(", ")})` : ""}, {Math.round(row.identifiers.sequentiality * 100)}% consecutive</>
            : "—"}</td>
          <td className="num" title={Object.entries(row.attack_labels).map(([label, n]) => `${label}: ${n}`).join("\n") || undefined}>
            {row.attack_requests ? <>{compact(row.attack_requests)}{row.attack_allowed ? <small> {compact(row.attack_allowed)} allowed</small> : null}</> : "—"}
          </td>
          <td>{row.flags.length ? row.flags.map((flag) => <span key={flag} className="st-chip anomaly">{CLIENT_FLAGS[flag]}</span>) : "—"}</td>
        </tr>
      ))}</tbody>
    </table></div>
    {data.clients_total > shown.length && <p className="muted-sm">{data.clients_total - shown.length} more fingerprints; those meeting a lead are listed first.</p>}
  </div>;
}

type AlertGroup = { key: string; state: string; day: string; alerts: Alert[] };

function groupAlerts(alerts: Alert[]): AlertGroup[] {
  const groups = new Map<string, AlertGroup>();
  for (const alert of alerts) {
    const key = `${alert.state}|${alert.observation_date}`;
    const group = groups.get(key) ?? { key, state: alert.state, day: alert.observation_date, alerts: [] };
    group.alerts.push(alert);
    groups.set(key, group);
  }
  return [...groups.values()];
}

function Kpi({ label, value, hint }: { label: string; value: string; hint?: string }) {
  return <div className="bot-kpi"><span>{label}</span><strong>{value}</strong>{hint && <small>{hint}</small>}</div>;
}

// An axis a reader can do arithmetic with: the smallest 1/1.2/1.5/2/2.5/3/4/5/6/8 x
// a power of ten that still covers the data. A 467-request day labels its axis 500.
const AXIS_STEPS = [1, 1.2, 1.5, 2, 2.5, 3, 4, 5, 6, 8, 10];
function niceMax(value: number) {
  if (!(value > 0)) return 1;
  const magnitude = 10 ** Math.floor(Math.log10(value));
  const step = AXIS_STEPS.find((n) => value <= n * magnitude * 1.0000001) ?? 10;
  return step * magnitude;
}

// Evenly spaced label positions that always include the first and last day, so the
// axis reads the same whether a monitor has 8 days or 28.
function labelledDays(count: number, most = 6) {
  const shown = Math.min(count, most);
  if (shown <= 1) return new Set([0]);
  return new Set(
    Array.from({ length: shown }, (_, k) => Math.round((k * (count - 1)) / (shown - 1))),
  );
}

const axisPct = (value: number) => `${+(value * 100).toFixed(1)}%`;

function CategoryBars({ series }: { series: MonitoringBots["series"] }) {
  const [mode, setMode] = useState<"requests" | "share">("requests");
  const [picked, setPicked] = useState<number | null>(null);
  const categories = [...new Set(series.flatMap((day) => Object.keys(day.by_category)))]
    .sort((a, b) => (a === "ai" ? -1 : b === "ai" ? 1 : a.localeCompare(b)));
  const totals = series.map((day) => Object.values(day.by_category).reduce((sum, n) => sum + n, 0));
  const max = mode === "share" ? 1 : niceMax(Math.max(1, ...totals));
  const width = 640, top = 18, height = 170, left = 44, right = 12;
  // Bars sit centred in their slot with real space between them: at eight days a
  // gapless bar is 71px wide and the row reads as one block rather than eight days.
  const slot = (width - left - right) / Math.max(series.length, 1);
  const bar = Math.max(2, Math.min(slot * 0.68, 46));
  // Every day gets its label when there is room for it; thinning is for long windows only.
  const labelled = slot >= 44
    ? new Set(series.map((_, i) => i))
    : labelledDays(series.length, Math.max(2, Math.floor((width - left - right) / 44)));
  const y = (value: number) => top + height - (value / max) * height;
  const ticks = [max, max / 2, 0];
  const shown = picked ?? series.length - 1;
  const day = series[shown];
  const earlier = totals.slice(0, shown);
  const usual = median(earlier);

  return <div className="category-bars">
    <div className="bot-head route-trends-head">
      <h3>Bot requests by category</h3>
      <div className="bot-range" role="group" aria-label="Measure">{(["requests", "share"] as const).map((option) => (
        <button key={option} className={`btn quiet sm${option === mode ? " active" : ""}`} aria-pressed={option === mode} onClick={() => setMode(option)}>
          {option === "requests" ? "Requests" : "Share"}
        </button>
      ))}</div>
    </div>
    <figure className="bot-chart">
      <svg viewBox={`0 0 ${width} ${top + height + 26}`} role="img"
        aria-label={mode === "share" ? "Share of bot requests per day by category" : "Bot requests per day by category"}
        onMouseLeave={() => setPicked(null)}>
        {ticks.map((tick) => <g key={tick}>
          <line x1={left} x2={width - right} y1={y(tick)} y2={y(tick)} style={{ stroke: "var(--line)" }} />
          <text x={left - 6} y={y(tick) + 4} textAnchor="end" style={{ fill: "var(--muted)", fontSize: 11 }}>
            {mode === "share" ? axisPct(tick) : compact(Math.round(tick))}
          </text>
        </g>)}
        {series.map((entry, i) => {
          const total = totals[i];
          const x = left + i * slot + (slot - bar) / 2;
          let base = top + height;
          return <g key={entry.day} className="category-day"
            style={{ opacity: picked !== null && picked !== i ? 0.4 : 1 }}>
            {categories.map((category) => {
              const count = entry.by_category[category] ?? 0;
              if (!count || !total) return null;
              const h = ((mode === "share" ? count / total : count) / max) * height;
              base -= h;
              return <rect key={category} x={x} y={base} width={bar} height={h} style={{ fill: categoryColor(category) }} />;
            })}
            {mode === "requests" && <text x={x + bar / 2} y={base - 5} textAnchor="middle"
              className={i === shown ? "bar-total picked" : "bar-total"}>{total ? compact(total) : "0"}</text>}
            {labelled.has(i) && <text x={x + bar / 2} y={top + height + 18} textAnchor="middle"
              style={{ fill: i === shown ? "var(--ink)" : "var(--muted)", fontSize: 11, fontWeight: i === shown ? 600 : 400 }}>
              {entry.day.slice(5)}
            </text>}
            {/* The whole column is the target, so a two-pixel day is as easy to pick as a tall one. */}
            <rect x={left + i * slot} y={top} width={slot} height={height + 24} className="category-hit"
              tabIndex={0} role="button" aria-label={`${entry.day}: ${compact(total)} bot requests`}
              onMouseEnter={() => setPicked(i)} onFocus={() => setPicked(i)} onClick={() => setPicked(i)} />
          </g>;
        })}
      </svg>
      {day && <div className="category-readout" aria-live="polite">
        <strong>{day.day}</strong>
        <span>
          {compact(totals[shown])} bot requests
          {usual !== null && usual > 0 && <small>
            {" "}({totals[shown] >= usual
              ? `${(totals[shown] / usual).toFixed(totals[shown] / usual >= 10 ? 0 : 1)}× the`
              : `${Math.round((totals[shown] / usual) * 100)}% of the`} median of earlier days, {compact(usual)})
          </small>}
        </span>
        <ul>{categories.filter((c) => day.by_category[c]).map((category) => (
          <li key={category}>
            <i style={{ background: categoryColor(category) }} />{categoryLabel(category)}{" "}
            <b>{compact(day.by_category[category])}</b>
            <small> {pct(share(day.by_category[category], totals[shown]))}</small>
          </li>
        ))}</ul>
      </div>}
      <figcaption className="bot-legend">{categories.map((category) => (
        <span key={category}><i style={{ background: categoryColor(category) }} />{categoryLabel(category)}</span>
      ))}</figcaption>
    </figure>
  </div>;
}

const ROUTE_COLORS = [
  "var(--accent)",
  "var(--teal)",
  "var(--amber)",
  "var(--violet)",
  "var(--red)",
  "var(--ink-soft)",
  "color-mix(in srgb, var(--accent) 50%, var(--teal))",
  "color-mix(in srgb, var(--amber) 50%, var(--red))",
];
const ROUTE_STATE_CHIP = { anomaly: "anomaly", normal: "baseline_ready", warming_up: "warming_up" } as const;
// The worker gives up on an agent after MONITORING_AI_TIMEOUT_SECONDS (10 minutes by
// default); a request still pending after this is stuck.
const STALE_PENDING_MS = 12 * 60_000;
const isStale = (explanation?: { status?: string; requested_at?: string | null }) =>
  explanation?.status === "pending" &&
  !!explanation.requested_at &&
  Date.now() - Date.parse(explanation.requested_at) > STALE_PENDING_MS;
const sharePct = (share: number | null) =>
  share === null ? "—" : `${(share * 100).toFixed(share < 0.01 ? 2 : 1)}%`;
const signedPct = (change: number | null) =>
  change === null ? "—" : `${change > 0 ? "+" : ""}${Math.round(change * 100)}%`;

function RouteTrends({ data }: { data: MonitoringRoutes }) {
  const [metric, setMetric] = useState<"share" | "requests">("share");
  const [focus, setFocus] = useState<string | null>(null);
  const days = data.routes[0]?.series.map((point) => point.day) ?? [];
  const value = (point: RouteDay) => (metric === "share" ? point.share : point.requests);
  const max = niceMax(Math.max(metric === "share" ? 0.01 : 1, ...data.routes.flatMap((route) => route.series.map(value))));
  // `right` has to clear both an anomaly ring on the last point and half of the last
  // day's label; at 12 it clipped each of them against the viewBox edge.
  const width = 640, height = 200, left = 52, right = 30, top = 10;
  const x = (i: number) =>
    days.length <= 1 ? left + (width - left - right) / 2 : left + (i * (width - left - right)) / (days.length - 1);
  const y = (v: number) => top + height - (v / max) * height;
  const label = (v: number) => (metric === "share" ? axisPct(v) : compact(Math.round(v)));
  const labelled = labelledDays(days.length);
  return <div className="monitor-card route-trends">
    <div className="bot-head route-trends-head">
      <h3>{metric === "share" ? "Share of traffic by route" : "Requests by route"}</h3>
      <div className="bot-range" role="group" aria-label="Measure">{(["share", "requests"] as const).map((option) => (
        <button key={option} className={`btn quiet sm${option === metric ? " active" : ""}`} aria-pressed={option === metric} onClick={() => setMetric(option)}>
          {option === "share" ? "Share" : "Requests"}
        </button>
      ))}</div>
    </div>
    <figure className="bot-chart">
      <svg viewBox={`0 0 ${width} ${top + height + 26}`} role="img" aria-label={`Daily ${metric} for the main routes`}>
        {[max, max / 2, 0].map((tick) => <g key={tick}>
          <line x1={left} x2={width - right} y1={y(tick)} y2={y(tick)} style={{ stroke: "var(--line)" }} />
          <text x={left - 6} y={y(tick) + 4} textAnchor="end" style={{ fill: "var(--muted)", fontSize: 11 }}>{label(tick)}</text>
        </g>)}
        {data.routes.map((route, index) => {
          const color = ROUTE_COLORS[index % ROUTE_COLORS.length];
          const last = route.series[route.series.length - 1];
          return <g key={route.route} style={{ opacity: focus !== null && focus !== route.route ? 0.15 : 1 }}>
            {route.series.length > 1 && <polyline
              points={route.series.map((point, i) => `${x(i)},${y(value(point))}`).join(" ")}
              style={{ fill: "none", stroke: color, strokeWidth: focus === route.route ? 3 : 2 }}
            />}
            {route.series.map((point, i) => <circle key={point.day} cx={x(i)} cy={y(value(point))} r={route.series.length > 1 ? 2.5 : 4} style={{ fill: color }}>
              <title>{`${route.route} · ${point.day}: ${metric === "share" ? sharePct(point.share) : compact(point.requests)}`}</title>
            </circle>)}
            {route.state === "anomaly" && last && <>
              {/* Routes that all collapse to ~0% stack their rings; a card-coloured
                  halo under each one keeps them countable instead of a red blob. */}
              <circle cx={x(route.series.length - 1)} cy={y(value(last))} r={7}
                style={{ fill: "none", stroke: "var(--surface)", strokeWidth: 4 }} />
              <circle cx={x(route.series.length - 1)} cy={y(value(last))} r={7}
                style={{ fill: "none", stroke: "var(--red)", strokeWidth: 2 }} />
            </>}
          </g>;
        })}
        {days.map((day, i) => labelled.has(i) && <text key={day} x={x(i)} y={top + height + 18} textAnchor="middle" style={{ fill: "var(--muted)", fontSize: 11 }}>{day.slice(5)}</text>)}
      </svg>
    </figure>
    <div className="bot-table-wrap"><table className="bot-table route-table">
      <thead><tr><th>Route</th><th className="num">Latest day</th><th className="num">Share</th><th className="num">Baseline</th><th className="num">Change</th><th>State</th></tr></thead>
      <tbody>{data.routes.map((route, index) => (
        <tr key={route.route} className={focus === route.route ? "focused" : undefined}>
          <td><button type="button" className="route-name" aria-pressed={focus === route.route} onClick={() => setFocus(focus === route.route ? null : route.route)}>
            <i style={{ background: ROUTE_COLORS[index % ROUTE_COLORS.length] }} /><code>{route.route}</code>
          </button></td>
          <td className="num">{compact(route.latest_requests)}</td>
          <td className="num">{sharePct(route.latest_share)}</td>
          <td className="num">{sharePct(route.baseline_share)}</td>
          <td className="num">{signedPct(route.change)}</td>
          <td><span className={`st-chip ${ROUTE_STATE_CHIP[route.state]}`} title={route.score === null ? undefined : `score ${route.score}`}>
            {route.state === "warming_up" ? "warming up" : route.state}
          </span></td>
        </tr>
      ))}</tbody>
    </table></div>
    <p className="muted-sm">Each route is compared by its share of the day&apos;s collected traffic against its own median over the previous days, so sampled and busy days stay comparable. A route is flagged when it moves well outside its usual spread and by at least 30%; it needs {data.minimum_baseline_days} prior days first. Click a route to focus it.</p>
  </div>;
}

function AgentLog({ lines, live }: { lines?: Explanation["log"]; live?: boolean }) {
  if (!lines?.length) return null;
  const shown = lines.slice(-15);
  return <ol className="agent-log" aria-live={live ? "polite" : undefined}>
    {shown.map((line, i) => <li key={`${line.at}-${i}`}><time>{line.at.slice(11, 19)}</time>{line.text}</li>)}
  </ol>;
}

function PastLog({ lines }: { lines?: Explanation["log"] }) {
  if (!lines?.length) return null;
  return <details className="agent-log-details"><summary>Agent log ({lines.length})</summary><AgentLog lines={lines} /></details>;
}

function ExplanationView({ explanation }: { explanation: Explanation }) {
  if (isStale(explanation)) {
    return <div className="explanation muted">The explanation did not finish. Try again.<PastLog lines={explanation.log} /></div>;
  }
  if (explanation.status === "pending") {
    return <div className="explanation" role="status">
      Reading the repository and the evidence…
      <AgentLog lines={explanation.log} live />
    </div>;
  }
  if (explanation.status === "unavailable") {
    return <div className="explanation muted">
      AI explanation unavailable: {AI_REASONS[explanation.reason ?? ""] ?? explanation.reason}
      <PastLog lines={explanation.log} />
    </div>;
  }
  const structured = explanation.structured;
  return <div className="explanation">
    <div className="explanation-label">AI explanation · commentary, not evidence</div>
    {structured?.summary ? <p>{structured.summary}</p> : <p>{explanation.text}</p>}
    {!!structured?.code_refs?.length && <ul className="code-refs">{structured.code_refs.map((ref, i) => (
      <li key={i}><code>{ref.path}{ref.line ? `:${ref.line}` : ""}</code> {ref.note}</li>
    ))}</ul>}
    {structured?.remediation && <p><strong>Suggested fix:</strong> {structured.remediation}</p>}
    {!!structured?.questions?.length && <ul>{structured.questions.map((q, i) => <li key={i}>{q}</li>)}</ul>}
    <PastLog lines={explanation.log} />
  </div>;
}

type BriefingItem = { title?: string; why?: string; action?: string; days?: string; lead_type?: string | null };
type BriefingBody = {
  headline?: string;
  verdict?: "act_now" | "review" | "all_clear" | "not_enough_data";
  traffic_summary?: string;
  act_now?: BriefingItem[];
  review?: BriefingItem[];
  safe_to_ignore?: BriefingItem[];
  earlier?: BriefingItem[];
  alerting?: { current_state?: string; will_alert_when?: string[]; gaps?: string[] };
  questions?: string[];
};
const BRIEFING_VERDICTS = {
  act_now: { label: "Act now", tone: "alert" },
  review: { label: "Review this week", tone: "warn" },
  all_clear: { label: "Nothing to act on", tone: "clear" },
  not_enough_data: { label: "Not enough data yet", tone: "warn" },
} as const;
const items = (value: unknown): BriefingItem[] =>
  Array.isArray(value) ? value.filter((v): v is BriefingItem => !!v && typeof v === "object") : [];
const strings = (value: unknown): string[] =>
  Array.isArray(value) ? value.filter((v): v is string => typeof v === "string") : [];

function BriefingList({ title, entries, tone }: { title: string; entries: BriefingItem[]; tone: string }) {
  if (!entries.length) return null;
  return <div className={`briefing-group ${tone}`}>
    <h3>{title}</h3>
    <ul>{entries.map((item, i) => <li key={i}>
      <strong>{item.title}</strong>
      {item.lead_type && <> <code>{item.lead_type}</code></>}
      {item.days && <small className="briefing-days">{item.days}</small>}
      {item.why && <p>{item.why}</p>}
      {item.action && <p className="briefing-action"><b>Do:</b> {item.action}</p>}
    </li>)}</ul>
  </div>;
}

/** Plain-language answer to "should I care, when do I react, and how would it alert". */
function TrafficBriefing({ briefing, days, onRequest }: {
  briefing: MonitoringBriefing | null;
  days: number;
  onRequest: () => void;
}) {
  const running = briefing?.status === "pending" && !isStale(briefing);
  const body = (briefing?.status === "complete" ? briefing.structured : null) as BriefingBody | null;
  const verdict = body?.verdict ? BRIEFING_VERDICTS[body.verdict] : undefined;
  const alerting = body?.alerting && typeof body.alerting === "object" ? body.alerting : undefined;
  return <div className={`monitor-card briefing ${verdict?.tone ?? ""}`}>
    <div className="briefing-head">
      <div>
        <div className="eyebrow">Evidence-backed commentary</div>
        <h2>AI security analyst</h2>
        <p className="muted-sm">What in the last {days} days of bot, AI and client traffic is worth caring about, when to react, and how it would raise an alert.</p>
      </div>
      <button className="btn quiet" disabled={running} onClick={onRequest}>
        {running ? "Briefing…" : briefing?.status === "complete" ? "Brief again" : "Brief me with AI"}
      </button>
    </div>
    {briefing && isStale(briefing) && <p className="muted">The briefing did not finish. Try again.</p>}
    {running && <div role="status">Reading the traffic, leads and alert history…<AgentLog lines={briefing?.log} live /></div>}
    {briefing?.status === "unavailable" && <p className="muted">
      AI briefing unavailable: {AI_REASONS[briefing.reason ?? ""] ?? briefing.reason}
    </p>}
    {briefing?.status === "complete" && <>
      <div className="explanation-label">
        {briefing.days} days through {briefing.evidence_through ?? "—"} · commentary, not evidence
      </div>
      {briefing.evidence_trimmed.length > 0 && <p className="briefing-trimmed" role="note">
        The evidence was too large to send whole, so this briefing may miss detail in: {briefing.evidence_trimmed.join(", ")}.
      </p>}
      {!body ? <p>{briefing.text}</p> : <>
        <div className="verdict-headline briefing-headline">
          {verdict && <span className={`briefing-verdict ${verdict.tone}`}>{verdict.label}</span>}
          <strong>{body.headline}</strong>
        </div>
        {body.traffic_summary && <p>{body.traffic_summary}</p>}
        <div className="briefing-groups">
          <BriefingList title="Act now" entries={items(body.act_now)} tone="alert" />
          <BriefingList title="Review" entries={items(body.review)} tone="warn" />
          <BriefingList title="Safe to ignore" entries={items(body.safe_to_ignore)} tone="clear" />
          <BriefingList title="Earlier in this window" entries={items(body.earlier)} tone="past" />
        </div>
        {alerting && <div className="briefing-alerting">
          <h3>How this alerts</h3>
          {alerting.current_state && <p>{alerting.current_state}</p>}
          {strings(alerting.will_alert_when).length > 0 && <><b>Raises an alert when</b>
            <ul>{strings(alerting.will_alert_when).map((line, i) => <li key={i}>{line}</li>)}</ul></>}
          {strings(alerting.gaps).length > 0 && <><b>Will not alert on</b>
            <ul>{strings(alerting.gaps).map((line, i) => <li key={i}>{line}</li>)}</ul></>}
        </div>}
        {strings(body.questions).length > 0 && <details className="briefing-questions"><summary>Open questions</summary>
          <ul>{strings(body.questions).map((q, i) => <li key={i}>{q}</li>)}</ul></details>}
      </>}
      <PastLog lines={briefing.log} />
    </>}
  </div>;
}

const MINUTE_MS = 60_000, DAY_MS = 86_400_000;
// The rapid check runs every 5 minutes; three missed runs is a stalled check, and a
// stalled check reads exactly like a quiet hour unless the page says otherwise.
const RAPID_STALE_MS = 20 * MINUTE_MS;

function ago(iso: string | null | undefined) {
  if (!iso) return null;
  const ms = Date.now() - Date.parse(iso);
  if (!Number.isFinite(ms)) return null;
  const minutes = Math.round(ms / MINUTE_MS);
  if (minutes < 1) return "just now";
  if (minutes < 60) return `${minutes} min ago`;
  const hours = Math.round(minutes / 60);
  return hours < 48 ? `${hours} h ago` : `${Math.round(hours / 24)} d ago`;
}

// Daily collection reads the previous UTC day after 02:00 UTC, so an on-schedule
// monitor's latest day is yesterday. Anything older is a collection falling behind.
function daysBehind(observationDate: string) {
  const today = Date.parse(new Date().toISOString().slice(0, 10));
  return Math.round((today - Date.parse(observationDate)) / DAY_MS) - 1;
}
// The last two weeks of completed UTC days, collected or not. A day with no run is a hole
// in the evidence, and the baseline only counts an unbroken run of complete days before
// each day, so a hole also delays or shortens the baseline of every day after it.
const HISTORY_DAYS = 14;
type HistoryDay = { day: string; run: MonitoringRun | undefined };
function historyDays(runs: MonitoringRun[], retentionDays: number): HistoryDay[] {
  const today = Date.parse(new Date().toISOString().slice(0, 10));
  const byDay = new Map(runs.map((run) => [run.observation_date, run]));
  const span = Math.min(HISTORY_DAYS, retentionDays);
  const days = Array.from({ length: span }, (_, i) => new Date(today - (i + 1) * DAY_MS).toISOString().slice(0, 10));
  // Runs older than the fortnight stay listed, so nothing that exists is hidden.
  const older = runs.filter((run) => !days.includes(run.observation_date)).map((run) => run.observation_date);
  return [...days, ...older].map((day) => ({ day, run: byDay.get(day) }));
}
const rapidIsStale = (run: MonitoringRapidRun | undefined) =>
  !run || Date.now() - Date.parse(run.created_at) > RAPID_STALE_MS;

const worstSeverity = (observations: Observation[]) =>
  SEVERITY_ORDER.find((sev) => observations.some((o) => severityOf(o) === sev));
const toneOf = (severity: SeverityName | undefined) =>
  !severity ? "clear" : severity === "critical" || severity === "high" ? "alert" : "warn";
const plural = (n: number, word: string) => `${n} ${word}${n === 1 ? "" : "s"}`;
const hourList = (hours: number[]) => hours.map((h) => String(h).padStart(2, "0")).join(", ");

type VolumeSource = "load_balancer" | "waf" | "sample";
type DayVolume = { requests: number; source: VolumeSource };

// The load balancer counts every request; a sampled WAF day counts only the newest
// events of each hour, so its size says nothing about how busy the day was. The total
// is used when it is present and readable, and the source is carried alongside so the
// page never compares a capped sample with a full count.
function dayVolume(run: MonitoringRun): DayVolume {
  const lbRequests = lbOf(run)?.total?.requests;
  if (typeof lbRequests === "number" && Number.isFinite(lbRequests) && lbRequests > 0) {
    return { requests: lbRequests, source: "load_balancer" };
  }
  return {
    requests: Number(run.metrics.event_count ?? 0),
    source: sampleOf(run) ? "sample" : "waf",
  };
}

type DailySnapshot = {
  events: number;
  volume: DayVolume;
  blocked: number;
  offSpec: number | null;
  attacks: number;
  attacksAllowed: number;
};

function dailySnapshot(run: MonitoringRun | undefined, hasContract: boolean): DailySnapshot | null {
  if (!run || run.status !== "complete") return null;
  const routes = run.metrics.routes && typeof run.metrics.routes === "object"
    ? Object.values(run.metrics.routes as Record<string, Record<string, unknown>>) : [];
  const clientMetrics = run.metrics.clients && typeof run.metrics.clients === "object"
    ? run.metrics.clients as { clients?: Record<string, unknown>[] } : {};
  const clients = Array.isArray(clientMetrics.clients) ? clientMetrics.clients : [];
  return {
    events: Number(run.metrics.event_count ?? 0),
    volume: dayVolume(run),
    blocked: routes.reduce((total, row) => total + Number(row.blocked_requests ?? 0), 0),
    offSpec: hasContract ? Number(run.metrics.unmapped_count ?? 0) : null,
    attacks: clients.reduce((total, row) => total + Number(row.attack_requests ?? 0), 0),
    attacksAllowed: clients.reduce((total, row) => total + Number(row.attack_allowed ?? 0), 0),
  };
}

function DailyBars({ runs }: { runs: MonitoringRun[] }) {
  const points = runs.filter((run) => run.status === "complete").slice(0, 14).reverse().map((run) => ({ run, volume: dayVolume(run) }));
  if (!points.length) return null;
  // A sampled day has no comparable height, so it neither sets the scale nor reads as a dip.
  const max = Math.max(1, ...points.filter((p) => p.volume.source !== "sample").map((p) => p.volume.requests));
  const allLoadBalancer = points.every((p) => p.volume.source === "load_balancer");
  return <figure className="daily-bars" aria-label="Daily request volume over the latest collected days">
    <div className="daily-bars-plot">{points.map(({ run, volume }) => {
      const sampled = volume.source === "sample";
      const label = volume.source === "load_balancer" ? "load balancer" : "WAF";
      return <div className={`daily-bar-slot${sampled ? " sampled" : ""}`} key={run.id}
        title={sampled
          ? `${run.observation_date}: no load balancer total — WAF sample only`
          : `${run.observation_date}: ${volume.requests.toLocaleString()} requests (${label})`}>
        <i style={{ height: `${sampled ? 3 : Math.max(3, volume.requests / max * 100)}%` }} />
        <small>{run.observation_date.slice(5)}</small>
      </div>;
    })}</div>
    <figcaption>{allLoadBalancer
      ? "Daily request volume (load balancer) · newest at right"
      : "Daily request volume · newest at right · faded days have no load balancer total"}</figcaption>
  </figure>;
}

const PULSE_SLOTS = 12;
const PULSE_MS = 5 * 60_000;
const hhmm = (ms: number) => new Date(ms).toISOString().slice(11, 16);

type PulseSlot =
  | { kind: "gap"; end: number }
  | { kind: "failed"; end: number; reason: string }
  | { kind: "window"; end: number; run: MonitoringRapidRun };

// A read that could not reach the logs stores an empty pulse; it is a coverage gap, not
// a quiet five minutes, and must never be drawn as low traffic.
function failedRead(run: MonitoringRapidRun): string | null {
  const coverage = run.skipped?.coverage;
  return coverage && coverage.startsWith("unavailable") ? coverage.replace(/^unavailable:\s*/, "") : null;
}

// The last hour on a real clock: one slot per five minutes ending at the newest window,
// so a missed check shows as a hole instead of pulling older windows alongside newer ones.
function pulseSlots(runs: MonitoringRapidRun[]): PulseSlot[] {
  const byEnd = new Map<number, MonitoringRapidRun>();
  for (const run of runs) {
    if (run.pulse?.minutes !== 5) continue;
    const end = Date.parse(run.window_end);
    if (!byEnd.has(end)) byEnd.set(end, run);
  }
  if (!byEnd.size) return [];
  const newest = Math.max(...byEnd.keys());
  return Array.from({ length: PULSE_SLOTS }, (_, i) => {
    const end = newest - (PULSE_SLOTS - 1 - i) * PULSE_MS;
    const run = byEnd.get(end);
    if (!run) return { kind: "gap", end };
    const reason = failedRead(run);
    return reason ? { kind: "failed", end, reason } : { kind: "window", end, run };
  });
}

function pulseTone(pulse: MonitoringPulse): "allowed" | "blocked" | "offspec" | null {
  if (pulse.attack_allowed > 0) return "allowed";
  if (pulse.attack_requests > 0) return "blocked";
  if ((pulse.off_spec_requests ?? 0) > 0) return "offspec";
  return null;
}

function pulseTitle(slot: PulseSlot): string {
  const span = `${hhmm(slot.end - PULSE_MS)}–${hhmm(slot.end)} UTC`;
  if (slot.kind === "gap") return `${span} · no check stored for this window`;
  if (slot.kind === "failed") return `${span} · logs could not be read (${slot.reason}) — traffic unknown`;
  const p = slot.run.pulse;
  const parts = [`${span}`, `${p.requests.toLocaleString()} requests`];
  if (p.attack_requests > 0) {
    const stopped = p.attack_requests - p.attack_allowed;
    parts.push(`${p.attack_requests} payload matches: ${p.attack_allowed} reached the app, ${stopped} stopped`);
  } else {
    parts.push("no payload matches");
  }
  if ((p.off_spec_requests ?? 0) > 0) parts.push(`${p.off_spec_requests} off-spec`);
  parts.push(`${p.blocked.toLocaleString()} blocked in total`);
  return parts.join(" · ");
}

function PulseTrend({ runs }: { runs: MonitoringRapidRun[] }) {
  const slots = pulseSlots(runs);
  if (!slots.length) return <p className="muted-sm">Five-minute totals begin with the next rapid check.</p>;
  const max = Math.max(1, ...slots.map((slot) => slot.kind === "window" ? slot.run.pulse.requests : 0));
  const tones = new Set(slots.map((slot) => slot.kind === "window" ? pulseTone(slot.run.pulse) : slot.kind));
  return <figure className="pulse-trend" aria-label="WAF requests per five minutes over the last hour">
    <div className="pulse-plot"><div className="pulse-bars">{slots.map((slot) => {
      if (slot.kind !== "window") return <i key={slot.end} className={slot.kind} title={pulseTitle(slot)} />;
      const { requests } = slot.run.pulse;
      const tone = pulseTone(slot.run.pulse);
      return <i key={slot.end} className={[tone, requests ? null : "empty"].filter(Boolean).join(" ") || undefined}
        style={requests ? { height: `${Math.max(3, requests / max * 100)}%` } : undefined}
        title={pulseTitle(slot)} />;
    })}</div>
    <div className="pulse-axis"><span>{hhmm(slots[0].end - PULSE_MS)}</span><span>{hhmm(slots[slots.length - 1].end)} UTC</span></div></div>
    <figcaption>
      Five-minute request volume over the last hour · newest at right
      <span className="pulse-legend">
        {tones.has("allowed") && <span className="allowed">attack reached the app</span>}
        {tones.has("blocked") && <span className="blocked">attack stopped by the WAF</span>}
        {tones.has("offspec") && <span className="offspec">off-spec traffic</span>}
        {tones.has("failed") && <span className="failed">logs not read</span>}
        {tones.has("gap") && <span className="gap">no check</span>}
      </span>
    </figcaption>
  </figure>;
}

function FiveMinuteNow({ monitor, rapidRuns }: {
  monitor: InfrastructureMonitor;
  rapidRuns: MonitoringRapidRun[];
}) {
  const rapid = rapidRuns[0];
  const pulse = rapid?.pulse?.minutes === 5 ? rapid.pulse : null;
  const stale = rapidIsStale(rapid);
  return <section id="now" className="monitor-card command-now">
    <div className="command-section-head">
      <div>
        <div className="eyebrow">Live security pulse</div>
        <h2>Last five minutes</h2>
      </div>
      <span className={`live-state ${!monitor.rapid_enabled ? "off" : stale ? "stale" : "live"}`}>
        {!monitor.rapid_enabled ? "Off" : !rapid ? "Waiting for data" : stale ? "Delayed" : "Live"}
      </span>
    </div>
    {!monitor.rapid_enabled ? <p>Enable rapid monitoring in <a href="#settings">settings</a>. The rolling-hour detectors will run every five minutes and publish an exact five-minute pulse.</p>
      : !rapid ? <p>No rapid window has completed yet. Missing telemetry is shown as missing, never as clean.</p>
      : !pulse ? <p>This record predates five-minute pulse totals. The next rapid check will populate them.</p>
      : <>
        <div className="pulse-kpis">
          <Kpi label="WAF requests" value={compact(pulse.requests)} hint={`${compact(pulse.distinct_clients)} client fingerprints · ${compact(pulse.distinct_routes)} routes`} />
          <Kpi label="Payload matches" value={compact(pulse.attack_requests)} hint={pulse.attack_requests ? `${compact(pulse.attack_allowed)} allowed past WAF` : "no AWS managed payload-rule matches"} />
          <Kpi label="Off-spec requests" value={pulse.off_spec_requests === null ? "—" : compact(pulse.off_spec_requests)} hint={pulse.off_spec_requests === null ? "attach an OpenAPI contract to evaluate" : "method or route absent from the contract"} />
          <Kpi label="Blocked / challenged" value={compact(pulse.blocked + pulse.challenged)} hint={`${compact(pulse.allowed)} allowed · ${compact(pulse.counted)} count-only`} />
        </div>
        <div className="pulse-layout">
          <div>
            <h3>Recent movement</h3>
            <PulseTrend runs={rapidRuns} />
          </div>
          <div className="pulse-evidence">
            <h3>What drove this window</h3>
            {!pulse.top_attack_labels.length && !pulse.top_routes.length
              ? <p className="muted-sm">No retained evidence categories in this pulse.</p>
              : <>
                {pulse.top_attack_labels.length > 0 && <ul>{pulse.top_attack_labels.map((row) => (
                  <li key={row.label}><span>{row.label.replaceAll("-", " ").replaceAll(":", " · ")}</span><strong>{compact(row.requests)}</strong></li>
                ))}</ul>}
                {pulse.top_routes.length > 0 && <details><summary>Top normalized routes</summary><ul>{pulse.top_routes.map((row) => (
                  <li key={row.route}><code>{row.route}</code><strong>{compact(row.requests)}</strong></li>
                ))}</ul></details>}
              </>}
          </div>
        </div>
        <p className="pulse-foot">Window {new Date(rapid.window_end).toISOString().slice(11, 16)} UTC · collected {ago(rapid.created_at)}. Slow reconnaissance still uses the complete rolling hour; this pulse contains only the final five minutes.</p>
      </>}
  </section>;
}

function DailySummary({ monitor, runs, latest, groups, lbLinked }: {
  monitor: InfrastructureMonitor;
  runs: MonitoringRun[];
  latest: MonitoringRun | undefined;
  groups: ObservationGroup[];
  lbLinked: boolean;
}) {
  const hasContract = Boolean(monitor.scan_id);
  const snapshot = dailySnapshot(latest, hasContract);
  const earlier = runs.slice(1).map((run) => dailySnapshot(run, hasContract)).filter((row): row is DailySnapshot => row !== null);
  // Only days measured the same way as the latest one are comparable: a capped sample
  // beside a load balancer total would read as a real drop or rise in traffic.
  const comparable = snapshot
    ? earlier.filter((row) => row.volume.source === snapshot.volume.source && row.volume.source !== "sample").slice(0, 7)
    : [];
  const normal = median(comparable.map((row) => row.volume.requests));
  const delta = snapshot && normal && normal > 0 ? (snapshot.volume.requests - normal) / normal : null;
  const sampled = snapshot?.volume.source === "sample";
  const sampledWithTotal = Boolean(snapshot && sampleOf(latest) && snapshot.volume.source === "load_balancer");
  const volumeText = snapshot
    ? sampled ? `${compact(snapshot.events)} sampled WAF events` : `${compact(snapshot.volume.requests)} requests`
    : "";
  const open = groups.filter((group) => !group.suppressed);
  return <section id="daily">
    <div className="command-section-head">
      <div><div className="eyebrow">Daily digest</div><h2>{latest ? latest.observation_date : "Latest completed day"}</h2></div>
      {latest && <span className={`st-chip ${latest.state}`}>{latest.state.replace("_", " ")}</span>}
    </div>
    {!snapshot ? <p>No completed daily collection yet. A missing day is a coverage gap, not an all-clear.</p> : <>
      <div className="daily-summary-grid">
        <div className="daily-summary-copy">
          <strong>{open.length ? `${plural(open.length, "open issue")} ${sampled ? "in" : "from"} ${volumeText}` : `No open issues in ${volumeText}`}
            {sampledWithTotal && ` · ${compact(snapshot.events)} WAF events sampled`}</strong>
          <p>{sampled
            ? "Volume comparison needs load balancer totals: the WAF sample is capped per hour, so its size says nothing about traffic."
            : delta === null
              ? "Collect more days to compare this volume with its recent baseline."
              : `Traffic was ${Math.abs(delta * 100).toFixed(0)}% ${delta >= 0 ? "above" : "below"} the median of the previous ${comparable.length} collected days.`}</p>
          <ul className="daily-facts">
            <li><b>{compact(snapshot.blocked)}</b> blocked by WAF</li>
            <li><b>{compact(snapshot.attacks)}</b> payload-rule matches{snapshot.attacksAllowed ? ` · ${compact(snapshot.attacksAllowed)} allowed` : ""}</li>
            <li><b>{snapshot.offSpec === null ? "—" : compact(snapshot.offSpec)}</b> off-spec requests</li>
            <li><b>{lbLinked ? "Linked" : "Not linked"}</b> origin metrics</li>
          </ul>
        </div>
        <DailyBars runs={runs} />
      </div>
      <div className="evidence-coverage" aria-label="Evidence coverage">
        <span className="ready">WAF request evidence</span>
        <span className={hasContract ? "ready" : "missing"}>OpenAPI contract</span>
        <span className={lbLinked ? "ready" : "missing"}>ALB origin metrics</span>
        <span className={latest?.data_quality === "sufficient" ? "ready" : "warming"}>Daily baseline {latest?.baseline_days_available ?? 0}/{monitor.minimum_baseline_days}</span>
      </div>
    </>}
  </section>;
}

type ContextTab = "lb" | "routes" | "clients" | "bots";
const CONTEXT_TABS: { key: ContextTab; label: string; show: string }[] = [
  { key: "lb", label: "App responses", show: "Show app responses by hour" },
  { key: "routes", label: "Routes", show: "Show route trends" },
  { key: "clients", label: "TLS clients", show: "Show TLS clients" },
  { key: "bots", label: "Bots and AI", show: "Show bot traffic" },
];
// Where the evidence behind a lead type is drawn, so a lead can open the chart that
// shows it. Only types whose chart actually carries their signal are listed.
function contextFor(type: string): ContextTab | null {
  if (type.startsWith("lb_")) return "lb";
  if (type.startsWith("ja4_") || type === "slow_recon_ja4") return "clients";
  if (["unverified_ai_surge", "bot_identity_spoof", "bot_on_protected_route"].includes(type)) return "bots";
  if (["shadow_route", "response_size_drift"].includes(type)) return "routes";
  return null;
}

type Tone = "clear" | "warn" | "alert" | "info" | "idle";
function Tile({ label, value, hint, tone, href }: {
  label: string; value: ReactNode; hint?: ReactNode; tone: Tone; href?: string;
}) {
  const body = <><span className="oncall-label">{label}</span><strong>{value}</strong>{hint && <small>{hint}</small>}</>;
  return href
    ? <a className={`oncall-tile ${tone}`} href={href}>{body}</a>
    : <div className={`oncall-tile ${tone}`}>{body}</div>;
}

/** The four questions an on-call engineer asks first, answered before any evidence. */
function OncallStrip({ monitor, latest, collecting, openGroups, openAlerts, rapid }: {
  monitor: InfrastructureMonitor;
  latest: MonitoringRun | undefined;
  collecting: boolean;
  openGroups: ObservationGroup[];
  openAlerts: Alert[];
  rapid: MonitoringRapidRun | undefined;
}) {
  const alertGroups = groupAlerts(openAlerts);
  const alertTile = <Tile label="Open alerts" href="#episodes"
    tone={openAlerts.length ? (alertGroups.some((g) => g.state === "degraded") && alertGroups.length === 1 ? "warn" : "alert") : "clear"}
    value={openAlerts.length ? alertGroups.length : "None"}
    hint={openAlerts.length ? alertGroups.map((g) => ALERT_STATES[g.state] ?? g.state).join(" · ") : "nothing to acknowledge"} />;

  const rapidLeads = (rapid?.observations ?? []) as Observation[];
  const pulse = rapid?.pulse?.minutes === 5 ? rapid.pulse : null;
  const rapidTile = !monitor.rapid_enabled
    ? <Tile label="Last 5 minutes" tone="info" value="Off" hint="live pulse disabled in settings" href="#settings" />
    : !rapid
      ? <Tile label="Last 5 minutes" tone="warn" value="No data" hint="the live check has not reported yet" />
      : <Tile label="Last 5 minutes" href="#now"
          tone={rapidIsStale(rapid) ? "warn" : "info"}
          value={pulse ? compact(pulse.requests) : rapidLeads.length ? plural(rapidLeads.length, "lead") : "Clear"}
          hint={rapidIsStale(rapid)
            ? <>check stalled · last ran {ago(rapid.created_at)}</>
            : pulse
              ? <>{compact(pulse.attack_requests)} payload matches · {compact(pulse.blocked + pulse.challenged)} stopped</>
              : <>window ended {ago(rapid.window_end)}</>} />;

  const behind = latest ? daysBehind(latest.observation_date) : 0;
  const dayTile = !latest
    ? <Tile label="Latest day" tone="warn" value="Never collected" hint="no evidence is not a clean result" />
    : collecting
      ? <Tile label="Latest day" tone="idle" value="Collecting…" hint={latest.observation_date} />
      : latest.status !== "complete"
        ? <Tile label="Latest day" tone="alert" value="Collection failed" href="#latest-day"
            hint={`${latest.observation_date}${latest.error_code ? ` · ${latest.error_code}` : ""}`} />
        : <Tile label="Latest day" href="#latest-day"
            tone={openGroups.length ? toneOf(openGroups[0].severity) : behind > 1 || latest.data_quality !== "sufficient" ? "warn" : "clear"}
            value={openGroups.length ? plural(openGroups.length, "issue") : "Clear"}
            hint={<>{latest.observation_date}
              {behind > 1 ? ` · ${behind} days behind` : ""}
              {latest.data_quality !== "sufficient" ? ` · baseline ${latest.baseline_days_available}/${monitor.minimum_baseline_days}` : ""}</>} />;

  const lb = lbOf(latest);
  const lbDay = lbWindow(lb, null);
  const lbLead = openGroups.some((g) => g.type.startsWith("lb_"));
  const appTile = !lb
    ? <Tile label="App errors" tone="idle" value="Not linked" hint="add a load balancer in settings" href="#settings" />
    : lb.error || !lbDay
      ? <Tile label="App errors" tone="warn" value="Unavailable" hint={lb.error ? LB_ERRORS[lb.error] ?? lb.error : "no hourly metrics"} />
      : <Tile label="App errors" href="#context"
          tone={lbLead || share(lbDay.server, lbDay.answered)! >= 0.01 ? "alert" : "clear"}
          value={`5XX ${pct(share(lbDay.server, lbDay.answered))}`}
          hint={<>4XX {pct(share(lbDay.client, lbDay.answered))}{lbDay.p99 !== null ? ` · p99 ${Math.round(lbDay.p99 * 1000)} ms` : ""}</>} />;

  return <div className="oncall-strip">{alertTile}{rapidTile}{dayTile}{appTile}</div>;
}

function AlertRows({ alerts, runs, onAcknowledge, onOpenDay }: {
  alerts: Alert[]; runs: MonitoringRun[];
  onAcknowledge: (groups: AlertGroup[]) => void;
  onOpenDay: (day: string) => void;
}) {
  const groups = groupAlerts(alerts);
  if (!groups.length) return null;
  return <div className="monitor-card oncall-alerts">
    {groups.length > 1 && <div className="oncall-alerts-head">
      <span className="muted-sm">{plural(groups.length, "open episode")}</span>
      <button className="btn quiet sm" onClick={() => onAcknowledge(groups)}>Acknowledge all</button>
    </div>}
    {groups.map((group) => {
      const run = runs.find((r) => r.observation_date === group.day);
      // A daily alert is about its own day, which is not necessarily the latest one.
      const openDay = group.state === "anomaly" && run?.status === "complete";
      return <div className="oncall-alert" key={group.key}>
        <span className={`st-chip ${group.state === "degraded" || group.state === "no_data" ? "degraded" : group.state.includes("anomaly") ? "anomaly" : "baseline_ready"}`}>
          {ALERT_STATES[group.state] ?? group.state}
        </span>
        <div>
          <strong>{group.day}</strong>{group.alerts.length > 1 && <span className="muted-sm"> · raised {group.alerts.length}&times;</span>}
          {group.state === "degraded" && run?.error_code && <p className="muted-sm">{run.error_code}: {COLLECTION_ERRORS[run.error_code] ?? ""}</p>}
          {group.state === "degraded" && run?.status === "complete" && <p className="muted-sm">The day has collected since.</p>}
        </div>
        <div className="monitor-actions">
          {group.state === "rapid_anomaly" && <a className="btn quiet sm" href="#rolling-hour">See leads</a>}
          {openDay && <button className="btn quiet sm" onClick={() => onOpenDay(group.day)}>See leads</button>}
          <button className="btn quiet sm" onClick={() => onAcknowledge([group])}>Acknowledge</button>
        </div>
      </div>;
    })}
  </div>;
}

// Detector counters arrive as snake_case numbers; the ones worth a glance are kept as
// labelled pairs instead of one run-on sentence.
function RapidLead({ observation }: { observation: Observation }) {
  const severity = severityOf(observation);
  const route = typeof observation.route_family === "string" && observation.route_family !== "*" ? observation.route_family : null;
  const method = typeof observation.method === "string" && observation.method !== "*" ? observation.method : null;
  const numbers = Object.entries((observation.current ?? {}) as Record<string, unknown>)
    .filter((entry): entry is [string, number] => typeof entry[1] === "number");
  return <article className={`monitor-card observation sev-${severity}`}>
    <div className="observation-head">
      <h3>{OBSERVATIONS[String(observation.type)] ?? String(observation.type)}</h3>
      <span className="observation-chips">
        <span className={`sev-chip ${severity}`}>{severity}</span>
        <span className="st-chip">{String(observation.confidence ?? "heuristic")}</span>
      </span>
    </div>
    <p>{route ? <code>{method ? `${method} ` : ""}{route}</code> : "All routes"}
      {observation.cohort !== undefined && <> · {cohortLabel(observation.cohort)}</>}</p>
    {numbers.length > 0 && <dl className="lead-numbers">{numbers.map(([key, value]) => (
      <div key={key}><dt>{key.replaceAll("_", " ")}</dt><dd>{Number.isInteger(value) ? compact(value) : value.toFixed(2)}</dd></div>
    ))}</dl>}
    <AttackPaths evidence={observation.current} />
    {typeof observation.remediation === "string" && <p>{observation.remediation}</p>}
  </article>;
}

function ObservationCard({ group, runs, latest, onExplain, onSuppress, onShowContext }: {
  group: ObservationGroup;
  runs: MonitoringRun[];
  latest: MonitoringRun;
  onExplain: (fingerprint: string) => void;
  onSuppress: () => void;
  // Absent for a past day: the trend charts describe the latest day only.
  onShowContext?: (tab: ContextTab) => void;
}) {
  const lead = group.members[0];
  const explanation = lead.ai_explanation as Explanation | undefined;
  const context = contextFor(group.type);
  const seen = recurrence(group, runs, latest.observation_date);
  // A dominating client is measured inside the sample too, so the card says how much of
  // the hour could be seen; the full count is not knowable from a capped read.
  const sample = sampleOf(latest);
  const current = (lead.current ?? {}) as { requests?: number; hour?: number };
  const sampleNote = group.type === "high_volume_client" && sample
    && typeof current.requests === "number" && typeof current.hour === "number"
    ? `Counted in the sample: ${current.requests} of the newest ${sample.per_hour} events kept for hour ${String(current.hour).padStart(2, "0")} UTC. The client's full count for that hour is not known.`
    : null;
  return <article className={`monitor-card observation sev-${group.severity}`}>
    <div className="observation-head">
      <h3>{OBSERVATIONS[group.type] ?? group.type}</h3>
      <span className="observation-chips">
        {seen.looked > 0 && !seen.earlier.length && <span className="st-chip new" title={`Not on any of the ${seen.looked} earlier collected days`}>new</span>}
        <span className={`sev-chip ${group.severity}`}>{group.severity}</span>
        <span className="st-chip">{evidenceLabel(group)}</span>
      </span>
    </div>
    {seen.earlier.length > 0 && <p className="muted-sm observation-seen">
      Also on {plural(seen.earlier.length, "earlier day")} of {seen.looked} collected
      {" "}· most recently {seen.earlier[0]}{seen.earlier.length > 1 ? `, first ${seen.earlier[seen.earlier.length - 1]}` : ""}
    </p>}
    <p className="observation-where">{group.method === "*" ? "All routes" : <code>{group.method} {group.route}</code>}
      {" · "}{group.cohorts.length > 1 ? `${group.cohorts.length} clients` : cohortLabel(group.cohorts[0])}
      {group.hours.length > 0 && <> · {group.hours.length === 1 ? "hour" : "hours"} {hourList(group.hours)} UTC</>}
      {group.members.length > 1 && <> · reported {group.members.length}&times;</>}
    </p>
    {group.hours.length > 0 && lbOf(latest)?.hours && (
      <LbLine runs={runs} latest={latest} hours={group.hours}
        scope={`Load balancer in ${group.hours.length === 1 ? "hour" : "hours"} ${hourList(group.hours)} UTC, all traffic`} />
    )}
    <AttackPaths evidence={lead.current} />
    {sampleNote && <p className="muted-sm">{sampleNote}</p>}
    <p className="observation-fix"><b>What to check:</b> {String(lead.remediation)}</p>
    {explanation && <ExplanationView explanation={explanation} />}
    <div className="monitor-actions">
      {context && onShowContext && <button className="btn quiet sm" onClick={() => onShowContext(context)}>
        {CONTEXT_TABS.find((t) => t.key === context)?.show}
      </button>}
      <button className="btn quiet sm" disabled={explanation?.status === "pending" && !isStale(explanation)} onClick={() => onExplain(String(lead.fingerprint))}>
        {explanation?.status === "complete" ? "Explain again" : "Explain with AI"}
      </button>
      <button className="btn quiet sm" onClick={onSuppress}>
        {group.members.length > 1 ? `Suppress all ${group.members.length}` : "Suppress"}
      </button>
    </div>
  </article>;
}

export default function MonitoringDetail({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);
  const [monitor, setMonitor] = useState<InfrastructureMonitor | null>(null);
  usePageTitle(monitor?.name ? `Monitor · ${monitor.name}` : null);
  const [runs, setRuns] = useState<MonitoringRun[]>([]);
  const [rapidRuns, setRapidRuns] = useState<MonitoringRapidRun[]>([]);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [bots, setBots] = useState<MonitoringBots | null>(null);
  const [routeTrends, setRouteTrends] = useState<MonitoringRoutes | null>(null);
  const [tlsClients, setTlsClients] = useState<MonitoringClients | null>(null);
  const [briefing, setBriefing] = useState<MonitoringBriefing | null>(null);
  const [days, setDays] = useState(28);
  const [tab, setTab] = useState<ContextTab | null>(null);
  const [selectedDay, setSelectedDay] = useState<string | null>(null);
  const [error, setError] = useState("");
  const router = useRouter();
  const load = useCallback(async () => {
    try {
      const [all, history, recent, currentAlerts, traffic, trends, fingerprints, brief] = await Promise.all([
        api.listMonitors(), api.listMonitoringRuns(id), api.listMonitoringRapidRuns(id),
        api.monitoringAlerts(id), api.monitoringBots(id, days), api.monitoringRoutes(id, days), api.monitoringClients(id),
        api.monitoringBriefing(id),
      ]);
      setBriefing(brief);
      setMonitor(all.find((m) => m.id === id) || null); setRuns(history); setRapidRuns(recent);
      setAlerts(currentAlerts); setBots(traffic);
      setRouteTrends(trends); setTlsClients(fingerprints); setError("");
    } catch (e) { setError((e as Error).message); }
  }, [id, days]);
  useEffect(() => { void load(); }, [load]);
  useEffect(() => {
    const timer = setInterval(() => void load(), 60_000);
    return () => clearInterval(timer);
  }, [load]);

  const latest = runs[0];
  const isCollecting = (run: MonitoringRun | undefined) => run?.status === "collecting" || run?.status === "queued";
  const latestCollecting = isCollecting(latest);
  // A backfilled or retried day is collected like any other and can sit behind the latest.
  const collectingRun = runs.find(isCollecting);
  const collecting = Boolean(collectingRun);
  // The day under "Daily evidence and decisions": the latest unless one was picked.
  const viewed = (selectedDay && runs.find((run) => run.observation_date === selectedDay)) || latest;
  const pastDay = Boolean(viewed && latest && viewed.id !== latest.id);
  const observations = (latest?.observations ?? []) as Record<string, unknown>[];
  const viewedObservations = (viewed?.observations ?? []) as Record<string, unknown>[];
  const groups = groupObservations(observations);
  const viewedGroups = pastDay ? groupObservations(viewedObservations) : groups;
  const latestLb = lbOf(latest);
  const openGroups = groups.filter((g) => !g.suppressed);
  const viewedOpen = viewedGroups.filter((g) => !g.suppressed);
  const answeredGroups = viewedGroups.filter((g) => g.suppressed);
  const progress = collectingRun?.metrics?.progress as { pages: number; events: number; seconds: number } | undefined;
  const sample = sampleOf(runs.find((run) => run.status === "complete"));
  const pending = collecting || (briefing?.status === "pending" && !isStale(briefing)) || [...observations, ...viewedObservations].some((o) => {
    const explanation = o.ai_explanation as Explanation | undefined;
    return explanation?.status === "pending" && !isStale(explanation);
  });
  useEffect(() => {
    if (!pending) return;
    const timer = setInterval(() => void load(), 2000);
    return () => clearInterval(timer);
  }, [pending, load]);

  async function act(work: () => Promise<unknown>) {
    try { await work(); await load(); } catch (e) { setError((e as Error).message); }
  }
  const collectDay = (day?: string) => act(() => api.collectMonitoringDay(id, day));
  // Sequential on purpose: the triage endpoint merges into `monitor.triage` and
  // recomputes, so concurrent calls would each read the old map and drop the others.
  const triageGroup = (group: ObservationGroup, disposition: "suppressed" | "candidate") =>
    act(async () => {
      for (const member of group.members) {
        await api.triageMonitoring(monitor!.id, String(member.fingerprint), disposition);
      }
    });

  const rapid = rapidRuns[0];
  const rapidLeads = (rapid?.observations ?? []) as Observation[];
  const openAlerts = alerts.filter((alert) => !alert.acknowledged);
  const acknowledged = alerts.length - openAlerts.length;
  const lbLinked = runs.some((run) => run.metrics?.origin);
  const activeTab: ContextTab = tab ?? (lbLinked ? "lb" : "routes");
  const showContext = (next: ContextTab) => {
    setTab(next);
    document.getElementById("context")?.scrollIntoView({ behavior: "smooth", block: "start" });
  };
  const openDay = (day: string | null) => {
    setSelectedDay(day);
    document.getElementById("latest-day")?.scrollIntoView({ behavior: "smooth", block: "start" });
  };
  const nothingOpen = !openAlerts.length && !rapidLeads.length && !openGroups.length;
  const history = historyDays(runs, monitor?.retention_days ?? 0);

  if (!monitor) return <section className="wrap monitoring-page"><Link href="/monitoring">← Monitoring</Link><p>{error || "Loading…"}</p></section>;
  return <section className="wrap monitoring-page">
    <Link href="/monitoring">← Monitoring</Link>
    <header className="oncall-head">
      <div>
        <div className="eyebrow">Passive traffic evidence</div>
        <h1>{monitor.name}</h1>
        <p className="lead">{monitor.target_binding}{monitor.scan_id && <> · <Link href={`/scans/${monitor.scan_id}`}>API contract</Link></>}
          {monitor.status === "paused" && <> · <span className="st-chip degraded">paused</span></>}</p>
      </div>
      <div className="monitor-actions">
        {collecting
          ? <button className="btn quiet" onClick={() => void act(() => api.cancelMonitoring(monitor.id))}>Cancel collection</button>
          : <button className="btn quiet" disabled={monitor.status !== "active"} title={monitor.status !== "active" ? "Resume the monitor in settings to collect" : undefined}
              onClick={() => void collectDay()}>Collect previous day</button>}
      </div>
    </header>
    {error && <p className="monitor-error" role="alert">{error}</p>}

    <OncallStrip monitor={monitor} latest={latest} collecting={latestCollecting} openGroups={openGroups} openAlerts={openAlerts} rapid={rapid} />
    {collectingRun && <p className="monitor-progress" role="status">
      {collectingRun.status === "queued"
        ? `Waiting for a worker to collect ${collectingRun.observation_date}…`
        : `Reading ${collectingRun.observation_date} from CloudWatch: ${progress ? `${progress.pages} page${progress.pages === 1 ? "" : "s"}, ${compact(progress.events)} events so far (${progress.seconds}s)` : "starting…"}`}
    </p>}
    {latest?.error_code && !latestCollecting && <p className="monitor-error" role="status">
      Collection failed for {latest.observation_date} ({latest.error_code}). {COLLECTION_ERRORS[latest.error_code] ?? ""}
      {" "}{monitor.status === "active" && <button className="btn quiet sm" onClick={() => void collectDay(latest.observation_date)}>Retry {latest.observation_date}</button>}
    </p>}

    <nav className="oncall-nav" aria-label="Sections">
      <a href="#now">Now</a><a href="#episodes">Attack episodes</a><a href="#daily">Daily digest</a><a href="#context">Trends</a><a href="#briefing">AI analysis</a><a href="#history">History</a><a href="#settings">Settings</a>
    </nav>

    <FiveMinuteNow monitor={monitor} rapidRuns={rapidRuns} />

    <h2 id="episodes">Attack episodes</h2>
    {nothingOpen && <p className="oncall-quiet">No open alerts, no rolling-hour leads, and nothing open on the latest day.</p>}
    <AlertRows alerts={openAlerts} runs={runs} onOpenDay={(day) => openDay(day === latest?.observation_date ? null : day)}
      onAcknowledge={(picked) => void act(() => Promise.all(picked.flatMap((group) => group.alerts).map((alert) => api.acknowledgeMonitoringAlert(monitor.id, alert.id))))} />
    {acknowledged > 0 && <p className="muted-sm">{plural(acknowledged, "acknowledged alert")}. A failed collection closes on its own once that day collects.</p>}

    <div className="oncall-subhead" id="rolling-hour">
      <h3>Rolling-hour detections</h3>
      {rapid && <span className="muted-sm">
        window {new Date(rapid.window_start).toISOString().slice(11, 16)}–{new Date(rapid.window_end).toISOString().slice(11, 16)} UTC
        {" "}· {compact(rapid.waf_count)} WAF requests · {compact(rapid.application_count)} app outcomes · checked {ago(rapid.created_at)}
      </span>}
    </div>
    {!monitor.rapid_enabled
      ? <p className="muted-sm">The short-window check is off. Enable it in <a href="#settings">settings</a> to see leads within minutes instead of the next day.</p>
      : !rapid ? <p className="muted-sm">No short-window evidence yet. The check runs every 5 minutes once enabled, or windows can be posted from a log pipeline.</p>
      : <>
        {rapidIsStale(rapid) && <p className="monitor-error" role="status">The short-window check last ran {ago(rapid.created_at)}. A stalled check shows no leads; check the beat and worker.</p>}
        {Object.entries(rapid.skipped).map(([key, reason]) => (
          <p className="muted-sm" key={key}>{RAPID_SKIPPED[key] ?? key}: {reason}.</p>
        ))}
        {rapidLeads.length
          ? rapidLeads.map((observation, index) => <RapidLead key={`${String(observation.fingerprint)}-${index}`} observation={observation} />)
          : <p className="muted-sm">No rolling-hour leads in the latest complete window.</p>}
        {!groups.length && <p className="muted-sm">Without an uploaded OpenAPI contract, reconnaissance is judged against routes seen in past days, so a crawl that only touches familiar routes is not flagged.</p>}
      </>}

    <DailySummary monitor={monitor} runs={runs} latest={latest} groups={groups} lbLinked={lbLinked} />

    <div className="oncall-subhead" id="latest-day">
      <h3>Daily evidence and decisions</h3>
      {viewed?.finished_at && <span className="muted-sm">{viewed.observation_date} · collected {ago(viewed.finished_at)}</span>}
    </div>
    {pastDay && viewed && <p className="day-view-note" role="status">
      Showing {viewed.observation_date}, not the latest day ({latest!.observation_date}). Suppressing a lead here suppresses it on every day.
      {" "}<button className="btn quiet sm" onClick={() => openDay(null)}>Back to latest</button>
    </p>}
    {!viewed ? <p>No collection run yet. A missing source is a coverage limitation, not a clean result.</p>
      : <>
      {viewed.status === "complete" && <Verdict run={viewed} runs={runs} groups={viewedGroups}
        routes={pastDay ? null : routeTrends} clients={pastDay ? null : tlsClients} minimumDays={monitor.minimum_baseline_days} />}
      {viewed.status === "complete" && viewed.data_quality !== "sufficient" && <p className="muted-sm">{stateSummary(viewed, monitor.minimum_baseline_days)}</p>}
      {!viewedObservations.length ? (isCollecting(viewed) ? <p className="muted-sm">Leads appear when the day finishes collecting.</p> : null)
      : <>
        {viewedOpen.map((group) => <ObservationCard key={group.key} group={group} runs={runs} latest={viewed}
          onExplain={(fingerprint) => void act(() => api.explainObservation(monitor.id, viewed.id, fingerprint))}
          onSuppress={() => void triageGroup(group, "suppressed")}
          onShowContext={pastDay ? undefined : showContext} />)}
        {!viewedOpen.length && <p className="muted-sm">Every lead on {viewed.observation_date} has been answered.</p>}
        {answeredGroups.length > 0 && <details className="observations-answered">
          <summary>{answeredGroups.length} answered {answeredGroups.length === 1 ? "issue" : "issues"} (suppressed)</summary>
          {answeredGroups.map((group) => (
            <div className="answered-row" key={group.key}>
              <span className={`sev-chip ${group.severity}`}>{group.severity}</span>
              <span>{OBSERVATIONS[group.type] ?? group.type}</span>
              {group.method !== "*" && <code>{group.method} {group.route}</code>}
              <button className="btn quiet sm" onClick={() => void triageGroup(group, "candidate")}>Restore</button>
            </div>
          ))}
        </details>}
      </>}
      </>}

    <div className="bot-head" id="context">
      <div><div className="eyebrow">Evidence explorer</div><h2>Trends and attribution</h2></div>
      <div className="bot-range" role="group" aria-label="Window">{[7, 14, 28].map((n) => (
        <button key={n} className={`btn quiet sm${n === days ? " active" : ""}`} aria-pressed={n === days} onClick={() => setDays(n)}>{n} days</button>
      ))}</div>
    </div>
    <div className="oncall-tabs" role="tablist" aria-label="Traffic view">{CONTEXT_TABS.map((t) => (
      <button key={t.key} role="tab" aria-selected={t.key === activeTab} className={t.key === activeTab ? "active" : undefined} onClick={() => setTab(t.key)}>{t.label}</button>
    ))}</div>
    {sample && <p className="muted-sm">Sampled: the newest {sample.per_hour} events of each UTC hour, up to {compact(sample.limit)} a day. Shares and rankings compare day to day; counts are sample counts.</p>}

    {activeTab === "lb" && (!lbLinked
      ? <p className="muted-sm">No load balancer linked. Add an Application Load Balancer ARN in <a href="#settings">settings</a> to see what the app answered, hour by hour.</p>
      : latestLb?.error
        ? <p className="muted-sm">Metrics for {latest?.observation_date} are unavailable: {LB_ERRORS[latestLb.error] ?? latestLb.error}.</p>
        : latest && <LoadBalancerChart runs={runs} latest={latest}
            flaggedHours={new Set(openGroups.filter((g) => g.type.startsWith("lb_")).flatMap((g) => g.hours))} />)}

    {activeTab === "routes" && (!routeTrends || !routeTrends.routes.length
      ? <p>No completed days in this window yet.</p>
      : <RouteTrends data={routeTrends} />)}

    {activeTab === "clients" && (!tlsClients?.day ? <p>No completed days yet.</p>
      : !tlsClients.clients.length ? <p>No JA4 fingerprints in the {tlsClients.day} logs. AWS WAF logs them for HTTPS requests; re-collect a day collected before JA4 support.</p>
      : <ClientFingerprints data={tlsClients} />)}

    {activeTab === "bots" && (!bots || !bots.days ? <p>No completed days in this window yet.</p> : !bots.bot_requests ? (
      <p>No Bot Control labels in {bots.days} day{bots.days === 1 ? "" : "s"} of logs. Enable AWS WAF Bot Control on the web ACL to see bot and AI traffic here.</p>
    ) : <>
      <div className="bot-kpis">
        <Kpi label="All bot requests" value={compact(bots.bot_requests)} hint={`of ${compact(bots.requests)} ${sample ? "sampled " : ""}requests`} />
        <Kpi label="AI bot requests" value={compact(bots.ai_requests)} />
        <Kpi label="Verified AI bot traffic" value={percent(bots.verified_ai_pct)} />
        <Kpi label="Unverified AI bot traffic" value={percent(bots.unverified_ai_pct)} />
      </div>
      <p className="muted-sm">Bot names come from AWS Bot Control labels. A request an earlier WAF rule blocked (for example an LFI or bad-input rule) never reaches Bot Control, so it carries no bot name: a crawler&apos;s blocked count here can read 0 while its TLS fingerprint was blocked. Check the TLS clients view for that fingerprint&apos;s blocks.</p>
      <div className="bot-grid">
        <div className="monitor-card">
          <h3>Top crawlers</h3>
          <div className="bot-table-wrap"><table className="bot-table">
            <thead><tr><th>Bot name</th><th>Organization</th><th className="num">Requests</th><th>Category</th><th>Verified</th><th className="num">Blocked</th></tr></thead>
            <tbody>{bots.crawlers.slice(0, 15).map((row) => (
              <tr key={`${row.name}|${row.organization}|${row.category}|${row.verification}`}>
                <td>{row.name || <span className="muted-sm">unnamed</span>}</td>
                <td>{row.organization || "—"}</td>
                <td className="num">{compact(row.requests)}</td>
                <td><span className="bot-chip" style={{ "--chip": categoryColor(row.category) } as CSSProperties}>{categoryLabel(row.category)}</span></td>
                <td>{row.verification === "verified" ? <span className="bot-verified">✓ Verified</span> : <span className="bot-unverified">⚠ Unverified</span>}</td>
                <td className="num">{compact(row.blocked + row.challenged)}</td>
              </tr>
            ))}</tbody>
          </table></div>
          {bots.crawler_count > 15 && <p className="muted-sm">{bots.crawler_count - 15} more bots in this window.</p>}
        </div>
        <div className="monitor-card"><CategoryBars series={bots.series} /></div>
      </div>
    </>)}

    <div id="briefing">
      <TrafficBriefing briefing={briefing} days={days} onRequest={() => void act(() => api.briefMonitoring(monitor.id, days))} />
    </div>

    <h2 id="history">Collection history</h2>
    {(() => {
      const missing = history.filter((row) => !row.run).length;
      const canCollect = monitor.status === "active" && !collecting;
      return <>
        <p className="muted-sm">
          {missing
            ? `${plural(missing, "day")} of the last ${Math.min(HISTORY_DAYS, monitor.retention_days)} ${missing === 1 ? "has" : "have"} no evidence. A missing day is not a quiet day, and the baseline only counts an unbroken run of complete days, so collecting a hole also restores the baseline of the days after it.`
            : `Every one of the last ${Math.min(HISTORY_DAYS, monitor.retention_days)} days has a collection run.`}
          {!canCollect && missing > 0 && (monitor.status !== "active" ? " Resume the monitor to collect." : " One collection runs at a time.")}
        </p>
        <div className="bot-table-wrap"><table className="bot-table history-table">
          <thead><tr><th>Day</th><th>State</th><th className="num">Requests</th><th className="num">Baseline days</th><th className="num">Open leads</th><th>Collected</th><th>Error</th><th /></tr></thead>
          <tbody>{history.map(({ day, run }) => {
            const volume = run?.status === "complete" ? dayVolume(run) : null;
            const open = run ? run.observations.filter((o) => !isSuppressed(o)).length : 0;
            const shown = viewed?.observation_date === day;
            return <tr key={day} className={[!run || run.status === "failed" ? "flagged" : null, shown ? "viewing" : null].filter(Boolean).join(" ") || undefined}>
              <td>{day}</td>
              <td>{!run ? <span className="st-chip degraded">not collected</span>
                : run.status === "complete"
                  ? <span className={`st-chip ${run.state}`}>{run.state.replace("_", " ")}</span>
                  : <span className={`st-chip ${run.status === "failed" || run.status === "cancelled" ? "degraded" : "running"}`}>{run.status}</span>}</td>
              <td className="num" title={volume?.source === "sample" ? "WAF events kept by the sample, not the day's requests" : undefined}>
                {!volume ? "—" : `${compact(volume.requests)}${volume.source === "sample" ? " sampled" : ""}`}</td>
              <td className="num">{run ? run.baseline_days_available : "—"}</td>
              <td className="num">{open || "—"}</td>
              <td>{run ? ago(run.finished_at ?? run.started_at) ?? "—" : "—"}</td>
              <td>{run?.error_code ? <span title={COLLECTION_ERRORS[run.error_code]}>{run.error_code}</span> : "—"}</td>
              <td className="history-action">{run?.status === "complete"
                ? shown ? <span className="muted-sm">shown above</span>
                  : <button className="btn quiet sm" onClick={() => openDay(run.id === latest?.id ? null : day)}>View day</button>
                : isCollecting(run) ? null
                : <button className="btn quiet sm" disabled={!canCollect} onClick={() => void collectDay(day)}>{run ? "Retry" : "Collect"}</button>}</td>
            </tr>;
          })}</tbody>
        </table></div>
      </>;
    })()}

    <h2 id="settings">Settings</h2>
    <MonitorLifecycle monitor={monitor} onChanged={() => void load()} onDeleted={() => router.push("/monitoring")} />
    <SetupEditor monitorId={monitor.id} onSaved={() => void load()} />
  </section>;
}
