// Monitoring: evidence sources, baseline runs, bots, routes, clients,
// briefings and alerts.
import { request } from "./transport";

export interface EvidenceSource {
  id: string;
  name: string;
  target_binding: string;
  connector: "json_snapshot" | "aws_cloudwatch" | "aws_alb" | "github";
  config: Record<string, unknown>;
  has_credentials: boolean;
  error_code: string | null;
  watermark: string | null;
  revision: number;
  status: "ready" | "untested" | "unavailable" | "revoked";
  created_at: string;
}

export interface EvidenceSourceInput {
  name: string;
  target_binding: string;
  connector?: "json_snapshot" | "aws_cloudwatch" | "aws_alb" | "github";
  config?: {
    routes?: { method: "GET" | "HEAD" | "POST" | "PUT" | "PATCH" | "DELETE" | "OPTIONS"; path: string }[];
    region?: string | null; log_group?: string | null; account_id?: string | null;
    load_balancer?: string | null;
    repository?: string | null; commit?: string | null; ref?: string | null; paths?: string[];
  };
  credentials?: {
    access_key_id?: string | null; secret_access_key?: string | null;
    session_token?: string | null; github_token?: string | null;
  } | null;
}

export interface InfrastructureMonitor {
  id: string;
  tenant_id: string;
  name: string;
  target_binding: string;
  source_ids: string[];
  schedule_minutes: number;
  minimum_baseline_days: number;
  schedule_enabled: boolean;
  rapid_enabled: boolean;
  retention_days: number;
  scan_id: string | null;
  status: "active" | "paused";
  last_observation_date: string | null;
  last_run_at: string | null;
  created_at: string;
}

export interface MonitoringInput {
  name: string;
  target_binding: string;
  source_ids?: string[];
  schedule_minutes?: number;
  minimum_baseline_days?: number;
  schedule_enabled?: boolean;
  retention_days?: number;
}

export interface MonitoringRun {
  id: string;
  monitor_id: string;
  observation_date: string;
  status: "queued" | "collecting" | "awaiting_evidence" | "complete" | "failed" | "cancelled";
  state: "no_data" | "warming_up" | "baseline_ready" | "degraded" | "anomaly";
  error_code: string | null;
  scope_revision: string;
  correlations: Record<string, unknown>[];
  baseline_start: string | null;
  baseline_end: string | null;
  baseline_days_available: number;
  data_quality: "unknown" | "missing" | "warming_up" | "sufficient";
  source_revisions: Record<string, string>;
  metrics: Record<string, unknown>;
  observations: Record<string, unknown>[];
  started_at: string | null;
  finished_at: string | null;
  created_at: string;
}

export interface MonitoringRapidRun {
  id: string;
  monitor_id: string;
  window_start: string;
  window_end: string;
  observations: Record<string, unknown>[];
  skipped: Record<string, string>;
  pulse: MonitoringPulse;
  waf_count: number;
  application_count: number;
  created_at: string;
}

/** Value-free totals for the final five minutes of a rolling rapid run. */
export interface MonitoringPulse {
  minutes: number;
  requests: number;
  allowed: number;
  blocked: number;
  challenged: number;
  counted: number;
  other_actions: number;
  attack_requests: number;
  attack_allowed: number;
  off_spec_requests: number | null;
  distinct_routes: number;
  distinct_clients: number;
  bot_requests: number;
  unverified_bot_requests: number;
  application_events: number;
  top_attack_labels: { label: string; requests: number }[];
  top_routes: { route: string; requests: number }[];
}

/** One bot as AWS WAF Bot Control labelled it; empty strings when unlabelled. */
export interface BotCrawler {
  name: string;
  organization: string;
  category: string;
  verification: string;
  requests: number;
  allowed: number;
  blocked: number;
  challenged: number;
}

export interface BotSeriesDay {
  day: string;
  by_category: Record<string, number>;
}

export interface AgentLogLine {
  at: string;
  text: string;
}

/** The latest AI traffic briefing on a monitor: commentary on the evidence, never evidence. */
export interface MonitoringBriefing {
  status: "none" | "pending" | "complete" | "unavailable";
  requested_at: string | null;
  finished_at: string | null;
  days: number | null;
  evidence_through: string | null;
  evidence_trimmed: string[];
  reason: string | null;
  provider: string | null;
  model: string | null;
  text: string | null;
  structured: Record<string, unknown> | null;
  tokens_in: number | null;
  tokens_out: number | null;
  log: AgentLogLine[];
}

export interface MonitoringBots {
  days: number;
  requests: number;
  bot_requests: number;
  ai_requests: number;
  verified_ai: number;
  unverified_ai: number;
  verified_ai_pct: number | null;
  unverified_ai_pct: number | null;
  by_category: Record<string, number>;
  crawlers: BotCrawler[];
  crawler_count: number;
  series: BotSeriesDay[];
}

export interface RouteDay {
  day: string;
  requests: number;
  /** Share of that day's collected events, so sampled and full days compare. */
  share: number;
  blocked: number;
  not_found: number;
}

export interface RouteTrend {
  route: string;
  total_requests: number;
  latest_day: string;
  latest_requests: number;
  latest_share: number;
  baseline_share: number | null;
  change: number | null;
  score: number | null;
  state: "warming_up" | "normal" | "anomaly";
  series: RouteDay[];
}

export interface MonitoringRoutes {
  days: number;
  sampled: boolean;
  minimum_baseline_days: number;
  routes: RouteTrend[];
}

export type ClientFlag = "ja4_endpoint_probing" | "ja4_identifier_enumeration" | "ja4_request_manipulation";

/** One JA4 TLS client fingerprint's breadth for a day. */
export interface ClientFingerprint {
  ja4: string;
  requests: number;
  /** Requests outside the operator's allow rules and verified bots; breadth counts only these. */
  eligible: number;
  trusted: number;
  verified_bot: number;
  blocked: number;
  challenged: number;
  addresses: number;
  paths: number;
  routes: number;
  hours: number;
  top_routes: { route: string; requests: number }[];
  identifiers: { route: string; distinct: number; sequentiality: number; parameters: string[] } | null;
  attack_requests: number;
  attack_allowed: number;
  attack_labels: Record<string, number>;
  attack_route: string | null;
  /** Paths of payload-matched requests, as sent (never the query string). */
  attack_paths: { path: string; requests: number }[];
  attack_paths_total: number;
  bot: string | null;
  flags: ClientFlag[];
}

export interface MonitoringClients {
  day: string | null;
  sampled: boolean;
  clients_total: number;
  without_fingerprint: number;
  clients: ClientFingerprint[];
}

/** One-step monitor: WAF log group, optional contract (spec or scan) and optional repository. */
export interface MonitoringSetupInput {
  name: string;
  target_binding: string;
  openapi?: string | null;
  scan_id?: string | null;
  waf_log_group_arn: string;
  /** Application Load Balancer whose CloudWatch metrics add response codes and latency. */
  alb_arn?: string | null;
  github_repository?: string | null;
  github_ref?: string;
  /** This monitor's read-only GitHub token; write-only, stored encrypted. */
  github_token?: string | null;
  schedule_enabled?: boolean;
}

/** A monitor's setup as the edit form shows it; the token is never returned. */
export interface MonitoringSetupView {
  name: string;
  target_binding: string;
  waf_log_group_arn: string | null;
  alb_arn: string | null;
  github_repository: string | null;
  github_ref: string | null;
  github_token_set: boolean;
  scan_id: string | null;
  schedule_enabled: boolean;
  rapid_enabled: boolean;
}

/**
 * An edit to a monitor's setup. A key left out is unchanged; `null` removes it. The
 * target and WAF log group are not editable -- they are what the baseline compares.
 */
export interface MonitoringSetupUpdate {
  name?: string | null;
  schedule_enabled?: boolean | null;
  rapid_enabled?: boolean | null;
  alb_arn?: string | null;
  github_repository?: string | null;
  github_ref?: string | null;
  /** Left out keeps the stored token; send one to replace it. */
  github_token?: string | null;
  openapi?: string | null;
  scan_id?: string | null;
}

export const monitoringApi = {
  updateMonitor: (id: string, input: { status: "active" | "paused"; schedule_enabled: boolean; retention_days: number }) =>
    request<InfrastructureMonitor>(`/monitoring/${id}`, { method: "PATCH", body: JSON.stringify(input) }),
  deleteMonitor: (id: string) => request<void>(`/monitoring/${id}`, { method: "DELETE" }),
  cancelMonitoring: (id: string) => request(`/monitoring/${id}/cancel`, { method: "POST" }),
  monitoringContext: (id: string) => request<Record<string, unknown>>(`/monitoring/${id}/context`),
  attachMonitoringContext: (id: string, input: { scan_id: string; repository_source_id?: string; include_database: boolean }) =>
    request<Record<string, unknown>>(`/monitoring/${id}/context`, { method: "PUT", body: JSON.stringify(input) }),
  triageMonitoring: (id: string, fingerprint: string, disposition: "candidate" | "suppressed" | "reviewed") =>
    request(`/monitoring/${id}/triage`, { method: "PUT", body: JSON.stringify({ fingerprint, disposition }) }),
  monitoringAlerts: (id: string) => request<{ id: string; state: string; observation_date: string; acknowledged: boolean }[]>(`/monitoring/${id}/alerts`),
  acknowledgeMonitoringAlert: (id: string, alert: string) => request(`/monitoring/${id}/alerts/${alert}/acknowledge`, { method: "POST" }),

  listEvidenceSources: () => request<EvidenceSource[]>("/monitoring/sources"),
  createEvidenceSource: (input: EvidenceSourceInput) =>
    request<EvidenceSource>("/monitoring/sources", { method: "POST", body: JSON.stringify(input) }),
  revokeEvidenceSource: (id: string) =>
    request<EvidenceSource>(`/monitoring/sources/${id}/revoke`, { method: "POST" }),
  deleteEvidenceSource: (id: string) =>
    request<void>(`/monitoring/sources/${id}`, { method: "DELETE" }),
  listMonitors: () => request<InfrastructureMonitor[]>("/monitoring"),
  createMonitor: (input: MonitoringInput) =>
    request<InfrastructureMonitor>("/monitoring", { method: "POST", body: JSON.stringify(input) }),
  listMonitoringRuns: (id: string) => request<MonitoringRun[]>(`/monitoring/${id}/runs`),
  listMonitoringRapidRuns: (id: string) => request<MonitoringRapidRun[]>(`/monitoring/${id}/rapid-runs`),
  collectMonitoringDay: (id: string, day?: string) =>
    request<MonitoringRun>(`/monitoring/${id}/run${day ? `?observation_date=${encodeURIComponent(day)}` : ""}`, { method: "POST" }),
  uploadMonitoringSnapshot: (
    monitorId: string, sourceId: string, day: string, revision: number, snapshot: Blob,
  ) => request<MonitoringRun>(
    `/monitoring/${monitorId}/sources/${sourceId}/snapshot?` +
    new URLSearchParams({ observation_date: day, revision: String(revision) }),
    { method: "POST", body: snapshot },
  ),
  setupMonitor: (input: MonitoringSetupInput) =>
    request<InfrastructureMonitor>("/monitoring/setup", { method: "POST", body: JSON.stringify(input) }),
  getMonitorSetup: (id: string) => request<MonitoringSetupView>(`/monitoring/${id}/setup`),
  updateMonitorSetup: (id: string, update: MonitoringSetupUpdate) =>
    request<MonitoringSetupView>(`/monitoring/${id}/setup`, { method: "PUT", body: JSON.stringify(update) }),
  createExampleMonitor: () => request<InfrastructureMonitor>("/monitoring/example", { method: "POST" }),
  monitoringBots: (id: string, days = 28) =>
    request<MonitoringBots>(`/monitoring/${id}/bots?days=${days}`),
  monitoringRoutes: (id: string, days = 28, limit = 8) =>
    request<MonitoringRoutes>(`/monitoring/${id}/routes?days=${days}&limit=${limit}`),
  monitoringClients: (id: string, limit = 50) =>
    request<MonitoringClients>(`/monitoring/${id}/clients?limit=${limit}`),
  monitoringBriefing: (id: string) => request<MonitoringBriefing>(`/monitoring/${id}/briefing`),
  briefMonitoring: (id: string, days = 28) =>
    request<MonitoringBriefing>(`/monitoring/${id}/briefing?days=${days}`, { method: "POST" }),
  explainObservation: (id: string, runId: string, fingerprint: string) =>
    request<MonitoringRun>(`/monitoring/${id}/runs/${runId}/observations/${fingerprint}/explain`, {
      method: "POST",
    }),
};
