// Scan, run, finding and report shapes, and every call that acts on a scan.
import { ApiError, downloadFile, request } from "./transport";
import { NO_RUN_OPTIONS } from "./types";
import type {
  AuthType,
  ConfigSource,
  FindingConfidence,
  GrantType,
  RunOptions,
  ScanStatus,
  Severity,
  Verdict,
} from "./types";

export interface Operation {
  id: string;
  method: string;
  path: string;
  params: Record<string, unknown>[];
  auth_scope: string | null;
  enabled: boolean;
}

export interface Credential {
  id: string;
  name: string;
  role: string;
  auth_type: AuthType;
  header_name: string | null;
  refresh_url: string | null;
  refresh_token_field: string;
  access_token_field: string;
  has_refresh_secret: boolean;
  grant_type: GrantType;
  token_url: string | null;
  grant_params: Record<string, unknown>;
  /** 0..100, higher is more privileged; null means "infer from the role name". Always present. */
  privilege: number | null;
  /** The workspace the identity belongs to; null when it declares none. Always present. */
  tenant: string | null;
  // The secret stays on the CLI machine; only `aidetector run` uses it.
  local_only: boolean;
}

/** What the server suggests a spec's credentials should look like. */
export type AuthSuggestion = "public" | "single" | "roles";

/** One security scheme the server found in the spec, already mapped to an AuthType. */
export interface AuthScheme {
  name: string;
  kind: "http" | "apiKey" | "oauth2" | "openIdConnect" | "basic";
  auth_type: AuthType;
  header_name: string | null;
  grant_type: GrantType;
  token_url: string | null;
  scopes: string[];
  description: string | null;
}

/** A role named in the spec, with the privilege level the server inferred. */
export interface RoleHint {
  name: string;
  privilege: number;
}

/** Setup guidance derived from the scan's spec. */
export interface AuthHints {
  suggested: AuthSuggestion;
  reason: string;
  operations: number;
  protected_operations: number;
  schemes: AuthScheme[];
  roles: RoleHint[];
}

export interface Scan {
  id: string;
  tenant_id: string;
  target_base_url: string;
  status: ScanStatus;
  progress: number;
  cancel_requested: boolean;
  requests_per_second: number;
  cost_cents: number;
  cost_usd: number;
  schedule_minutes: number | null;
  next_run_at: string | null;
  /** The run options every scheduled run uses; empty when no schedule is set. */
  schedule_options: Record<string, unknown>;
  spec_text: string | null;
  /** Short, redacted reason when the status is "failed"; null otherwise. */
  failure_reason: string | null;
  created_at: string;
  operations: Operation[];
  credential_profiles: Credential[];
  /** What the project file owns; `{}` when the web owns every setting. */
  managed_config: Record<string, unknown>;
}

/**
 * The volatile scan state, returned by `GET /scans/{id}/progress`.
 *
 * The full `Scan` eager-loads operations, credentials, findings, events and the
 * ledger; this is the subset a one-second poll needs while a run is active.
 */
export interface ScanProgress {
  id: string;
  status: ScanStatus;
  progress: number;
  cancel_requested: boolean;
  failure_reason: string | null;
  heartbeat_at: string | null;
  cost_cents: number;
  schedule_minutes: number | null;
  next_run_at: string | null;
  created_at: string;
}

export interface ScanSummary {
  id: string;
  tenant_id: string;
  target_base_url: string;
  status: ScanStatus;
  progress: number;
  cancel_requested: boolean;
  requests_per_second: number;
  schedule_minutes: number | null;
  /** Live findings by severity; dismissed false positives are not counted. */
  finding_counts: Record<Severity, number>;
  /** `started_at` of the newest run, or null before the first one. */
  last_run_at: string | null;
  created_at: string;
}

export interface ScanEvent {
  stage: string;
  pct: number;
  message: string;
  created_at: string;
}

export interface RunFinding {
  check: string;
  severity: Severity;
  confidence: FindingConfidence;
  /** Stable identity across runs; empty on runs archived before it existed. */
  fingerprint: string;
  title: string;
  owasp_id: string | null;
  verdict: Verdict;
}

/**
 * What changed between two runs of one scan, matched by fingerprint.
 * `unmatchable` counts rows on either side that predate fingerprinting — a
 * non-zero value means one run is older than the feature, not that anything
 * went wrong.
 */
export interface RunDiff {
  from_run: number;
  to_run: number;
  added: RunFinding[];
  resolved: RunFinding[];
  /** Older-run findings from an opt-in pass the newer run left off — not fixed, unchecked. */
  not_retested: RunFinding[];
  /** The two runs used different options, so the comparison is partial. */
  options_changed: boolean;
  /** The two runs ran on different executors (server worker vs local runner). */
  executor_changed: boolean;
  /** The two runs took their settings from a different project file (or from the web). */
  config_changed: boolean;
  unchanged: RunFinding[];
  unmatchable: number;
}

export interface CoverageRow {
  operation_id: string | null;
  method: string;
  path: string;
  enabled: boolean;
  requests: number;
  checks: string[];
  findings: number;
}

export interface PlanRow {
  operation_id: string | null;
  method: string;
  path: string;
  priority: string;
  rationale: string;
}

export interface AdaptiveAttempt {
  number: number;
  variant: string;
  status: number | null;
  outcome: string;
  assessment: string;
  tokens: number;
  cost_micros: number;
  cost_estimated: boolean;
  persisted: boolean;
  cleanup: string;
}

export interface AdaptiveSettings {
  attempts: 2 | 3;
  endpoints: number;
  requests: number;
  seconds: number;
  tokens: number;
  cost_micros: number;
}

export interface AdaptiveTest {
  operation_id: string | null;
  method: string;
  route: string;
  field: string;
  location: string;
  rule: string;
  priority: number;
  rationale: string;
  attempts: AdaptiveAttempt[];
  outcome: string;
  schema_status: string;
  stop_reason: string;
  schema_facts: string[];
  finding_fingerprint: string | null;
}

export interface AdaptiveHistory {
  enabled: boolean;
  settings: AdaptiveSettings;
  tests: AdaptiveTest[];
  requests: number;
  elapsed_ms: number;
  stop_reason: string;
  cost_estimated: boolean;
  tokens: number;
  cost_micros: number;
}

export interface ResourceRow {
  resource: string;
  create_method: string;
  create_path: string;
  read_method: string;
  read_path: string;
  status: string;
  via_ai: boolean;
  cleanup: string;
  source: string;
  attempts: Array<{ number: number; source: string; status: number | null }>;
}

export interface MutationRow {
  sequence: number;
  method: string;
  route: string;
  check: string;
  /** Credential whose headers went out — "anonymous" when none did. */
  identity: string;
  /** Which pass made the call: "engine" or "discovery". */
  pass: string;
  elapsed_ms: number | null;
  /** Transport failure class ("ReadTimeout", "ConnectError") when no response came back. */
  error?: string | null;
  request: {
    headers: Record<string, string>;
    query_fields: string[];
    json_shape: unknown;
    /** Redacted JSON payload we sent — what a rejection was rejecting. */
    json_body: string;
    content_bytes: number;
  };
  response: {
    status: number | null;
    headers: Record<string, string>;
    content_type: string;
    body_bytes: number;
    /** Redacted, truncated response text — why a call was accepted or not. */
    body: string;
    /** The retained text was cut at the per-row limit. */
    truncated: boolean;
    /** No text kept: not a textual response, or the run's body budget was spent. */
    body_omitted: boolean;
    json_shape: unknown;
  };
}

/** One page of a run's request trace. */
export interface RunTrace {
  run_number: number;
  total: number;
  offset: number;
  rows: MutationRow[];
}

export interface DesignSuggestion {
  title: string;
  priority: "high" | "medium" | "low";
  observation: string;
  risk: string;
  recommendation: string;
  validation: string;
  assumptions: string[];
  references: string[];
}

export interface SecurityReview {
  status: "not_requested" | "running" | "completed" | "unavailable";
  schema_status: "not_provided" | "available" | "unavailable";
  model: string;
  suggestions: DesignSuggestion[];
}

export interface ScanRun {
  manifest: Record<string, unknown>;
  id: string;
  run_number: number;
  status: string;
  started_at: string;
  finished_at: string | null;
  findings_count: number;
  requests: number;
  findings_snapshot: RunFinding[];
  coverage: CoverageRow[];
  plan: PlanRow[];
  adaptive: AdaptiveHistory;
  security_review: SecurityReview;
  resources: ResourceRow[];
  /** The run options this run executed with; empty for runs archived before them. */
  options: Record<string, unknown>;
  /** Who ran it: {} is the server worker, {kind:"local_runner",...} the CLI machine. */
  executor: Record<string, unknown>;
  /**
   * The project file this run's settings came from; `{}` when they came from the
   * web. Only path/digest/commit travel — the file's contents stay on the CLI's
   * machine.
   */
  config_source: Record<string, unknown>;
  /**
   * What the run could not do: adjunct tools that were requested but never ran,
   * and whether the request budget ran out. Absent on runs archived before it.
   */
  gaps: {
    not_run: string[];
    budget_exhausted: boolean;
    /** Identities this run left out (local-only, or unreadable); [] when none. */
    identities_missing: string[];
    /** Engine checks the run skipped as inapplicable; the diff never calls their findings fixed. */
    skipped_checks: string[];
    /** Engine checks that raised before finishing (e.g. a timeout); not fixed either. */
    failed_checks: string[];
    /** Whether a local directory scan completed its language-version CVE lookups. */
    source_audit_complete: boolean;
  };
  /**
   * How many request-trace rows this run archived. The rows themselves are not
   * on this object — a run's trace is hundreds of rows with body samples, and
   * `/runs` returns every run a scan ever had. Fetch a page with `getRunTrace`.
   */
  trace_count: number;
}

export interface Finding {
  id: string;
  operation_id: string | null;
  check: string;
  /** Stable identity across runs — what carried triage and the diff match on. */
  fingerprint: string;
  owasp_id: string | null;
  severity: Severity;
  confidence: FindingConfidence;
  title: string;
  description: string;
  evidence: Record<string, unknown>;
  /** What to change, shaped by this finding's evidence. May be empty. */
  remediation: string;
  /** Supporting links (OWASP cheat sheets, CWE) for the fix above. */
  references: string[];
  verdict: Verdict;
  ai_rationale: string | null;
  created_at: string;
  /** True when this finding came from a premium-tier check (premium:true run). */
  readonly premium: boolean;
}

/** Where a finding's assignment stands. Separate from triage — a verdict is not changed by it. */
export type FindingWorkStatus = "open" | "in_progress" | "resolved" | "accepted_risk";

export interface FindingComment {
  id: string;
  scan_id: string;
  fingerprint: string;
  author: string;
  author_user_id?: string | null;
  body: string;
  created_at: string;
}

/** Team-workflow state for one live finding, with its discussion oldest first. */
export interface FindingWork {
  scan_id: string;
  fingerprint: string;
  owner: string | null;
  owner_user_id?: string | null;
  due_date: string | null;
  status: FindingWorkStatus;
  updated_at: string;
  comments: FindingComment[];
}

/** Omitted fields stay unchanged; an explicit null clears owner or due date. */
export interface FindingWorkInput {
  owner?: string | null;
  owner_user_id?: string | null;
  due_date?: string | null;
  status?: FindingWorkStatus;
}

export interface AskAnswer {
  answer: string;
}

export interface LedgerEntry {
  phase: string;
  model: string;
  tokens_in: number;
  tokens_out: number;
  cost_micros: number;
}

export interface AiModelUsage {
  model: string;
  phases: string[];
  calls: number;
  tokens_in: number;
  tokens_out: number;
  cost_usd: number;
}

export interface Cost {
  scan_id: string;
  total_usd: number;
  entries: LedgerEntry[];
  models: AiModelUsage[];
}

export interface RunAccepted {
  scan_id: string;
  status: ScanStatus;
}

export interface CredentialInput {
  name: string;
  role: string;
  auth_type: AuthType;
  header_name?: string | null;
  /** Required unless local_only, which must not carry one. */
  secret?: string | null;
  refresh_url?: string | null;
  refresh_secret?: string | null;
  refresh_token_field?: string;
  access_token_field?: string;
  grant_type?: GrantType;
  token_url?: string | null;
  grant_params?: Record<string, unknown>;
  /** 0..100, higher is more privileged; null infers it from the role name. */
  privilege?: number | null;
  /** The workspace the identity belongs to; null when undeclared. */
  tenant?: string | null;
  /** The secret stays on the CLI machine; only `aidetector run` can use it. */
  local_only?: boolean;
}

/** Edit payload: metadata required, secret only when replacing it. */
export interface CredentialUpdateInput extends Omit<CredentialInput, "secret" | "local_only"> {
  secret?: string | null;
}

export interface ScanInput { target_base_url: string }
export interface RequestRateInput { requests_per_second: number }
/** What a spec parse did: how much it kept, what it dropped and any warnings. */
export interface SpecReport {
  operations: number;
  skipped: { path: string; method: string | null; reason: string }[];
  warnings: string[];
}

/** A spec upload's response: the scan plus what the parse did to it. */
export interface SpecUpload extends Scan { spec_report: SpecReport }

export interface SpecInput { content: string }
export interface OperationsInput { operations: { id: string; enabled: boolean }[] }
/** A schedule is a standing run request: enabling one carries the run's flags and authorization. */
export interface ScheduleInput extends Omit<RunInput, "authorized"> {
  authorized?: boolean;
  minutes?: number | null;
}
export interface VerdictInput { verdict: Verdict }
export interface AskInput { question: string }
export interface RunInput extends Omit<Partial<RunOptions>, "requests_per_second"> {
  authorized: boolean;
  requests_per_second?: number | null;
  /**
   * The project file a CLI run took its settings from. The CLI sends it inside
   * the options dict, so it travels with the run rather than as a task argument.
   */
  config_source?: ConfigSource | null;
}

export interface FindingQuery {
  severity?: Severity;
  check?: string;
  /** Narrows to one operation. */
  operation_id?: string;
  /**
   * An endpoint label as the list renders it (`GET /users/{id}`); matches
   * findings with an operation and evidence-only findings alike.
   */
  endpoint?: string;
  verdict?: Verdict;
  confidence?: FindingConfidence;
  premium?: boolean;
  q?: string;
  include_dismissed?: boolean;
  sort?: "severity" | "endpoint" | "check" | "newest";
}

/**
 * The full-set counts as the page holds them: still being read, read, or
 * unavailable. Only `ready` may back a statement about every finding.
 */
export type FindingSummaryState =
  | { status: "loading" }
  | { status: "ready"; summary: FindingSummary }
  | { status: "unavailable" };

export interface FindingSummary {
  total: number;
  active: number;
  dismissed: number;
  verified_critical: number;
  verified_high: number;
  severity: Record<string, number>;
}

export const scansApi = {
  listScans: (limit = 500, offset = 0) =>
    request<ScanSummary[]>(`/scans?limit=${limit}&offset=${offset}`),
  getScan: (id: string) => request<Scan>(`/scans/${id}`),
  /** The lightweight poll used while a scan is active. */
  getScanProgress: (id: string) =>
    request<ScanProgress>(`/scans/${id}/progress`),
  createScan: (target_base_url: string) =>
    request<Scan>("/scans", {
      method: "POST",
      body: JSON.stringify({ target_base_url } satisfies ScanInput),
    }),
  /** Dev only: the bundled target with its spec and both seed identities, not yet run. */
  createExampleScan: () => request<Scan>("/scans/example", { method: "POST" }),
  updateScan: (id: string, target_base_url: string) =>
    request<Scan>(`/scans/${id}`, {
      method: "PATCH",
      body: JSON.stringify({ target_base_url } satisfies ScanInput),
    }),
  setRequestRate: (id: string, requests_per_second: number) =>
    request<Scan>(`/scans/${id}/request-rate`, {
      method: "PUT",
      body: JSON.stringify({ requests_per_second } satisfies RequestRateInput),
    }),
  uploadSpec: (id: string, content: string) =>
    request<SpecUpload>(`/scans/${id}/spec`, {
      method: "POST",
      body: JSON.stringify({ content } satisfies SpecInput),
    }),
  /** Drop the project-file lock: the web owns every setting again from here. */
  clearManagedConfig: (id: string) =>
    request<Scan>(`/scans/${id}/managed-config`, { method: "DELETE" }),
  deleteScan: (id: string) =>
    request<{ status: string }>(`/scans/${id}`, { method: "DELETE" }),
  setOperations: (
    id: string,
    operations: { id: string; enabled: boolean }[],
  ) =>
    request<Scan>(`/scans/${id}/operations`, {
      method: "PATCH",
      body: JSON.stringify({ operations } satisfies OperationsInput),
    }),
  /**
   * Credential setup hints derived from the scan's spec. A scan without a spec
   * answers 409, which is "nothing to suggest yet" rather than an error.
   */
  authHints: async (id: string): Promise<AuthHints | null> => {
    try {
      return await request<AuthHints>(`/scans/${id}/auth-hints`);
    } catch (e) {
      if (e instanceof ApiError && e.status === 409) return null;
      throw e;
    }
  },
  addCredential: (id: string, cred: CredentialInput) =>
    request<Credential>(`/scans/${id}/credentials`, {
      method: "POST",
      body: JSON.stringify(cred),
    }),
  updateCredential: (id: string, credId: string, cred: CredentialUpdateInput) =>
    request<Credential>(`/scans/${id}/credentials/${credId}`, {
      method: "PATCH",
      body: JSON.stringify(cred),
    }),
  deleteCredential: (id: string, credId: string) =>
    request<{ status: string }>(`/scans/${id}/credentials/${credId}`, {
      method: "DELETE",
    }),
  runScan: (id: string, authorized: boolean, options: Partial<RunOptions> = {}) =>
    request<RunAccepted>(`/scans/${id}/run`, {
      method: "POST",
      body: JSON.stringify({ ...NO_RUN_OPTIONS, ...options, authorized } satisfies RunInput),
    }),
  getCost: (id: string) => request<Cost>(`/scans/${id}/cost`),
  /** Enabling needs `authorized`; the options become every scheduled run's. Clearing needs neither. */
  setSchedule: (
    id: string,
    minutes: number | null,
    options: Partial<RunOptions> = {},
    authorized = false,
  ) =>
    request<Scan>(`/scans/${id}/schedule`, {
      method: "PUT",
      body: JSON.stringify(
        (minutes
          ? { ...NO_RUN_OPTIONS, ...options, authorized, minutes }
          : { minutes }) satisfies ScheduleInput,
      ),
    }),
  downloadExport: (id: string) => downloadFile(`/scans/${id}/export`, `scan-${id}.json`),
  downloadPdf: (id: string) => downloadFile(`/scans/${id}/report.pdf`, `scan-${id}.pdf`),
  downloadSarif: (id: string) => downloadFile(`/scans/${id}/sarif`, `scan-${id}.sarif`),
  downloadPentestReport: (id: string) =>
    downloadFile(`/scans/${id}/report.pentest`, `scan-${id}.pentest.md`),
  /**
   * Saved rather than opened: a blob URL would render the report — which quotes
   * target-controlled values — under this app's origin instead of the API's.
   */
  openHtmlReport: (id: string) => downloadFile(`/scans/${id}/report.html`, `scan-${id}.html`),
  cancelScan: (id: string) =>
    request<ScanSummary>(`/scans/${id}/cancel`, { method: "POST" }),
  getEvents: (id: string, limit = 500) =>
    request<ScanEvent[]>(`/scans/${id}/events?limit=${limit}`),
  getRuns: (id: string, limit = 50, offset = 0) =>
    request<ScanRun[]>(`/scans/${id}/runs?limit=${limit}&offset=${offset}`),
  getRunTrace: (id: string, runNumber: number, offset = 0, limit = 100) =>
    request<RunTrace>(`/scans/${id}/runs/${runNumber}/trace?offset=${offset}&limit=${limit}`),
  /** What changed between two runs. Defaults to the two most recent;
   *  409 when the scan has fewer than two runs to compare. */
  getDiff: (id: string) => request<RunDiff>(`/scans/${id}/diff`),
  getFindings: (id: string, limit = 1000, offset = 0, query?: FindingQuery) => {
    const params = new URLSearchParams({
      limit: String(limit),
      offset: String(offset),
    });
    if (query?.severity) params.set("severity", query.severity);
    if (query?.check) params.set("check", query.check);
    if (query?.operation_id) params.set("operation_id", query.operation_id);
    if (query?.endpoint) params.set("endpoint", query.endpoint);
    if (query?.verdict) params.set("verdict", query.verdict);
    if (query?.confidence) params.set("confidence", query.confidence);
    if (query?.premium !== undefined) {
      params.set("premium", String(query.premium));
    }
    if (query?.q) params.set("q", query.q);
    if (query?.include_dismissed !== undefined) {
      params.set("include_dismissed", String(query.include_dismissed));
    }
    if (query?.sort) params.set("sort", query.sort);
    return request<Finding[]>(`/scans/${id}/findings?${params.toString()}`);
  },
  getFindingSummary: (id: string) =>
    request<FindingSummary>(`/scans/${id}/findings/summary`),
  /** Assignment and discussion for the scan's live findings. */
  listWork: (id: string) => request<FindingWork[]>(`/scans/${id}/work`),
  saveWork: (id: string, fingerprint: string, input: FindingWorkInput) =>
    request<FindingWork>(
      `/scans/${id}/findings/${encodeURIComponent(fingerprint)}/work`,
      { method: "PUT", body: JSON.stringify(input) },
    ),
  deleteWork: (id: string, fingerprint: string) =>
    request<void>(`/scans/${id}/findings/${encodeURIComponent(fingerprint)}/work`, {
      method: "DELETE",
    }),
  addComment: (id: string, fingerprint: string, body: string) =>
    request<FindingComment>(
      `/scans/${id}/findings/${encodeURIComponent(fingerprint)}/comments`,
      { method: "POST", body: JSON.stringify({ body }) },
    ),
  deleteComment: (id: string, commentId: string) =>
    request<void>(`/scans/${id}/comments/${encodeURIComponent(commentId)}`, {
      method: "DELETE",
    }),
  /** Ask a natural-language question about the scan's findings (premium). */
  ask: (id: string, question: string) =>
    request<AskAnswer>(`/scans/${id}/ask`, {
      method: "POST",
      body: JSON.stringify({ question } satisfies AskInput),
    }),
  setVerdict: (scanId: string, findingId: string, verdict: Verdict) =>
    request<Finding>(`/scans/${scanId}/findings/${findingId}`, {
      method: "PATCH",
      body: JSON.stringify({ verdict } satisfies VerdictInput),
    }),
};
