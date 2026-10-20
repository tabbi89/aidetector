// Vocabulary shared by more than one feature: enums, run options and the
// settings a project file can own. Nothing here performs a request.
import type { Scan } from "./scans";

export type Verdict = "unreviewed" | "confirmed" | "dismissed";

export type ScanStatus = "draft" | "queued" | "running" | "completed" | "failed" | "cancelled";

export type GrantType = "static" | "client_credentials" | "password" | "cookie";

export type Severity = "info" | "low" | "medium" | "high" | "critical";

export type AuthType =
  | "bearer"
  | "header"
  | "api_key"
  | "basic"
  | "query"
  | "cookie"
  | "none";

/** A server-expanded run level; the web names the level and never the flags it implies. */
export type ScanLevel = "quick" | "standard" | "deep";

/**
 * The evidence tier a finding was graded at, mirroring `Confidence` in
 * `app/models/finding.py`. Severity says how bad it is if real; this says how
 * sure the engine is. `verified` means the evidence demonstrates the weakness
 * (a cross-identity read/write that persisted, an out-of-band callback, an
 * inspected certificate); `heuristic` means it is a lead to confirm by hand.
 *
 * The same vocabulary `Confidence` in `lib/coverage.ts` uses per check — that
 * one describes what a check *can* prove, this one what a finding *did*.
 */
export type FindingConfidence = "heuristic" | "verified";

export type CheckKey =
  | "bola"
  | "bfla"
  | "broken_auth"
  | "security_headers"
  | "info_disclosure"
  | "data_exposure"
  | "potential_secrets"
  | "enumeration"
  | "resource_consumption"
  | "write_authz"
  | "seeded_bola"
  | "mass_assignment"
  | "race_condition"
  | "business_flow"
  | "reflected_injection"
  | "signature_injection"
  | "ssrf"
  | "oob_injection"
  | "schema_fuzz"
  | "tls_config"
  | "host_header"
  | "design_review"
  | "advanced_rate_limit"
  | "xxe_confirmation"
  | "jwt_confusion"
  | "deserialization"
  | "unsafe_consumption"
  | "graphql_introspection"
  | "graphql_behavior"
  | "request_smuggling"
  | "grpc_reflection";

/**
 * The opt-in passes for a run — mirrors `services/api/app/scans/run_options.py`.
 *
 * Every flag defaults to off, and that is a safety property: `mutate` writes to
 * the target, `zap`/`kali`/`confirm` fire far more traffic than the engine's
 * request budget allows, `testssl` takes minutes, and `plan`/`adjudicate` spend
 * tokens.
 *
 * `authorized` is deliberately not here — it gates whether a run may start,
 * it does not configure one.
 */
export interface RunOptions {
  /** Let the server expand quick/standard/deep into the passes it implies. Null leaves the server default. */
  level?: ScanLevel | null;
  seed?: number | null;
  adjudicate: boolean;
  security_review: boolean;
  zap: boolean;
  kali: boolean;
  mutate: boolean;
  /** Explicit AI switch: plan, adjudication and design review (plus more at Deep). */
  ai: boolean;
  confirm: boolean;
  /** testssl.sh deep TLS audit of an HTTPS target; heavy lane (Deep level). */
  testssl: boolean;
  plan: boolean;
  /** AI payload design: DeepSeek proposes extra reflection-payload variants. */
  genai_payloads: boolean;
  fuzz: boolean;
  /** Heavy-lane bounded whitebox agent (CLI local runner only); no-op on the server. */
  agent: boolean;
  premium: boolean;
  adaptive: boolean;
  adaptive_attempts: number;
  resource_refine: boolean;
  resource_attempts: number;
  predefined_resource_ids: Record<string, string>;
  requests_per_second: number;
  /** Engine check keys to run; empty runs every check. Narrows, never enables. */
  checks: CheckKey[];
}

export const NO_RUN_OPTIONS: RunOptions = {
  checks: [],
  level: "quick",
  ai: false,
  adjudicate: false,
  security_review: false,
  zap: false,
  kali: false,
  mutate: false,
  confirm: false,
  testssl: false,
  plan: false,
  genai_payloads: false,
  fuzz: false,
  agent: false,
  premium: false,
  adaptive: false,
  adaptive_attempts: 3,
  resource_refine: false,
  resource_attempts: 3,
  predefined_resource_ids: {},
  requests_per_second: 10,
};

/** Which opt-in passes the deployment can run now; advisory, keyed by RunOptions flag. */
export interface Capabilities {
  passes: Partial<Record<"zap" | "kali" | "confirm" | "testssl" | "plan" | "adjudicate" | "security_review" | "genai_payloads",
    { available: boolean; reason: string | null }>>;
}

export interface Health {
  status: string;
  /** Whether the dev-only example endpoints answer. */
  examples: boolean;
}

/** Who the presented key belongs to, and whether the deployment gates the API at all. */
export interface AuthStatus {
  tenant: string;
  auth_required: boolean;
  role: "admin" | "analyst" | "viewer";
  user: { id: string; email: string; display_name: string } | null;
}

/** A setting a project file (`aidetector.yml`) owns for this scan. */
export type ManagedField =
  | "target"
  | "spec"
  | "identities"
  | "requests_per_second"
  | "run_options";

/**
 * The project file the CLI last ran this scan from, and what it owns. Mirrored
 * by hand from `ManagedConfig` in `app/api/schemas.py` — nothing generates it.
 */
export interface ManagedConfig {
  path: string;
  digest: string;
  commit: string | null;
  fields: ManagedField[];
  /** Credential names the file declares; those profiles are read-only here. */
  identities: string[];
  updated_at: string;
}

/**
 * Where a run's settings came from: a project file (path + digest + commit).
 * Mirrors `ConfigSource` in `app/api/schemas.py`.
 */
export interface ConfigSource {
  path: string;
  digest: string;
  commit?: string | null;
}

/**
 * The settings the project file owns on this scan, as a set the panels test
 * one field at a time. An empty set — the `{}` the API sends when the web owns
 * everything — leaves every control live.
 *
 * `managed_config` is an open JSON object on the wire (`Record<string, unknown>`),
 * so the array is narrowed at runtime rather than trusted from the type.
 */
export function managedFields(scan: Scan): Set<ManagedField> {
  const fields = scan.managed_config?.fields;
  return new Set<ManagedField>(Array.isArray(fields) ? (fields as ManagedField[]) : []);
}

/**
 * The project file a run recorded, or null for the `{}` the API sends when the
 * run's settings came from the web. The wire type is an open object, so this
 * checks the two fields a reader actually uses.
 */
export function configSourceOf(value: Record<string, unknown> | null | undefined): ConfigSource | null {
  if (!value || typeof value.path !== "string" || typeof value.digest !== "string") return null;
  return {
    path: value.path,
    digest: value.digest,
    commit: typeof value.commit === "string" ? value.commit : null,
  };
}
