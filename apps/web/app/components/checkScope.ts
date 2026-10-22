// What a run can be scoped to — the engine-tier checks, grouped the way people
// ask for them ("just the headers", "every payload test").
//
// A hand-maintained mirror of `services/api/app/engine/checks/__init__.py`.
// `tests/test_coverage_mirror.py` fails if a registered check is missing here,
// a key here left the registry, or a `needs` entry disagrees with the check's
// own mutate / premium / fuzz traits. Keep one entry per line.
import type { CheckKey, RunOptions } from "@/lib/api";

/** A run flag (or deployment setting) a check needs before it reports anything. */
export type Need = "mutate" | "premium" | "fuzz" | "oast";

export interface ScopeCheck {
  key: CheckKey;
  label: string;
  needs?: Need[];
}

export interface ScopeGroup {
  id: string;
  title: string;
  blurb: string;
  checks: ScopeCheck[];
}

export const SCOPE_GROUPS: ScopeGroup[] = [
  {
    id: "headers",
    title: "Headers & exposure",
    blurb: "One GET per endpoint — headers, CORS, cookies, TLS, leaked fields. No payloads.",
    checks: [
      { key: "security_headers", label: "Security headers, CORS & cookies" },
      { key: "info_disclosure", label: "Information disclosure headers" },
      { key: "data_exposure", label: "Sensitive fields in responses" },
      { key: "potential_secrets", label: "Secrets in responses and spec" },
      { key: "tls_config", label: "TLS certificate & ciphers" },
      { key: "host_header", label: "Host-header / vhost injection", needs: ["premium"] },
    ],
  },
  {
    id: "payloads",
    title: "Payload injection",
    blurb: "Every check that sends a crafted value: reflection, error signatures, SSRF, OOB, fuzzing.",
    checks: [
      { key: "reflected_injection", label: "Reflected injection (SQLi/SSTI/XSS/traversal leads)" },
      { key: "signature_injection", label: "Backend error signatures" },
      { key: "ssrf", label: "Server-side request forgery" },
      { key: "oob_injection", label: "Out-of-band callbacks", needs: ["oast"] },
      { key: "schema_fuzz", label: "Schema fuzzing (5xx on bad input)", needs: ["fuzz"] },
      { key: "xxe_confirmation", label: "XXE confirmation", needs: ["premium", "mutate"] },
      { key: "deserialization", label: "Insecure deserialization", needs: ["premium", "mutate"] },
      { key: "unsafe_consumption", label: "Unsafe upstream consumption", needs: ["premium", "oast"] },
      { key: "request_smuggling", label: "HTTP request smuggling", needs: ["premium"] },
    ],
  },
  {
    id: "access",
    title: "Access control",
    blurb: "Can one identity reach another's objects or functions? Pairs your two credentials.",
    checks: [
      { key: "bola", label: "Object-level authorization (BOLA)" },
      { key: "bfla", label: "Function-level authorization (BFLA)" },
      { key: "broken_auth", label: "Broken authentication" },
      { key: "jwt_confusion", label: "JWT key confusion", needs: ["premium"] },
      { key: "write_authz", label: "Authorization on writes", needs: ["mutate"] },
      { key: "seeded_bola", label: "Seeded cross-tenant read", needs: ["mutate"] },
      { key: "mass_assignment", label: "Mass assignment", needs: ["mutate"] },
    ],
  },
  {
    id: "logic",
    title: "Business logic & limits",
    blurb: "Enumeration, page-size caps, rate limits, races and sensitive flows.",
    checks: [
      { key: "enumeration", label: "Enumeration / missing rate limit" },
      { key: "resource_consumption", label: "Uncapped page size" },
      { key: "race_condition", label: "Race condition", needs: ["mutate"] },
      { key: "business_flow", label: "Sensitive business flows", needs: ["mutate"] },
      { key: "advanced_rate_limit", label: "Sustained rate limit", needs: ["premium"] },
    ],
  },
  {
    id: "design",
    title: "API design & protocols",
    blurb: "Spec design review, GraphQL and gRPC exposure.",
    checks: [
      { key: "design_review", label: "Spec design review", needs: ["premium"] },
      { key: "graphql_introspection", label: "GraphQL introspection", needs: ["premium"] },
      { key: "graphql_behavior", label: "GraphQL suggestions, aliases & batching", needs: ["premium"] },
      { key: "grpc_reflection", label: "gRPC reflection", needs: ["premium"] },
    ],
  },
];

export const ALL_SCOPE_KEYS: CheckKey[] = SCOPE_GROUPS.flatMap((g) => g.checks.map((c) => c.key));

/** Short tag shown beside a check in the picker. */
export const NEED_TAG: Record<Need, string> = {
  mutate: "writes",
  premium: "premium",
  fuzz: "fuzzing",
  oast: "OAST",
};

/**
 * Plain-language expansion of a tag, shown on hover. "OAST" needs this most: it
 * is the one need no run flag can turn on, so a reader who has not met
 * out-of-band testing has nowhere else to learn what it means.
 */
export const NEED_HINT: Record<Need, string> = {
  mutate:
    "Writes to the target — create/update authorization, mass assignment, races and body-sink injection. Off by default because it changes target data.",
  premium: "A premium-tier detection; the run and this tenant both need premium.",
  fuzz: "Sends boundary and malformed values from the spec and flags 5xx responses. Spends the request budget.",
  oast: "Out-of-band: needs an OAST/Interactsh callback server — a deployment setting rather than a run flag. Blind SSRF, RCE and XXE are confirmed when the target calls back to it.",
};

/** The option that switches a need on, for the "won't run" hint. */
export const NEED_OPTION: Record<Need, string> = {
  mutate: "Test writes",
  premium: "premium detections (or Standard/Deep)",
  fuzz: "the Standard scan level",
  oast: "an OAST server (deployment setting)",
};

export type PresetId = "all" | "custom" | string;

/**
 * Scope changes preserve explicitly chosen run passes. A caller may clear
 * passes reported unavailable, while a custom selection stays unchanged.
 */
export function withPresetPasses(
  options: RunOptions,
  preset: PresetId,
  unavailable: ReadonlySet<string> = new Set(),
): RunOptions {
  if (preset === "custom") return options;
  const next = { ...options };
  const flags = next as unknown as Record<string, boolean>;
  for (const pass of unavailable) {
    if (pass in flags) flags[pass] = false;
  }
  return next;
}

/** Which preset a selection matches; empty means every check. */
export function presetOf(checks: string[]): PresetId {
  if (checks.length === 0) return "all";
  const chosen = new Set(checks);
  const group = SCOPE_GROUPS.find(
    (g) => g.checks.length === chosen.size && g.checks.every((c) => chosen.has(c.key)),
  );
  return group ? group.id : "custom";
}

/** The run-flag needs a check has that the current options leave off. */
export function unmetNeeds(check: ScopeCheck, options: RunOptions): Need[] {
  return (check.needs ?? []).filter((need) => {
    if (need === "oast") return false; // deployment-level; the run event says if it is missing
    return !options[need];
  });
}

/** Normalise a selection: registry order, and every check collapses to []. */
export function normaliseScope(chosen: Set<string>): CheckKey[] {
  const keys = ALL_SCOPE_KEYS.filter((k) => chosen.has(k));
  return keys.length === ALL_SCOPE_KEYS.length ? [] : keys;
}
