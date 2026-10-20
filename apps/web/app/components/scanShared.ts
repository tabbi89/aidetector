// Constants, types and helpers shared by the scan wizard and the scan detail page.
import type { AuthType, Credential, FindingConfidence, GrantType, ScanEvent, Severity } from "@/lib/api";

export const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];

export const RANK: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

/**
 * Proof before leads within one severity — the same tie-break `sort_findings`
 * applies in `app/models/finding.py`, so the UI, the API, the exports and the
 * PDF all list findings in one order.
 */
export const CONFIDENCE_RANK: Record<FindingConfidence, number> = {
  verified: 0,
  heuristic: 1,
};

export const CONFIDENCE_HINT: Record<FindingConfidence, string> = {
  verified:
    "Verified — the evidence demonstrates the weakness directly. Act on this.",
  heuristic:
    "Heuristic — a lead. The signal shows input reached the response, not that it executes. Confirm by hand.",
};

/** Statuses that mean the worker is still writing to this scan. */
export const ACTIVE = new Set(["queued", "running"]);

export const AUTH_TYPES: AuthType[] = [
  "bearer",
  "header",
  "api_key",
  "basic",
  "query",
  "cookie",
  "none",
];

/** How a credential obtains the token it authenticates with. */
export const GRANTS: GrantType[] = ["static", "client_credentials", "password", "cookie"];

/** Select labels — the user's mental model, not the OAuth grant names. */
export const GRANT_LABELS: Record<GrantType, string> = {
  static: "I paste a token",
  client_credentials: "Client credentials (OAuth2)",
  password: "Username and password",
  cookie: "Login cookie",
};

/** What the write-only `secret` field carries, per grant. */
export const SECRET_LABELS: Record<GrantType, string> = {
  static: "Token",
  client_credentials: "Client secret",
  password: "Password",
  cookie: "Password",
};

export const SECRET_HINTS: Record<GrantType, string> = {
  static: "Sent as-is on every request.",
  client_credentials: "The client secret half of the OAuth client.",
  password: "The password of that username.",
  cookie: "The password of that username.",
};

/**
 * One profile as the form holds it. Every field here is one the API accepts, so
 * the form doubles as the payload — `credPayload` only normalises blanks.
 */
export interface CredForm {
  name: string;
  role: string;
  auth_type: AuthType;
  header_name: string | null;
  /** 0..100; null lets the server infer it from the role name. */
  privilege: number | null;
  /** The workspace the identity belongs to; null when undeclared. */
  tenant: string | null;
  secret: string;
  grant_type: GrantType;
  token_url: string | null;
  grant_params: Record<string, string>;
  refresh_url: string | null;
  refresh_secret: string;
  refresh_token_field: string;
  access_token_field: string;
}

/** The non-secret grant inputs the form shows; `credPayload` folds them in. */
export interface CredGrant {
  client_id: string;
  scope: string;
  username: string;
  username_field: string;
  password_field: string;
  cookie_name: string;
  /** Cookie grant: a form body also renames the two login field inputs. */
  login_format: "json" | "form";
}

export const EMPTY_CRED: CredForm = {
  name: "",
  role: "",
  auth_type: "header",
  header_name: "Authorization",
  privilege: null,
  tenant: null,
  secret: "",
  grant_type: "static",
  token_url: null,
  grant_params: {},
  refresh_url: null,
  refresh_secret: "",
  refresh_token_field: "refresh_token",
  access_token_field: "access_token",
};

export const EMPTY_GRANT: CredGrant = {
  client_id: "",
  scope: "",
  username: "",
  username_field: "",
  password_field: "",
  cookie_name: "",
  login_format: "json",
};

/**
 * The grant inputs as `grant_params`, under exactly the keys
 * `app/engine/base.py` reads per grant. Blanks are dropped so the engine keeps
 * its own defaults (`username`, `password`, a JSON login body).
 */
function grantParams(grant: CredGrant, grantType: GrantType): Record<string, string> {
  const params: Record<string, string> = {};
  const put = (key: string, value: string) => {
    if (value.trim()) params[key] = value.trim();
  };
  if (grantType === "client_credentials" || grantType === "password") {
    put("client_id", grant.client_id);
    put("scope", grant.scope);
  }
  if (grantType === "password" || grantType === "cookie") put("username", grant.username);
  if (grantType === "cookie") {
    put("username_field", grant.username_field);
    put("password_field", grant.password_field);
    put("cookie_name", grant.cookie_name);
    if (grant.login_format === "form") params.format = "form";
  }
  return params;
}

/** The form as the API payload: blank optionals go as null rather than "". */
export function credPayload(form: CredForm, grant: CredGrant, editing: boolean): CredForm {
  const orNull = (value: string | null) => value?.trim() || null;
  const payload: CredForm = {
    ...form,
    name: form.name.trim(),
    role: form.role.trim(),
    header_name: orNull(form.header_name),
    tenant: orNull(form.tenant),
    token_url: orNull(form.token_url),
    refresh_url: orNull(form.refresh_url),
    refresh_token_field: form.refresh_token_field.trim() || "refresh_token",
    access_token_field: form.access_token_field.trim() || "access_token",
    grant_params: grantParams(grant, form.grant_type),
  };
  // The API reads an empty string as an invalid secret, so a blank write-only
  // field drops its key. The refresh token is optional on create and update;
  // a blank secret only means "keep the stored one" on an edit.
  const writable: { secret?: string; refresh_secret?: string } = payload;
  if (!payload.refresh_secret.trim()) delete writable.refresh_secret;
  if (editing && !payload.secret) delete writable.secret;
  return payload;
}

/** A stored profile back in the form. Secrets are never returned, so they blank. */
export function credForm(c: Credential): CredForm {
  return {
    name: c.name,
    role: c.role,
    auth_type: c.auth_type,
    header_name: c.header_name ?? "Authorization",
    privilege: c.privilege ?? null,
    tenant: c.tenant ?? null,
    secret: "",
    grant_type: c.grant_type,
    token_url: c.token_url,
    grant_params: {},
    refresh_url: c.refresh_url,
    refresh_secret: "",
    refresh_token_field: c.refresh_token_field,
    access_token_field: c.access_token_field,
  };
}

/** The non-secret grant params, back in the fields their grant shows. */
export function credGrant(c: Credential): CredGrant {
  const params = c.grant_params ?? {};
  const str = (key: string) => (params[key] == null ? "" : String(params[key]));
  return {
    client_id: str("client_id"),
    scope: str("scope"),
    username: str("username"),
    username_field: str("username_field"),
    password_field: str("password_field"),
    cookie_name: str("cookie_name"),
    login_format: params.format === "form" ? "form" : "json",
  };
}

export function clock(iso: string) {
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? "" : d.toLocaleTimeString();
}

/**
 * "3 steps did not run" — or "did not run or finish" once a check started and
 * raised (`check_failed`): that check ran, it just stopped part-way.
 */
export function gapCountLabel(gaps: ScanEvent[]): string {
  const n = gaps.length;
  const verb = gaps.some((e) => e.stage === "check_failed") ? "did not run or finish" : "did not run";
  return `${n} step${n === 1 ? "" : "s"} ${verb}`;
}
