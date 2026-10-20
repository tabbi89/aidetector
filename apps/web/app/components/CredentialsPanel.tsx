"use client";

import { memo, useEffect, useRef, useState, type InputHTMLAttributes } from "react";
import {
  api,
  type AuthHints,
  type AuthType,
  type Credential,
  type GrantType,
} from "@/lib/api";
import {
  AUTH_TYPES,
  EMPTY_CRED,
  EMPTY_GRANT,
  GRANTS,
  GRANT_LABELS,
  SECRET_HINTS,
  SECRET_LABELS,
  credForm,
  credGrant,
  credPayload,
  type CredForm,
  type CredGrant,
} from "./scanShared";

/** How the scan's API is authenticated, as the user thinks about it. */
type SetupMode = "public" | "single" | "roles";

const SETUP_MODES: { id: SetupMode; label: string }[] = [
  { id: "public", label: "Public" },
  { id: "single", label: "One API key" },
  { id: "roles", label: "Several roles" },
];

/** Privilege levels the server understands; "" is "infer from the role name". */
const PRIVILEGES: { value: string; label: string }[] = [
  { value: "", label: "From role name" },
  { value: "0", label: "Lowest 0" },
  { value: "1", label: "Low 1" },
  { value: "2", label: "Elevated 2" },
  { value: "3", label: "Highest 3" },
];

/** What `header_name` carries, per auth type; null when the type has no name. */
function credentialNameLabel(type: AuthType): string | null {
  if (type === "header" || type === "api_key") return "Header name";
  if (type === "query") return "Query parameter";
  if (type === "cookie") return "Cookie name";
  return null;
}

function credentialNamePlaceholder(type: AuthType): string {
  if (type === "query") return "api_key";
  if (type === "cookie") return "session";
  return "X-API-Key";
}

/** A blank form sent the way the spec's first scheme says. */
function hintedForm(hints: AuthHints | null, base: CredForm = EMPTY_CRED): CredForm {
  const scheme = hints?.schemes[0];
  if (!scheme) return base;
  return {
    ...base,
    auth_type: scheme.auth_type,
    header_name: scheme.header_name ?? base.header_name,
    grant_type: scheme.grant_type,
    token_url: scheme.token_url,
  };
}

/** The compact form's starting point: one default identity, shaped by the spec. */
function singleForm(hints: AuthHints | null): CredForm {
  return hintedForm(hints, { ...EMPTY_CRED, name: "default", role: "user" });
}

/** One labelled input, with an optional one-line hint and inline message. */
function Field({
  label,
  hint,
  error,
  ...input
}: { label: string; hint?: string; error?: string } & InputHTMLAttributes<HTMLInputElement>) {
  return (
    <label className="field">
      <span>
        {label}
        {hint && <span className="opt-hint">{hint}</span>}
      </span>
      {/* The hint and error live inside this label, so without an explicit
          name the input's accessible name grows when either appears. Keep it
          the label word; callers can still override with their own aria-label. */}
      <input aria-label={label} {...input} />
      {error && <span className="field-error">{error}</span>}
    </label>
  );
}

/**
 * Required fields per grant. The API rejects a blank secret on create and a
 * blank grant URL outright, so the form says so inline instead of letting the
 * request come back a 422.
 */
function missing(
  form: CredForm,
  grant: CredGrant,
  {
    editing,
    hasRefreshSecret,
    localOnly,
  }: { editing: boolean; hasRefreshSecret: boolean; localOnly: boolean },
): Record<string, string> {
  const errs: Record<string, string> = {};
  if (!form.name.trim()) errs.name = "Name is required.";
  if (!form.role.trim()) errs.role = "Role is required.";
  const nameLabel = credentialNameLabel(form.auth_type);
  if (
    form.grant_type === "static" &&
    (form.auth_type === "query" || form.auth_type === "cookie") &&
    !form.header_name?.trim()
  ) {
    errs.header_name = `${nameLabel} is required.`;
  }
  const type = form.grant_type;
  if (type !== "static" && !form.token_url?.trim()) {
    errs.token_url = type === "cookie" ? "Login URL is required." : "Token URL is required.";
  }
  if (type === "client_credentials" && !grant.client_id.trim()) {
    errs.client_id = "Client ID is required.";
  }
  if ((type === "password" || type === "cookie") && !grant.username.trim()) {
    errs.username = "Username is required.";
  }
  if (!form.secret && !editing) errs.secret = `${SECRET_LABELS[type]} is required.`;
  // A local-only identity's secrets live on the CLI machine: none to ask for.
  if (form.refresh_url?.trim() && !localOnly) {
    if (!form.refresh_secret.trim() && !(editing && hasRefreshSecret)) {
      errs.refresh_secret = "Refresh token is required.";
    }
  } else if (form.refresh_secret.trim()) {
    errs.refresh_url = "A refresh URL is needed for the refresh token.";
  }
  return errs;
}

/**
 * Credential profiles for the scan, plus the add/edit form.
 *
 * Secrets are write-only end to end — the API never echoes one back, so editing
 * a profile starts with a blank secret field and leaves the stored one in place
 * unless a new value is typed. A grant turns that secret into one half of a
 * handshake: the worker mints the token from the target at run start, so a
 * short-lived credential works and a failed mint only costs that identity.
 */
function CredentialsPanelImpl({
  scanId,
  credentials,
  specScopes,
  running,
  onSave,
  onRemove,
  startOpen = false,
  managedIdentities = [],
}: {
  /** The scan whose spec the server derives credential hints from. */
  scanId?: string | null;
  credentials: Credential[];
  specScopes: string[];
  running: boolean;
  onSave: (form: CredForm, editingId: string | null) => Promise<void>;
  onRemove: (credId: string) => void;
  /** The new-scan wizard opens on the form; the detail page opens on the list. */
  startOpen?: boolean;
  /**
   * Names a project file declares. Those profiles are read-only here — the CLI
   * overwrites them on its next run — while every other profile and the add
   * form stay live, and the new-scan wizard (nothing managed) passes none.
   */
  managedIdentities?: string[];
}) {
  const [open, setOpen] = useState(startOpen);
  /** UI-only: how the user describes the API. Never sent to the server. */
  const [mode, setMode] = useState<SetupMode>(() =>
    credentials.length === 1 ? "single" : "roles",
  );
  const [hints, setHints] = useState<AuthHints | null>(null);
  /** Set once the user picks a mode, so late hints never move the choice. */
  const modePicked = useRef(false);
  const hintsApplied = useRef(false);
  const [current, setForm] = useState<CredForm>(EMPTY_CRED);
  const form = current;
  const [grant, setGrant] = useState<CredGrant>(EMPTY_GRANT);
  const [hasRefreshSecret, setHasRefreshSecret] = useState(false);
  const [errs, setErrs] = useState<Record<string, string>>({});
  const [editingId, setEditingId] = useState<string | null>(null);
  /** The identity being edited keeps its secret on the CLI machine. */
  const [editingLocalOnly, setEditingLocalOnly] = useState(false);
  const [busy, setBusy] = useState(false);

  // Hints are advisory: no spec (409), an unreachable server or an old API
  // just means the defaults stand.
  useEffect(() => {
    if (!scanId) return;
    let cancelled = false;
    api
      .authHints(scanId)
      .then((value) => {
        if (cancelled) return;
        setHints(value);
        if (!modePicked.current && credentials.length === 0 && value) {
          setMode(value.suggested);
          if (value.suggested === "single") setForm(singleForm(value));
        }
      })
      .catch(() => undefined);
    return () => {
      cancelled = true;
    };
  }, [scanId, credentials.length]);

  // Prefill from the first scheme once; later edits are the user's.
  useEffect(() => {
    if (!hints || hintsApplied.current) return;
    hintsApplied.current = true;
    const scheme = hints.schemes[0];
    if (!scheme) return;
    setForm((prev) => ({
      ...prev,
      auth_type: scheme.auth_type,
      header_name: scheme.header_name ?? prev.header_name,
      grant_type: scheme.grant_type,
      token_url: scheme.token_url,
    }));
  }, [hints]);

  /** An edit clears the message on the field it just changed. */
  function clear(field: string) {
    setErrs((prev) => (prev[field] ? { ...prev, [field]: "" } : prev));
  }

  function edit(patch: Partial<CredForm>, field: string) {
    setForm({ ...form, ...patch });
    clear(field);
  }

  function editGrant(patch: Partial<CredGrant>, field: string) {
    setGrant({ ...grant, ...patch });
    clear(field);
  }

  function chooseMode(next: SetupMode) {
    modePicked.current = true;
    setMode(next);
    setErrs({});
    setEditingId(null);
    setEditingLocalOnly(false);
    setHasRefreshSecret(false);
    setGrant(EMPTY_GRANT);
    setForm(next === "single" ? singleForm(hints) : hintedForm(hints));
    setOpen(next !== "public");
  }

  function startAdd() {
    setForm(mode === "single" ? singleForm(hints) : hintedForm(hints));
    setGrant(EMPTY_GRANT);
    setHasRefreshSecret(false);
    setErrs({});
    setEditingId(null);
    setEditingLocalOnly(false);
    setOpen(true);
  }

  function startEdit(c: Credential) {
    // Editing needs the grant and refresh fields, so it always uses the full form.
    modePicked.current = true;
    setMode("roles");
    setForm(credForm(c));
    setGrant(credGrant(c));
    setHasRefreshSecret(c.has_refresh_secret);
    setErrs({});
    setEditingId(c.id);
    setEditingLocalOnly(Boolean(c.local_only));
    setOpen(true);
  }

  async function save() {
    const editing = editingId !== null;
    // The compact one-key form has no name or role fields; never let a blank
    // one fail validation the user cannot see.
    const form =
      mode === "single"
        ? {
            ...current,
            name: current.name.trim() || "default",
            role: current.role.trim() || "user",
          }
        : current;
    const found = missing(form, grant, {
      editing,
      hasRefreshSecret,
      localOnly: editing && editingLocalOnly,
    });
    setErrs(found);
    if (Object.keys(found).length > 0) return;
    setBusy(true);
    try {
      await onSave(credPayload(form, grant, editing), editingId);
      setEditingId(null);
      setErrs({});
      if (mode === "single") {
        // One saved key is the goal here; the note below offers the second.
        setForm(EMPTY_CRED);
        setGrant(EMPTY_GRANT);
        setHasRefreshSecret(false);
        setOpen(false);
      } else if (startOpen) {
        // Wizard: keep the form up for the next role, but carry the auth and
        // grant shape over — the second identity usually matches the first.
        setForm({
          ...EMPTY_CRED,
          auth_type: form.auth_type,
          header_name: form.header_name,
          grant_type: form.grant_type,
          token_url: form.token_url,
        });
        setHasRefreshSecret(false);
      } else {
        setOpen(false);
      }
    } finally {
      setBusy(false);
    }
  }

  const headerLabel = credentialNameLabel(form.auth_type);

  return (
    <div className="specbox">
      <div className="spec-head">
        <h2>Credentials</h2>
        <span className="muted-sm">
          {credentials.length} profile{credentials.length === 1 ? "" : "s"}
        </span>
        <span className="grow" />
        {!running &&
          !open &&
          mode !== "public" &&
          !(mode === "single" && credentials.length > 0) && (
            <button className="btn quiet sm" onClick={startAdd}>
              Add credential
            </button>
          )}
      </div>

      <div style={{ marginTop: 10 }}>
        <p className="muted-sm" style={{ margin: "0 0 4px" }}>
          What kind of API is this?
        </p>
        <div className="cli-tabs" role="tablist" aria-label="What kind of API is this?">
          {SETUP_MODES.map((option) => (
            <button
              key={option.id}
              type="button"
              role="tab"
              aria-selected={mode === option.id}
              className="cli-tab"
              onClick={() => chooseMode(option.id)}
            >
              {option.label}
            </button>
          ))}
        </div>
      </div>

      {specScopes.length > 0 && (
        <p className="muted-sm" style={{ margin: "8px 0 0" }}>
          Spec auth scopes: {specScopes.join(", ")} — two accounts are enough: two
          tenants, or a user and an admin.
        </p>
      )}

      {credentials.length > 0 && (
        <div style={{ marginTop: 10 }}>
          {credentials.map((c) => {
            const locked = managedIdentities.includes(c.name);
            return (
            <div className="cred-item" key={c.id}>
              <strong>{c.name}</strong>
              <span className="role">{c.role}</span>
              <span className="role">{c.auth_type}</span>
              {c.header_name && <span className="role">{c.header_name}</span>}
              {c.privilege != null && (
                <span className="role">privilege {c.privilege}</span>
              )}
              {c.tenant && <span className="role">tenant {c.tenant}</span>}
              {c.local_only ? (
                <span
                  className="lock"
                  title="The secret never reached the server: only `aidetector run` can use this identity, and a web run leaves it out."
                >
                  local-only
                </span>
              ) : (
                <span className="lock" aria-hidden="true">🔒 encrypted</span>
              )}
              <span className="grow" />
              {!running && (
                <>
                  {locked && (
                    <span
                      className="muted-sm"
                      title="This profile is declared in the project file"
                    >
                      set by aidetector.yml
                    </span>
                  )}
                  <button
                    className="btn quiet sm"
                    onClick={() => startEdit(c)}
                    disabled={locked}
                    title={locked ? "This profile comes from the project file" : undefined}
                  >
                    Edit
                  </button>
                  <button
                    className="btn quiet sm"
                    onClick={() => onRemove(c.id)}
                    disabled={locked}
                    title={locked ? "This profile comes from the project file" : undefined}
                  >
                    Remove
                  </button>
                </>
              )}
            </div>
            );
          })}
        </div>
      )}

      {mode === "public" && (
        <p className="muted-sm" style={{ margin: "10px 0 0" }}>
          Nothing to add: the scan runs without signing in. The checks that
          compare signed-in accounts (BOLA, BFLA, the write oracle) are skipped
          and say so in the run.
          {credentials.length > 0 &&
            ` This scan still has ${credentials.length} credential profile${
              credentials.length === 1 ? "" : "s"
            } — remove ${
              credentials.length === 1 ? "it" : "them"
            } if the API really is public.`}
        </p>
      )}

      {mode === "single" && credentials.length > 0 && (
        <div style={{ marginTop: 12 }}>
          <p className="muted-sm" style={{ margin: "0 0 8px" }}>
            Add a key from a second account to test whether one account can read
            another&apos;s data (cross-account BOLA).
          </p>
          <button className="btn quiet sm" onClick={() => chooseMode("roles")}>
            Add a second account
          </button>
        </div>
      )}

      {open && mode === "single" && (
        <>
          <div className="row" style={{ marginTop: 10 }}>
            <label className="field">
              <span>How is it sent?</span>
              <select
                value={form.auth_type}
                onChange={(e) =>
                  setForm({ ...form, auth_type: e.target.value as AuthType })
                }
              >
                {AUTH_TYPES.map((t) => (
                  <option key={t} value={t}>
                    {t}
                  </option>
                ))}
              </select>
            </label>
            {credentialNameLabel(form.auth_type) && (
              <Field
                label={credentialNameLabel(form.auth_type) as string}
                error={errs.header_name}
                value={form.header_name ?? ""}
                onChange={(e) => edit({ header_name: e.target.value }, "header_name")}
                placeholder={credentialNamePlaceholder(form.auth_type)}
              />
            )}
          </div>

          {form.grant_type !== "static" && (
            <Field
              label="Token URL"
              hint="The scan mints the key at run start."
              error={errs.token_url}
              type="url"
              value={form.token_url ?? ""}
              onChange={(e) => edit({ token_url: e.target.value }, "token_url")}
              placeholder="https://api.example.com/oauth/token"
            />
          )}
          {form.grant_type === "client_credentials" && (
            <Field
              label="Client ID"
              error={errs.client_id}
              value={grant.client_id}
              onChange={(e) => editGrant({ client_id: e.target.value }, "client_id")}
              placeholder="scan-client"
            />
          )}
          {(form.grant_type === "password" || form.grant_type === "cookie") && (
            <Field
              label="Username"
              error={errs.username}
              value={grant.username}
              onChange={(e) => editGrant({ username: e.target.value }, "username")}
              placeholder="alice"
            />
          )}

          <Field
            label={SECRET_LABELS[form.grant_type]}
            hint={SECRET_HINTS[form.grant_type]}
            error={errs.secret}
            type="password"
            value={form.secret}
            onChange={(e) => edit({ secret: e.target.value }, "secret")}
            placeholder={
              form.grant_type === "static"
                ? "token / key / user:pass"
                : "client secret / password"
            }
          />

          <div className="actions">
            <button className="btn" onClick={save} disabled={busy}>
              {busy && <span className="spinner" aria-hidden="true" />}
              {busy ? "Saving…" : "Add credential"}
            </button>
            {!startOpen && (
              <button
                className="btn quiet"
                onClick={() => {
                  setOpen(false);
                  setErrs({});
                }}
                disabled={busy}
              >
                Cancel
              </button>
            )}
          </div>
        </>
      )}

      {open && mode === "roles" && (
        <>
          <div className="row" style={{ marginTop: 10 }}>
            <Field
              label="Name"
              error={errs.name}
              value={form.name}
              onChange={(e) => edit({ name: e.target.value }, "name")}
              placeholder="alice"
            />
            <Field
              label="Role"
              error={errs.role}
              value={form.role}
              onChange={(e) => edit({ role: e.target.value }, "role")}
              placeholder="user / admin"
            />
            <label className="field">
              <span>Privilege</span>
              <select
                value={form.privilege === null ? "" : String(form.privilege)}
                onChange={(e) =>
                  edit(
                    {
                      privilege:
                        e.target.value === "" ? null : Number(e.target.value),
                    },
                    "privilege",
                  )
                }
              >
                {PRIVILEGES.map((p) => (
                  <option key={p.value} value={p.value}>
                    {p.label}
                  </option>
                ))}
              </select>
            </label>
            <Field
              label="Tenant"
              hint="optional"
              value={form.tenant ?? ""}
              onChange={(e) => edit({ tenant: e.target.value || null }, "tenant")}
              placeholder="workspace-a"
              title="Which workspace this identity belongs to. With tenants set, BOLA compares identities of different tenants and BFLA compares identities within one."
            />
          </div>

          {hints && hints.roles.length > 0 && (
            <div
              style={{
                display: "flex",
                flexWrap: "wrap",
                alignItems: "center",
                gap: 8,
                margin: "4px 0 10px",
              }}
            >
              <span className="muted-sm">Roles from the spec:</span>
              {hints.roles.map((r) => (
                <button
                  key={r.name}
                  type="button"
                  className="btn quiet sm"
                  onClick={() => edit({ role: r.name, privilege: r.privilege }, "role")}
                >
                  {r.name} (privilege {r.privilege})
                </button>
              ))}
            </div>
          )}

          <label className="field">
            <span>How is the token obtained?</span>
            <select
              value={form.grant_type}
              onChange={(e) => edit({ grant_type: e.target.value as GrantType }, "token_url")}
            >
              {GRANTS.map((g) => (
                <option key={g} value={g}>
                  {GRANT_LABELS[g]}
                </option>
              ))}
            </select>
          </label>

          {form.grant_type !== "static" && (
            <p className="muted-sm cred-grant-note">
              The scan mints a fresh token from the target&apos;s own auth
              endpoint when the run starts, which is also what picks the auth
              channel (a bearer token, or a Cookie header for the login-cookie
              grant). If the mint fails, that identity is dropped for the run —
              the scan itself still runs.
            </p>
          )}

          {form.grant_type === "static" && (
            <div className="row">
              <label className="field">
                <span>Auth type</span>
                <select
                  value={form.auth_type}
                  onChange={(e) =>
                    setForm({ ...form, auth_type: e.target.value as AuthType })
                  }
                >
                  {AUTH_TYPES.map((t) => (
                    <option key={t} value={t}>
                      {t}
                    </option>
                  ))}
                </select>
              </label>
              {headerLabel && (
                <Field
                  label={headerLabel}
                  error={errs.header_name}
                  value={form.header_name ?? ""}
                  onChange={(e) => edit({ header_name: e.target.value }, "header_name")}
                  placeholder={credentialNamePlaceholder(form.auth_type)}
                />
              )}
            </div>
          )}

          {form.grant_type === "client_credentials" && (
            <>
              <div className="row">
                <Field
                  label="Token URL"
                  hint="The target's OAuth token endpoint, POSTed form-encoded at scan start."
                  error={errs.token_url}
                  type="url"
                  value={form.token_url ?? ""}
                  onChange={(e) => edit({ token_url: e.target.value }, "token_url")}
                  placeholder="https://api.example.com/oauth/token"
                />
                <Field
                  label="Client ID"
                  hint="The public half of the OAuth client."
                  error={errs.client_id}
                  value={grant.client_id}
                  onChange={(e) => editGrant({ client_id: e.target.value }, "client_id")}
                  placeholder="scan-client"
                />
              </div>
              <Field
                label="Scope (optional)"
                hint="Only if the token endpoint wants one."
                value={grant.scope}
                onChange={(e) => editGrant({ scope: e.target.value }, "scope")}
                placeholder="read:items"
              />
            </>
          )}

          {form.grant_type === "password" && (
            <>
              <div className="row">
                <Field
                  label="Token URL"
                  hint="The target's OAuth token endpoint, POSTed form-encoded at scan start."
                  error={errs.token_url}
                  type="url"
                  value={form.token_url ?? ""}
                  onChange={(e) => edit({ token_url: e.target.value }, "token_url")}
                  placeholder="https://api.example.com/oauth/token"
                />
                <Field
                  label="Username"
                  hint="The identity this profile stands for."
                  error={errs.username}
                  value={grant.username}
                  onChange={(e) => editGrant({ username: e.target.value }, "username")}
                  placeholder="alice"
                />
              </div>
              <div className="row">
                <Field
                  label="Client ID (optional)"
                  hint="Only if the token endpoint asks for one."
                  value={grant.client_id}
                  onChange={(e) => editGrant({ client_id: e.target.value }, "client_id")}
                  placeholder="scan-client"
                />
                <Field
                  label="Scope (optional)"
                  hint="Only if the token endpoint wants one."
                  value={grant.scope}
                  onChange={(e) => editGrant({ scope: e.target.value }, "scope")}
                  placeholder="read:items"
                />
              </div>
            </>
          )}

          {form.grant_type === "cookie" && (
            <>
              <div className="row">
                <Field
                  label="Login URL"
                  hint="The endpoint that sets the session cookie."
                  error={errs.token_url}
                  type="url"
                  value={form.token_url ?? ""}
                  onChange={(e) => edit({ token_url: e.target.value }, "token_url")}
                  placeholder="https://app.example.com/login"
                />
                <Field
                  label="Username"
                  hint="The identity this profile stands for."
                  error={errs.username}
                  value={grant.username}
                  onChange={(e) => editGrant({ username: e.target.value }, "username")}
                  placeholder="alice"
                />
              </div>
              <div className="row">
                <Field
                  label="Cookie name (optional)"
                  hint="Keep just this cookie; all of them when blank."
                  value={grant.cookie_name}
                  onChange={(e) => editGrant({ cookie_name: e.target.value }, "cookie_name")}
                  placeholder="sessionid"
                />
                <label className="field">
                  <span>
                    Login body
                    <span className="opt-hint">
                      How the login endpoint expects its body.
                    </span>
                  </span>
                  <select
                    value={grant.login_format}
                    onChange={(e) =>
                      editGrant(
                        { login_format: e.target.value as CredGrant["login_format"] },
                        "username",
                      )
                    }
                  >
                    <option value="json">JSON</option>
                    <option value="form">form-encoded</option>
                  </select>
                </label>
              </div>
              <div className="row">
                <Field
                  label="Username field (optional)"
                  hint="Body field the login reads the username from — username by default."
                  value={grant.username_field}
                  onChange={(e) =>
                    editGrant({ username_field: e.target.value }, "username_field")
                  }
                  placeholder="username"
                />
                <Field
                  label="Password field (optional)"
                  hint="Body field the login reads the password from — password by default."
                  value={grant.password_field}
                  onChange={(e) =>
                    editGrant({ password_field: e.target.value }, "password_field")
                  }
                  placeholder="password"
                />
              </div>
            </>
          )}

          {editingId && editingLocalOnly ? (
            <p className="muted">
              This identity is local-only: its secret stays on the machine that runs{" "}
              <code>aidetector run</code>, and the server refuses one here.
            </p>
          ) : (
          <Field
            label={
              editingId
                ? `New ${SECRET_LABELS[form.grant_type].toLowerCase()} — leave blank to keep the current one`
                : SECRET_LABELS[form.grant_type]
            }
            hint={SECRET_HINTS[form.grant_type]}
            error={errs.secret}
            type="password"
            value={form.secret}
            onChange={(e) => edit({ secret: e.target.value }, "secret")}
            placeholder={
              editingId
                ? "••••••••"
                : form.grant_type === "static"
                  ? "token / key / user:pass"
                  : "client secret / password"
            }
          />
          )}

          <details className="cred-advanced" open={hasRefreshSecret}>
            <summary>Token refresh (optional)</summary>
            <Field
              label="Refresh URL"
              hint="Called once when the target rejects a token, then the request is replayed."
              error={errs.refresh_url}
              type="url"
              value={form.refresh_url ?? ""}
              onChange={(e) => edit({ refresh_url: e.target.value }, "refresh_url")}
              placeholder="https://api.example.com/token/refresh"
            />
            <div className="row">
              {!(editingId && editingLocalOnly) && (
              <Field
                label={
                  hasRefreshSecret
                    ? "New refresh token — leave blank to keep the current one"
                    : "Refresh token"
                }
                hint="The write-only half of this pair."
                error={errs.refresh_secret}
                type="password"
                value={form.refresh_secret}
                onChange={(e) => edit({ refresh_secret: e.target.value }, "refresh_secret")}
                placeholder={hasRefreshSecret ? "••••••••" : "refresh-token"}
              />
              )}
              <Field
                label="Refresh token field"
                hint="Request body field carrying the refresh token."
                value={form.refresh_token_field}
                onChange={(e) =>
                  edit({ refresh_token_field: e.target.value }, "refresh_token_field")
                }
              />
            </div>
            <Field
              label="Access token field"
              hint="Response field holding the token — read from a mint and a refresh alike."
              value={form.access_token_field}
              onChange={(e) =>
                edit({ access_token_field: e.target.value }, "access_token_field")
              }
            />
          </details>

          <div className="actions">
            <button className="btn" onClick={save} disabled={busy}>
              {busy && <span className="spinner" aria-hidden="true" />}
              {busy ? "Saving…" : editingId ? "Save changes" : "Add credential"}
            </button>
            {!startOpen && (
              <button
                className="btn quiet"
                onClick={() => {
                  setOpen(false);
                  setEditingId(null);
                  setErrs({});
                }}
                disabled={busy}
              >
                Cancel
              </button>
            )}
          </div>
        </>
      )}
    </div>
  );
}

export const CredentialsPanel = memo(CredentialsPanelImpl);
