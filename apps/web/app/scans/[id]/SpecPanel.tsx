"use client";

import { ExpandingTextarea } from "../../components/ExpandingTextarea";

import { memo, useEffect, useMemo, useState } from "react";
import type { Operation, SpecReport } from "@/lib/api";
import { SpecReportView } from "../../components/SpecReportView";

function resourceKey(name: string): string {
  let value = name.toLowerCase().replace(/[^a-z0-9]/g, "");
  for (const suffix of ["uuid", "guid", "id"]) {
    if (value.endsWith(suffix) && value.length > suffix.length) {
      value = value.slice(0, -suffix.length);
      break;
    }
  }
  // Every trailing "s", like the engine's `resource_key` (`rstrip("s")`).
  return value.replace(/s+$/, "");
}

const BARE_ID_NAMES = new Set(["id", "uuid", "guid"]);

/**
 * The editor key for one path parameter. Mirrors the engine's
 * `resource_map.param_resource_name`: a named parameter keeps its spec name,
 * and a bare `{id}` / `{uuid}` / `{guid}` names its resource by the static
 * segment before it, so `/monitors/{id}` and `/incidents/{id}` get separate
 * boxes (`monitor_id`, `incident_id`) instead of sharing one `id`.
 */
function resourceIdName(path: string, name: string): string {
  if (!BARE_ID_NAMES.has(name.toLowerCase().replace(/[^a-z0-9]/g, ""))) return name;
  const parts = path.split("/").filter(Boolean);
  const index = parts.indexOf(`{${name}}`);
  const previous = index > 0 ? parts[index - 1] : "";
  if (!previous || previous.startsWith("{")) return name;
  const resource = resourceKey(previous);
  // The API's resource-name grammar starts with a letter.
  return /^[a-z]/.test(resource) ? `${resource}_id` : name;
}

function resourceIdTemplate(
  operations: Operation[],
  values: Record<string, string>,
): Record<string, string> {
  // Editor key -> the spec parameter names it stands for.
  const specNames = new Map<string, Set<string>>();
  for (const operation of operations) {
    for (const param of operation.params) {
      if (param.in !== "path" || typeof param.name !== "string") continue;
      const key = resourceIdName(operation.path, param.name);
      specNames.set(key, (specNames.get(key) ?? new Set()).add(param.name));
    }
  }
  const names = [...specNames.keys()].sort();
  const used = new Set<string>();
  return Object.fromEntries(names.map((name) => {
    const matchingKey = Object.prototype.hasOwnProperty.call(values, name)
      ? name
      : Object.keys(values).find(
          (key) => !used.has(key) && resourceKey(key) === resourceKey(name),
        );
    if (matchingKey) {
      used.add(matchingKey);
      return [name, values[matchingKey]];
    }
    // A value saved on the bare name (`{"id": ...}`) predates per-resource
    // keys; like the engine's fallback, it applies to every bare-id resource.
    const bare = [...(specNames.get(name) ?? [])].find(
      (spec) => spec !== name && Object.prototype.hasOwnProperty.call(values, spec),
    );
    return [name, bare ? values[bare] : ""];
  }));
}

/** The editor's text: blank until some ID is set, so an unused box reads as empty. */
function resourceIdsDraft(template: Record<string, string>): string {
  return Object.values(template).some((value) => value.trim())
    ? JSON.stringify(template, null, 2)
    : "";
}

/**
 * The spec box: operation count, the inline spec editor, and the per-operation
 * in-scope checkboxes.
 *
 * The editor's draft lives here, seeded from ``specText`` only when editing
 * starts — so the page's once-a-second poll can never overwrite what the user
 * is typing.
 */
function SpecPanelImpl({
  operations,
  specText,
  running,
  onSaveSpec,
  onSetOpEnabled,
  onSetAllOpsEnabled,
  predefinedResourceIds,
  onSetPredefinedResourceIds,
  specReport = null,
  specManaged = false,
}: {
  operations: Operation[];
  specText: string | null;
  /** The last parse's report; only a save returns one. */
  specReport?: SpecReport | null;
  running: boolean;
  onSaveSpec: (text: string) => Promise<void>;
  onSetOpEnabled: (opId: string, enabled: boolean) => void;
  onSetAllOpsEnabled: (enabled: boolean) => void;
  predefinedResourceIds: Record<string, string>;
  onSetPredefinedResourceIds: (values: Record<string, string>) => void;
  /** The project file owns the spec, so its editor is locked. */
  specManaged?: boolean;
}) {
  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState("");
  const [busy, setBusy] = useState(false);
  const pathParamNames = useMemo(
    () => Object.keys(resourceIdTemplate(operations, {})),
    [operations],
  );
  const pathParamSignature = pathParamNames.join("\u0000");
  // The spec's own names stay accepted too: a bare `{"id": ...}` predates
  // per-resource keys and the engine still applies it to every bare id.
  const acceptedNames = useMemo(
    () => new Set([
      ...pathParamNames,
      ...operations.flatMap((operation) =>
        operation.params
          .filter((param) => param.in === "path" && typeof param.name === "string")
          .map((param) => param.name as string),
      ),
    ]),
    [operations, pathParamNames],
  );
  const [resourceIdsText, setResourceIdsText] = useState(() =>
    resourceIdsDraft(resourceIdTemplate(operations, predefinedResourceIds)),
  );
  const [resourceIdsError, setResourceIdsError] = useState("");

  useEffect(() => {
    setResourceIdsText(resourceIdsDraft(resourceIdTemplate(operations, predefinedResourceIds)));
    setResourceIdsError("");
    // Only operation shape changes reset the editor; typing a value updates the
    // run options and must not reformat the user's in-progress JSON.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [pathParamSignature]);

  const total = operations.length;
  const on = operations.filter((o) => o.enabled).length;

  function updateResourceIds(text: string) {
    setResourceIdsText(text);
    try {
      const parsed: unknown = JSON.parse(text || "{}");
      if (!parsed || Array.isArray(parsed) || typeof parsed !== "object") {
        throw new Error("Use a JSON object.");
      }
      const entries = Object.entries(parsed);
      const unknown = entries.find(([name]) => !acceptedNames.has(name));
      if (unknown) throw new Error(`Unknown path parameter: ${unknown[0]}`);
      const invalid = entries.find(([, value]) => typeof value !== "string");
      if (invalid) throw new Error("Each resource ID must be a string.");
      // Empty values are placeholders in the SPEC editor, not IDs to send.
      onSetPredefinedResourceIds(
        Object.fromEntries(entries.filter(([, value]) => Boolean(value.trim()))),
      );
      setResourceIdsError("");
    } catch (error) {
      setResourceIdsError(error instanceof Error ? error.message : "Use a JSON object of path parameters.");
    }
  }

  async function save() {
    setBusy(true);
    try {
      await onSaveSpec(draft);
      setEditing(false);
      setDraft("");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="specbox">
      <div className="spec-head">
        <h2>Spec</h2>
        <span className="muted-sm">
          {on === total
            ? `${total} operation${total === 1 ? "" : "s"}`
            : `${on} of ${total} selected`}
        </span>
        <span className="grow" />
        {!running && !editing && (
          <>
            {specManaged && (
              <span className="muted-sm" title="The spec comes from the project file">
                set by runpentests.yml
              </span>
            )}
            <button
              className="btn quiet sm"
              onClick={() => {
                setDraft(specText ?? "");
                setEditing(true);
              }}
              disabled={specManaged}
              title={specManaged ? "The spec comes from the project file" : undefined}
            >
              Edit spec
            </button>
          </>
        )}
      </div>

      {specReport && <SpecReportView report={specReport} />}

      <div className="resource-id-editor">
        <div className="field-label">Predefined resource IDs</div>
        {pathParamNames.length > 0 ? (
          <>
            <p className="hint">
              Optional IDs for declared path parameters. Keys mirror the spec, except a
              bare <code>{"{id}"}</code>, which is named after its collection
              (<code>/monitors/{"{id}"}</code> is <code>monitor_id</code>); leave a value
              empty when the run should create that resource.
            </p>
            {!resourceIdsText.trim() && !running && (
              <button
                className="btn quiet sm resource-id-fill"
                type="button"
                onClick={() =>
                  setResourceIdsText(
                    JSON.stringify(resourceIdTemplate(operations, predefinedResourceIds), null, 2),
                  )
                }
              >
                Add IDs for {pathParamNames.length} path parameter
                {pathParamNames.length === 1 ? "" : "s"}
              </button>
            )}
            <ExpandingTextarea
              value={resourceIdsText}
              onChange={(e) => updateResourceIds(e.target.value)}
              placeholder="None — the run creates the resources it needs."
              rows={Math.min(6, Math.max(3, pathParamNames.length + 1))}
              spellCheck={false}
              disabled={running}
              aria-label="Predefined resource IDs for spec path parameters"
              aria-invalid={Boolean(resourceIdsError)}
            />
            {resourceIdsError && <span className="field-error">{resourceIdsError}</span>}
          </>
        ) : (
          <p className="hint">No path parameters are declared in this spec.</p>
        )}
      </div>

      {editing ? (
        <>
          <label className="field" style={{ marginTop: 10 }}>
            <span>Spec contents (JSON or YAML) — replaces the current operations</span>
            <ExpandingTextarea
              value={draft}
              onChange={(e) => setDraft(e.target.value)}
              placeholder={'{ "openapi": "3.0.0", "paths": { … } }'}
              spellCheck={false}
            />
          </label>
          <div className="actions">
            <button className="btn" onClick={save} disabled={busy || !draft.trim()}>
              {busy && <span className="spinner" aria-hidden="true" />}
              {busy ? "Saving…" : "Save spec"}
            </button>
            <label className="btn quiet">
              Load file…
              <input
                type="file"
                accept=".json,.yaml,.yml,application/json,text/yaml"
                className="visually-hidden"
                onChange={(e) => {
                  const f = e.target.files?.[0];
                  if (f) void f.text().then(setDraft);
                  e.target.value = "";
                }}
              />
            </label>
            <button
              className="btn quiet"
              onClick={() => setEditing(false)}
              disabled={busy}
            >
              Cancel
            </button>
          </div>
        </>
      ) : (
        total > 0 && (
          <details style={{ marginTop: 10 }}>
            <summary>Operations</summary>
            {!running && (
              <div className="oplist-head">
                <span className="hint">
                  Uncheck an endpoint to leave it out of the run.
                </span>
                <span className="oplist-bulk">
                  <button
                    type="button"
                    className="btn quiet sm"
                    onClick={() => onSetAllOpsEnabled(true)}
                  >
                    Select all
                  </button>
                  <button
                    type="button"
                    className="btn quiet sm"
                    onClick={() => onSetAllOpsEnabled(false)}
                  >
                    None
                  </button>
                </span>
              </div>
            )}
            <div className="oplist">
              {operations.map((o) =>
                running ? (
                  <div className={`op${o.enabled ? "" : " off"}`} key={o.id}>
                    <span className={`method ${o.method.toLowerCase()}`}>
                      {o.method}
                    </span>
                    <span className="p">{o.path}</span>
                    {o.auth_scope && <span className="scope">{o.auth_scope}</span>}
                  </div>
                ) : (
                  <label
                    className={`op selectable${o.enabled ? "" : " off"}`}
                    key={o.id}
                  >
                    <input
                      type="checkbox"
                      checked={o.enabled}
                      onChange={() => onSetOpEnabled(o.id, !o.enabled)}
                    />
                    <span className={`method ${o.method.toLowerCase()}`}>
                      {o.method}
                    </span>
                    <span className="p">{o.path}</span>
                    {o.auth_scope && <span className="scope">{o.auth_scope}</span>}
                  </label>
                ),
              )}
            </div>
          </details>
        )
      )}
    </div>
  );
}

export const SpecPanel = memo(SpecPanelImpl);
