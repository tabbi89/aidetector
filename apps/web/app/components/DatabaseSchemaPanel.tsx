"use client";

import { useCallback, useEffect, useState } from "react";
import { api, type SchemaContext, type SchemaSnapshotSummary } from "@/lib/api";
import { Ago, CopyButton } from "./ui";
import { PlanBadge } from "./PlanBadge";

const REASONS: Record<string, string> = {
  password_missing: "No password supplied on the CLI machine",
  connection_unavailable: "Could not connect",
  destination_not_allowed: "Destination is not allowed",
  table_unavailable: "Table or schema not found",
  metadata_limit: "Schema metadata exceeds the safe limit",
  tls_ca_unconfigured: "verify-full needs sslrootcert",
  ambient_service_forbidden: "PGSERVICE is set on the CLI machine",
  invalid_upload: "The runner's snapshot was rejected",
};

const PRIVILEGED = "This credential has broader database privileges. The scanner still uses fixed, "
  + "read-only catalog queries, but a dedicated metadata account limits exposure if "
  + "the credential is ever compromised.";

const EXAMPLE = `schema:
  host: localhost
  database: app
  username: schema_reader
  password_env: APP_SCHEMA_PASSWORD
  sslmode: disable        # verify-full + sslrootcert for a remote database
  tables: [public.accounts, public.widgets]`;

function plural(count: number, noun: string) {
  return `${count} ${noun}${count === 1 ? "" : "s"}`;
}

function reasonLabel(reason: string | null) {
  if (!reason) return "unknown reason";
  return REASONS[reason] ?? reason.replaceAll("_", " ");
}

function Snapshot({ snapshot }: { snapshot: SchemaSnapshotSummary }) {
  return (
    <>
      <div className="schema-status schema-snapshot ready">
        <span className="schema-status-dot" aria-hidden="true" />
        <span>
          Snapshot from local run #{snapshot.run_number} · <Ago iso={snapshot.captured_at} />
        </span>
      </div>
      {snapshot.warnings.includes("privileged_account") && (
        <div className="schema-warning" role="status">{PRIVILEGED}</div>
      )}
      {snapshot.tables.length > 0 ? (
        <ul className="schema-tables">
          {snapshot.tables.map((table) => (
            <li key={`${table.schema_name}.${table.table_name}`}>
              <code>{table.schema_name}.{table.table_name}</code>
              <span className="muted-sm">
                · {plural(table.column_count, "column")} · {plural(table.constraint_count, "key")}
              </span>
            </li>
          ))}
        </ul>
      ) : (
        <p className="muted-sm">The snapshot lists no tables.</p>
      )}
    </>
  );
}

export function DatabaseSchemaPanel({ scanId, running }: { scanId: string; running: boolean }) {
  const [context, setContext] = useState<SchemaContext | null>(null);
  const [forgetting, setForgetting] = useState(false);
  const [message, setMessage] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const value = await api.getSchemaContext(scanId);
      setContext(value);
      return value;
    } catch (error) {
      setMessage((error as Error).message);
      return undefined;
    }
  }, [scanId]);

  useEffect(() => { void load(); }, [load]);

  const snapshot = context?.snapshot ?? null;
  const latest = context?.latest ?? null;
  const unavailable = latest?.status === "unavailable"
    && (!snapshot || latest.run_number > snapshot.run_number);

  async function forget() {
    setForgetting(true); setMessage(null);
    try {
      const deleted = await api.deleteSchemaContext(scanId);
      await load();
      setMessage(deleted.removed === 1 ? "Snapshot forgotten." : `${deleted.removed} snapshots forgotten.`);
    } catch (error) { setMessage((error as Error).message); }
    finally { setForgetting(false); }
  }

  return (
    <div className="specbox schema-panel">
      <div className="spec-head">
        <h2>Schema context</h2>
        <PlanBadge premium />
        <span className="muted-sm">PostgreSQL · read-only</span>
      </div>

      <div className="schema-intro">
        <p>
          Read by <code>runpentests</code> from the <code>schema:</code> block in{" "}
          <code>runpentests.yml</code>. The password stays on that machine; only table and
          column structure is uploaded. Values and rows are never read.
        </p>
      </div>

      {snapshot && <Snapshot snapshot={snapshot} />}

      {unavailable && latest && (
        <div className="schema-status schema-snapshot unavailable">
          <span className="schema-status-dot" aria-hidden="true" />
          <span>Local run #{latest.run_number} could not read the schema: {reasonLabel(latest.reason)}</span>
        </div>
      )}

      {context && !snapshot && !unavailable && (
        <div className="schema-empty">
          <p>No schema snapshot yet. Add it to runpentests.yml:</p>
          <div className="cli-command">
            <pre className="shell">{EXAMPLE}</pre>
            <CopyButton value={EXAMPLE} label="Copy runpentests.yml example" />
          </div>
          <p>then run <code>runpentests</code>.</p>
        </div>
      )}

      {message && <p className="schema-message" role="status">{message}</p>}

      {(snapshot || latest) && (
        <div className="actions">
          <button className="btn quiet danger-text" onClick={forget} disabled={forgetting || running}>
            {forgetting ? "Forgetting…" : "Forget snapshot"}
          </button>
        </div>
      )}
    </div>
  );
}
