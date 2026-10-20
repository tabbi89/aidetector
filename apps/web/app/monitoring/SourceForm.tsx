"use client";
import { useState } from "react";
import { api, type EvidenceSourceInput } from "@/lib/api";

export function SourceForm({ onSaved, onError }: { onSaved: () => void; onError: (error: string) => void }) {
  const [connector, setConnector] = useState<NonNullable<EvidenceSourceInput["connector"]>>("json_snapshot");
  const [busy, setBusy] = useState(false);
  return <form className="monitor-card" onSubmit={async (event) => {
    event.preventDefault(); const form = event.currentTarget; const fields = new FormData(form);
    const value = (name: string) => String(fields.get(name) || "").trim();
    const input: EvidenceSourceInput = { name: value("name"), target_binding: value("target"), connector };
    if (connector === "aws_cloudwatch") {
      input.config = { region: value("region"), log_group: value("group"), account_id: value("account") || null };
      // No keys: the worker's AWS credential chain signs the read.
      if (value("key") || value("secret")) {
        input.credentials = { access_key_id: value("key"), secret_access_key: value("secret"), session_token: value("session") || null };
      }
    } else if (connector === "github") {
      const paths = value("paths").split("\n").map(s => s.trim()).filter(Boolean);
      input.config = { repository: value("repository"), ref: value("ref") || null, commit: value("commit") || null, paths };
      if (value("token")) input.credentials = { github_token: value("token") };
    }
    setBusy(true);
    try { await api.createEvidenceSource(input); form.reset(); onSaved(); }
    catch (error) { onError((error as Error).message); }
    finally { setBusy(false); }
  }}>
    <h2>Add evidence source</h2>
    <label>Name<input name="name" required maxLength={160} /></label>
    <label>API base URL<input name="target" type="url" required placeholder="https://api.example.com" /></label>
    <label>Source type<select value={connector} onChange={e => setConnector(e.target.value as typeof connector)}>
      <option value="json_snapshot">JSON log upload</option><option value="aws_cloudwatch">AWS CloudWatch logs</option><option value="github">GitHub repository context</option>
    </select></label>
    {connector === "aws_cloudwatch" && <>
      <p>Reads are signed with the worker&apos;s AWS credential chain, so no keys are needed. The log group must be listed in <code>MONITORING_AWS_LOG_GROUPS</code>.</p>
      <label>AWS region<input name="region" required placeholder="us-west-2" /></label>
      <label>Log group<input name="group" required placeholder="aws-waf-logs-production" /></label>
      <label>AWS account ID (optional)<input name="account" inputMode="numeric" pattern="[0-9]{12}" placeholder="123456789012" /></label>
      <details><summary>Use access keys instead</summary>
        <label>Access key ID<input name="key" type="password" autoComplete="off" /></label>
        <label>Secret access key<input name="secret" type="password" autoComplete="off" /></label>
        <label>Session token (optional)<input name="session" type="password" autoComplete="off" /></label>
      </details>
    </>}
    {connector === "github" && <>
      <p>A branch is read on demand by the AI explainer through read-only GitHub MCP, using this source&apos;s own token.</p>
      <label>Repository<input name="repository" required placeholder="owner/repository" /></label>
      <label>Branch or tag<input name="ref" placeholder="main" /></label>
      <label>Fine-grained token, Contents: read-only on this repository<input name="token" type="password" autoComplete="off" /></label>
      <details><summary>Pin exact files at a commit (optional)</summary>
        <p>Only route metadata from these files is retained.</p>
        <label>Commit SHA<input name="commit" pattern="[0-9a-f]{40}" placeholder="Full 40-character commit SHA" /></label>
        <label>File paths (one per line, up to 10)<textarea name="paths" placeholder="src/routes.py" /></label>
      </details>
    </>}
    <button className="btn" disabled={busy}>{busy ? "Saving…" : "Save source"}</button>
  </form>;
}
