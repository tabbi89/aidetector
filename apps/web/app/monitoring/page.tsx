"use client";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useCallback, useEffect, useState } from "react";
import { api, type EvidenceSource, type InfrastructureMonitor, type MonitoringRapidRun, type ScanSummary } from "@/lib/api";
import { SourceForm } from "./SourceForm";

/** What the index needs of a monitor beyond the monitor record itself. Nulls mean the read failed. */
type MonitorPulse = { alerts: number | null; rapid: MonitoringRapidRun[] | null };

function relativeTime(iso: string, now = Date.now()) {
  const then = new Date(iso).getTime();
  if (Number.isNaN(then)) return "";
  const minutes = Math.floor((now - then) / 60000);
  if (minutes < 1) return "just now";
  if (minutes < 60) return `${minutes} min ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours} h ago`;
  return `${Math.floor(hours / 24)} d ago`;
}

// The rapid check runs every 5 minutes; three missed runs is a stalled check.
const RAPID_STALE_MS = 20 * 60_000;

/** A scheduled, active monitor owes yesterday's UTC day; manual and paused ones owe nothing. */
const collectsDaily = (m: InfrastructureMonitor) => m.schedule_enabled && m.status === "active";

/** Whole UTC days a monitor's newest collected day trails yesterday's (0 when on time, manual, paused, or empty). */
function daysBehind(m: InfrastructureMonitor, now = Date.now()) {
  if (!collectsDaily(m) || !m.last_observation_date) return 0;
  const today = new Date(now).toISOString().slice(0, 10);
  const days = Math.round((Date.parse(`${today}T00:00:00Z`) - Date.parse(`${m.last_observation_date}T00:00:00Z`)) / 86_400_000);
  return Math.max(0, days - 1);
}

/** A daily monitor that has not produced yesterday's day: late, or nothing collected at all. */
const isBehind = (m: InfrastructureMonitor) => collectsDaily(m) && (daysBehind(m) > 0 || !m.last_observation_date);

/** The newest short-window run, if the monitor has any. */
function newestRapid(runs: MonitoringRapidRun[]) {
  return runs.reduce<MonitoringRapidRun | null>((newest, run) => (!newest || run.window_end > newest.window_end ? run : newest), null);
}

export default function MonitoringIndex() {
  const router = useRouter();
  const [sources, setSources] = useState<EvidenceSource[]>([]);
  const [monitors, setMonitors] = useState<InfrastructureMonitor[]>([]);
  const [scans, setScans] = useState<ScanSummary[]>([]);
  const [pulse, setPulse] = useState<Record<string, MonitorPulse>>({});
  const [loaded, setLoaded] = useState(false);
  const [examples, setExamples] = useState(false);
  const [contract, setContract] = useState<"none" | "spec" | "scan">("none");
  const [spec, setSpec] = useState("");
  const [target, setTarget] = useState("");
  const [error, setError] = useState(""); const [busy, setBusy] = useState(false);
  const loadPulse = useCallback(async (list: InfrastructureMonitor[]) => {
    // One read per monitor, in parallel; a monitor that fails reads as unknown ("?") rather
    // than taking the whole page down with it.
    const pairs = await Promise.all(list.map(async (m): Promise<[string, MonitorPulse]> => {
      try {
        const [alerts, runs] = await Promise.all([api.monitoringAlerts(m.id), api.listMonitoringRapidRuns(m.id)]);
        // The detail page shows alert episodes, not raw alerts: one unacknowledged alert per
        // state and day. Counting the same keys here keeps the two pages agreeing.
        const open = alerts.filter(a => !a.acknowledged);
        return [m.id, { alerts: new Set(open.map(a => `${a.state}|${a.observation_date}`)).size, rapid: runs }];
      } catch { return [m.id, { alerts: null, rapid: null }]; }
    }));
    setPulse(Object.fromEntries(pairs));
  }, []);
  const load = useCallback(async () => {
    try {
      const [s, m, sc] = await Promise.all([api.listEvidenceSources(), api.listMonitors(), api.listScans()]);
      setSources(s); setMonitors(m); setScans(sc); setError(""); setLoaded(true);
      void loadPulse(m);
    } catch (e) { setError((e as Error).message); }
  }, [loadPulse]);
  useEffect(() => {
    void load();
    api.health().then((h) => setExamples(h.examples)).catch(() => setExamples(false));
    const timer = setInterval(() => void load(), 60000);
    return () => clearInterval(timer);
  }, [load]);
  async function action(work: () => Promise<unknown>) {
    setBusy(true); try { await work(); await load(); } catch (e) { setError((e as Error).message); } finally { setBusy(false); }
  }
  async function open(work: () => Promise<InfrastructureMonitor>) {
    setBusy(true); setError("");
    try { const monitor = await work(); router.push(`/monitoring/${monitor.id}`); }
    catch (e) { setError((e as Error).message); setBusy(false); }
  }
  const leadsIn = (m: InfrastructureMonitor) => {
    const rapid = pulse[m.id]?.rapid;
    return rapid ? (newestRapid(rapid)?.observations.length ?? 0) : 0;
  };
  // A monitor with something to look at sorts to the top of the on-call scan.
  const needsAttention = (m: InfrastructureMonitor) => {
    const p = pulse[m.id];
    return !!p && ((p.alerts ?? 0) > 0 || leadsIn(m) > 0 || isBehind(m));
  };
  const ordered = [...monitors].sort((a, b) => (Number(needsAttention(b)) - Number(needsAttention(a))) || a.name.localeCompare(b.name));

  return <section className="wrap monitoring-page">
    <div className="monitor-intro">
      <div>
        <div className="eyebrow">Passive evidence</div><h1>Infrastructure monitoring</h1>
        <p className="lead">Compare daily AWS WAF traffic with its baseline and see which bots and AI crawlers reach your API. Observations are investigation leads; active scan findings keep their own proof and confidence.</p>
      </div>
      {examples && <button className="btn quiet" disabled={busy} onClick={() => void open(api.createExampleMonitor)}>Load example monitor</button>}
    </div>
    {error && <p className="monitor-error" role="alert">{error}</p>}

    <h2>Monitors</h2>
    {!monitors.length && <p>No monitors yet.</p>}
    {monitors.length > 0 && <div className="bot-table-wrap"><table className="bot-table">
      <thead><tr><th>Monitor</th><th>Open alerts</th><th>Last 5 minutes</th><th>Last day collected</th><th>Collection</th></tr></thead>
      <tbody>{ordered.map(m => {
        const p = pulse[m.id]; const rapid = p?.rapid ? newestRapid(p.rapid) : null; const leads = rapid?.observations.length ?? 0;
        const behind = daysBehind(m);
        return <tr key={m.id}>
          <td><Link href={`/monitoring/${m.id}`}><strong>{m.name}</strong></Link><small className="cell-sub">{m.target_binding}</small></td>
          <td>{!p || p.alerts === null ? "?" : p.alerts > 0 ? <span className="st-chip anomaly">{p.alerts}</span> : "—"}</td>
          <td>{!m.rapid_enabled ? "off" : !p || p.rapid === null ? "?" : !rapid ? "no data" : <>
            <span className={`st-chip ${leads ? "anomaly" : "baseline_ready"}`}>{rapid.pulse?.minutes === 5 ? `${rapid.pulse.requests} requests` : leads ? `${leads} lead${leads === 1 ? "" : "s"}` : "clear"}</span>
            {/* A stalled check reads exactly like a quiet pulse unless it says otherwise. */}
            {Date.now() - Date.parse(rapid.created_at) > RAPID_STALE_MS
              ? <small className="cell-sub stale">check stalled · ran {relativeTime(rapid.created_at)}</small>
              : <small className="cell-sub">{rapid.pulse?.attack_requests ? `${rapid.pulse.attack_requests} payload matches · ` : ""}{relativeTime(rapid.window_end)}</small>}
          </>}</td>
          <td>{m.last_observation_date ? <>{m.last_observation_date}{behind > 0
            ? <small className="cell-sub stale">{behind} day{behind === 1 ? "" : "s"} behind</small>
            : m.last_run_at && <small className="cell-sub">{relativeTime(m.last_run_at)}</small>}</>
            : <>never{isBehind(m)
              ? <small className="cell-sub stale">no day collected yet</small>
              : m.last_run_at && <small className="cell-sub">{relativeTime(m.last_run_at)}</small>}</>}</td>
          <td>{m.schedule_enabled ? "Daily" : "Manual"}{m.status === "paused" && <> <span className="st-chip degraded">paused</span></>}</td>
        </tr>;
      })}</tbody>
    </table></div>}

    <details className="monitor-card" open={loaded && !monitors.length}><summary>New monitor</summary>
    <form className="monitor-setup" onSubmit={e => {
      e.preventDefault(); const data = new FormData(e.currentTarget);
      const value = (name: string) => String(data.get(name) || "").trim();
      void open(() => api.setupMonitor({
        name: value("name"),
        target_binding: target.trim(),
        openapi: contract === "spec" ? spec : null,
        scan_id: contract === "scan" ? value("scan") : null,
        waf_log_group_arn: value("arn"),
        alb_arn: value("alb") || null,
        // Repository source comes from where the aidetector CLI runs now, not
        // a remote GitHub connector, so the web no longer collects one.
        github_repository: null,
        github_ref: "main",
        github_token: null,
        schedule_enabled: data.get("daily") === "on",
      }));
    }}>
      <p>Reads the AWS WAF log group with the worker&apos;s AWS credentials, so no keys go in here, and nothing is sent to the API. The server must allowlist the log group (<code>MONITORING_AWS_LOG_GROUPS</code>).</p>
      <div className="monitor-setup-grid">
        <label>Monitor name<input name="name" required maxLength={160} placeholder="pd_prod" /></label>
        <label>API base URL<input value={target} onChange={e => setTarget(e.target.value)} type="url" required placeholder="https://api.example.com" /></label>
      </div>
      <label>AWS WAF log group ARN<input name="arn" required spellCheck={false} placeholder="arn:aws:logs:us-west-2:123456789012:log-group:aws-waf-logs-prod:*" /></label>
      <label>Application Load Balancer ARN (optional)<input name="alb" spellCheck={false} placeholder="arn:aws:elasticloadbalancing:us-west-2:123456789012:loadbalancer/app/prod/50dc6c495c0c9188" /></label>
      <p>WAF logs record what the WAF did, not what your app answered. The load balancer&apos;s CloudWatch metrics add that per hour: response codes and latency. No access logging needed; the server must allowlist the load balancer (<code>MONITORING_AWS_LOAD_BALANCERS</code>) and the worker needs <code>cloudwatch:GetMetricData</code>.</p>
      <fieldset>
        <legend>API contract (optional)</legend>
        <div className="contract-mode">
          <label><input type="radio" name="contract" checked={contract === "none"} onChange={() => setContract("none")} /> None</label>
          <label><input type="radio" name="contract" checked={contract === "spec"} onChange={() => setContract("spec")} /> OpenAPI spec</label>
          <label><input type="radio" name="contract" checked={contract === "scan"} disabled={!scans.length} onChange={() => setContract("scan")} /> Spec from an existing scan</label>
        </div>
        {contract === "none" && <p>Routes are grouped by URL shape. Add a spec to name routes exactly and to enable the shadow-route and bot-on-authenticated-route leads.</p>}
        {contract === "spec" && <>
          <label>Spec file<input type="file" accept=".json,.yaml,.yml,application/json,text/yaml" onChange={async e => { const file = e.target.files?.[0]; if (file) setSpec(await file.text()); }} /></label>
          <label>Spec contents<textarea value={spec} onChange={e => setSpec(e.target.value)} required spellCheck={false} placeholder={'{ "openapi": "3.0.0", "paths": { ... } }'} /></label>
        </>}
        {contract === "scan" && <label>Scan<select name="scan" required defaultValue="" onChange={e => { const scan = scans.find(s => s.id === e.target.value); if (scan) setTarget(scan.target_base_url); }}>
          <option value="" disabled>Select a scan</option>
          {scans.map(s => <option key={s.id} value={s.id}>{s.target_base_url} · {new Date(s.created_at).toLocaleDateString()}</option>)}
        </select></label>}
      </fieldset>
      <label className="monitor-check"><input type="checkbox" name="daily" defaultChecked /> Collect the previous UTC day every day after 02:00 UTC</label>
      <p>Seven complete days build the baseline before leads are raised. The AI and bot view needs AWS WAF Bot Control labels in the logs.</p>
      <button className="btn" disabled={busy}>{busy ? "Creating…" : "Create monitor"}</button>
    </form></details>

    <details className="monitor-advanced">
      <summary>Advanced: individual evidence sources</summary>
      <div className="monitor-grid"><SourceForm onSaved={() => void load()} onError={setError} />
        <form className="monitor-card" onSubmit={e => {
          e.preventDefault(); const form = e.currentTarget; const data = new FormData(form);
          const source = sources.find(s => s.id === data.get("source")); if (!source) return;
          void action(async () => { await api.createMonitor({ name: String(data.get("name")), target_binding: source.target_binding,
            source_ids: [source.id], schedule_enabled: data.get("daily") === "on" }); form.reset(); });
        }}>
          <h2>Monitor from a source</h2><label>Monitor name<input name="name" required maxLength={160} /></label>
          <label>Traffic source<select name="source" required><option value="">Select source</option>{sources.filter(s => s.connector !== "github" && s.status !== "revoked").map(s => <option value={s.id} key={s.id}>{s.name}</option>)}</select></label>
          <label className="monitor-check"><input type="checkbox" name="daily" /> Enable daily collection</label>
          <p>JSON sources need an uploaded snapshot per day. AWS collection starts after 02:00 UTC and rechecks three days for late logs.</p>
          <button className="btn" disabled={busy}>Create monitor</button>
        </form>
      </div>
      <h2>Evidence sources</h2>{!sources.length && <p>No sources yet.</p>}
      {sources.map(s => <article className="monitor-card" key={s.id}>
        <h3>{s.name}</h3><p>{s.connector} · {s.status} · revision {s.revision}{s.connector === "aws_cloudwatch" && !s.has_credentials ? " · worker credentials" : ""}</p><p>{s.target_binding}</p>
        {s.error_code && <p role="status">Source unavailable: {s.error_code}</p>}
        <div className="monitor-actions"><button className="btn quiet" disabled={busy || s.status === "revoked"} onClick={() => void action(() => api.revokeEvidenceSource(s.id))}>Revoke source</button>
        <button className="btn quiet" disabled={busy} onClick={() => { if (window.confirm(`Delete ${s.name} and its retained monitoring evidence?`)) void action(() => api.deleteEvidenceSource(s.id)); }}>Delete source and evidence</button></div>
      </article>)}
    </details>
  </section>;
}
