"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { use, useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  NO_RUN_OPTIONS,
  api,
  managedFields,
  type CheckKey,
  type Finding,
  type FindingWork,
  type FindingWorkInput,
  type ManagedConfig,
  type ManagedField,
  type RunOptions,
  type Scan,
  type Severity,
  type SpecReport,
  type Verdict,
} from "@/lib/api";
import { useUrlState } from "@/lib/useUrlState";
import { usePageTitle } from "../../components/usePageTitle";
import { ErrorBanner, Skel } from "../../components/ui";
import { ActivityLog, stageLabel } from "./ActivityLog";
import { AiCostPanel } from "./AiCostPanel";
import { CredentialsPanel } from "../../components/CredentialsPanel";
import { ResultsWorkspace } from "./ResultsWorkspace";
import { GAP_STAGES } from "./RunInsights";
import { ConfigurationWorkspace } from "../../components/ConfigurationWorkspace";
import { DatabaseSchemaPanel } from "../../components/DatabaseSchemaPanel";
import { RunPanel } from "../../components/RunPanel";
import {
  OwnershipNotice,
  useTargetOwnership,
  verifiedHostOf,
} from "../../components/OwnershipNotice";
import { withPresetPasses } from "../../components/checkScope";
import { useCapabilities } from "../../components/useCapabilities";
import { AttentionSummary } from "./AttentionSummary";
import { RequestRatePanel } from "./RequestRatePanel";
import { ScanHeader } from "./ScanHeader";
import { useFindings, useRunResources, useScanProgress } from "./useScanData";
import { SchedulePanel } from "./SchedulePanel";
import { SpecPanel } from "./SpecPanel";
import { ACTIVE, type CredForm } from "../../components/scanShared";

/**
 * The project file a CLI run last recorded, or null when the web owns every
 * setting. The `{}` the API sends then is typed as an index signature, so a
 * property check alone narrows nothing — this guard reads the runtime shape.
 */
/** Host first, so a long URL does not fill the tab. */
function scanTitle(url: string | undefined): string | null {
  if (!url) return null;
  try {
    return `Scan · ${new URL(url).host}`;
  } catch {
    return `Scan · ${url}`;
  }
}

function managedConfigOf(scan: Scan | null): ManagedConfig | null {
  const config = scan?.managed_config as unknown as Partial<ManagedConfig> | undefined;
  return typeof config?.path === "string" ? (config as ManagedConfig) : null;
}

/** The managed fields in the order the API declares them, as plain words. */
const MANAGED_ORDER: ManagedField[] = [
  "target",
  "spec",
  "identities",
  "requests_per_second",
  "run_options",
];

/** "target URL, identities alice + bob, request rate" — the banner's list. */
function managedSummary(config: ManagedConfig): string {
  const words: Record<ManagedField, string> = {
    target: "target URL",
    spec: "API spec",
    identities: config.identities.length
      ? `identities ${config.identities.join(", ")}`
      : "identities",
    requests_per_second: "request rate",
    run_options: "run options",
  };
  const owned = MANAGED_ORDER.filter((field) => config.fields.includes(field));
  return owned.map((field) => words[field]).join(", ");
}

function scheduleSummary(minutes: number | null): string {
  if (minutes === 60) return "Hourly";
  if (minutes === 360) return "Every 6 hours";
  if (minutes === 1440) return "Daily";
  return minutes ? `Every ${minutes} minutes` : "Off";
}

/**
 * Scan detail: polls the scan while it runs and composes the panels.
 *
 * This component owns only the server data and the actions that mutate it.
 * Everything view-local — filters, drafts, form state — lives inside the panel
 * that uses it.
 */
export default function ScanDetail({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = use(params);
  const router = useRouter();

  const progress = useScanProgress(id);
  const { scan, events, connected, staleSeconds, notFound, setScan } = progress;
  usePageTitle(scanTitle(scan?.target_base_url));
  const running = scan ? ACTIVE.has(scan.status) : false;
  const verifiedHost = verifiedHostOf(useTargetOwnership(id, scan?.target_base_url ?? ""));

  // Findings grow during a run, but far slower than the progress line, so they
  // refresh on their own slow tick instead of riding the 1s poll.
  const findingsData = useFindings(id, running);
  const { findings, failed: findingsFailed, setFindings, refreshSummary } = findingsData;

  const { get: getUrl, set: setUrl } = useUrlState();
  const tab = getUrl("tab") ?? "findings";
  const setTab = useCallback(
    (next: string) => setUrl({ tab: next === "findings" ? null : next }),
    [setUrl],
  );
  // AI usage lives in the *configuration* workspace, not the results tabs, so
  // it needs its own selected-section state to know when to fetch the ledger.
  const configTab = getUrl("ctab") ?? "spec";
  const setConfigTab = useCallback(
    (next: string) => setUrl({ ctab: next === "spec" ? null : next }),
    [setUrl],
  );
  // The run-derived reads are cached by the hook; costs are only wanted while
  // the AI panel is open. Runs are always wanted because several section metas
  // and the attention summary read the latest run.
  const wanted = useMemo(
    () => ({ runs: true, diff: true, cost: configTab === "ai" }),
    [configTab],
  );
  const runResources = useRunResources(id, wanted);
  const { runs, diff, cost } = runResources;
  // How many distinct AI steps spent tokens; the panel names them, never the model.
  const aiSteps = useMemo(
    () => new Set((cost?.entries ?? []).map((e) => e.phase)).size,
    [cost],
  );
  const failed = useMemo(
    () => ({
      cost: runResources.failed.cost,
      findings: findingsFailed,
      runs: runResources.failed.runs,
      diff: runResources.failed.diff,
    }),
    [runResources.failed, findingsFailed],
  );
  // A scan that has not answered yet is still loading; a 404 or a read error
  // is a page state, not a skeleton.
  const loaded = scan !== null || notFound || progress.error !== null;

  const capabilities = useCapabilities();
  // Unknown entitlement allows the panel; the API's 402 is the truth, and the
  // panel would otherwise stay hidden during the first probe.
  const collaborationEnabled = capabilities.premium
    ? capabilities.premium.available
    : true;

  // A run's record changes exactly at its status boundaries: starting one
  // resets runs/diff, finishing one appends coverage, traces and findings.
  // Without this, a page watched through completion keeps the pre-run answers.
  const previousRunning = useRef<boolean | null>(null);
  // Stable callbacks: the hook objects are rebuilt every render, their
  // refresh functions are not.
  const refreshFindings = findingsData.refresh;
  const refreshResources = runResources.refresh;
  useEffect(() => {
    const was = previousRunning.current;
    previousRunning.current = running;
    if (was === null || was === running) return;
    void refreshFindings();
    refreshResources();
  }, [running, refreshFindings, refreshResources]);

  const [err, setErr] = useState<string | null>(null);
  useEffect(() => {
    if (progress.error) setErr(progress.error);
  }, [progress.error]);

  // Assignment and discussion, loaded once after the scan and refreshed after
  // each mutation — deliberately outside the 1s progress poll.
  const [work, setWork] = useState<Map<string, FindingWork>>(new Map());
  const workLoaded = useState(() => ({ done: false }))[0];
  const refreshWork = useCallback(async () => {
    try {
      const items = await api.listWork(id);
      setWork(new Map(items.map((item) => [item.fingerprint, item])));
    } catch {
      // Optional read: leave the panel editable rather than blanking the page.
      // A mutation reports its own failure inline.
    }
  }, [id]);
  useEffect(() => {
    if (!scan || workLoaded.done || !collaborationEnabled) return;
    workLoaded.done = true;
    void refreshWork();
  }, [scan, workLoaded, refreshWork, collaborationEnabled]);

  const [runPanelOpen, setRunPanelOpen] = useState(false);
  // Starts quick: every check, with writes and AI off until switched on.
  const [runOptions, setRunOptions] = useState<RunOptions>(() =>
    withPresetPasses(NO_RUN_OPTIONS, "all"),
  );
  // The schedule panel saves these options too, so a tool this deployment
  // cannot run is dropped from the defaults before either panel is opened.
  // The hook shares one probe with the entitlement check above.
  useEffect(() => {
    const off = new Set(
      Object.entries(capabilities.passes)
        .filter(([, p]) => p?.available === false)
        .map(([k]) => k),
    );
    if (off.size) setRunOptions((current) => withPresetPasses(current, "all", off));
  }, [capabilities.passes]);
  // What the last spec upload parsed; only the upload response carries it.
  const [specReport, setSpecReport] = useState<SpecReport | null>(null);
  const [runBusy, setRunBusy] = useState(false);
  const [cancelling, setCancelling] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [handingBack, setHandingBack] = useState(false);

  // The attention rows narrow the findings list. FindingsSection is already
  // mounted, so the request carries a nonce: a second click on the same
  // severity must apply again.
  const [focusRequest, setFocusRequest] = useState<{
    sev?: Severity;
    dismissed?: boolean;
    nonce: number;
  }>({ nonce: 0 });
  const focusFindings = useCallback(
    (sev: Severity) => {
      setFocusRequest((prev) => ({ sev, nonce: prev.nonce + 1 }));
      setTab("findings");
      setUrl({ tab: null, sev });
    },
    [setTab, setUrl],
  );
  const focusDismissed = useCallback(() => {
    setFocusRequest((prev) => ({ dismissed: true, nonce: prev.nonce + 1 }));
    setTab("findings");
    setUrl({ tab: null, dismissed: "1" });
  }, [setTab, setUrl]);

  // Re-read everything an action may have changed. The progress poll is
  // cheap and immediate; findings and the run-derived reads are refreshed
  // explicitly because their own cadence is slow or on demand.
  const reload = useCallback(async () => {
    await Promise.all([progress.reload(), findingsData.refresh()]);
    runResources.refresh();
  }, [progress, findingsData, runResources]);

  // Work-item mutations update the map in place, so the panel does not wait
  // for a refetch. They reject to the panel, which shows the message inline.
  const saveWork = useCallback(
    async (fingerprint: string, input: FindingWorkInput) => {
      const item = await api.saveWork(id, fingerprint, input);
      setWork((prev) => new Map(prev).set(fingerprint, item));
    },
    [id],
  );
  const removeWork = useCallback(
    async (fingerprint: string) => {
      await api.deleteWork(id, fingerprint);
      // The assignment is gone; the discussion is not. Re-read so the row
      // comes back as the API now returns it — unassigned, still commented.
      await refreshWork();
    },
    [id, refreshWork],
  );
  const addComment = useCallback(
    async (fingerprint: string, body: string) => {
      const comment = await api.addComment(id, fingerprint, body);
      setWork((prev) => {
        // A comment can exist before anyone is assigned: synthesize the same
        // unassigned "open" item the API returns rather than dropping it.
        const current: FindingWork = prev.get(fingerprint) ?? {
          scan_id: id,
          fingerprint,
          owner: null,
          due_date: null,
          status: "open",
          updated_at: comment.created_at,
          comments: [],
        };
        const next = new Map(prev);
        next.set(fingerprint, {
          ...current,
          comments: [...current.comments, comment],
        });
        return next;
      });
    },
    [id],
  );
  const removeComment = useCallback(
    async (commentId: string) => {
      await api.deleteComment(id, commentId);
      setWork((prev) => {
        const next = new Map(prev);
        for (const [fingerprint, item] of next) {
          if (!item.comments.some((comment) => comment.id === commentId)) continue;
          next.set(fingerprint, {
            ...item,
            comments: item.comments.filter((comment) => comment.id !== commentId),
          });
        }
        return next;
      });
    },
    [id],
  );

  // Retest narrows the scope to one check and opens the existing panel. It
  // never starts a run: the authorization checkbox is still the gate.
  const retest = useCallback((check: string) => {
    setRunOptions((current) => ({ ...current, checks: [check as CheckKey] }));
    setRunPanelOpen(true);
    requestAnimationFrame(() =>
      document.getElementById("run-panel")?.scrollIntoView({ block: "start" }),
    );
  }, []);

  const fail = useCallback((e: unknown) => setErr((e as Error).message), []);

  const schedule = useCallback(
    async (minutes: number | null, authorized: boolean) => {
      try {
        setScan(
          await api.setSchedule(
            id,
            minutes,
            { ...runOptions, requests_per_second: scan?.requests_per_second ?? 10 },
            authorized,
          ),
        );
      } catch (e) {
        fail(e);
      }
    },
    [id, runOptions, scan?.requests_per_second, fail, setScan],
  );

  const saveRequestRate = useCallback(
    async (requestsPerSecond: number) => {
      setErr(null);
      try {
        setScan(await api.setRequestRate(id, requestsPerSecond));
      } catch (e) {
        fail(e);
        throw e;
      }
    },
    [id, fail, setScan],
  );

  const cancel = useCallback(async () => {
    setCancelling(true);
    try {
      await api.cancelScan(id);
      await reload();
    } catch (e) {
      setCancelling(false);
      fail(e);
    }
  }, [id, reload, fail]);

  const destroy = useCallback(async () => {
    // Irreversible: the scan's spec, credentials, findings and run history go
    // with it. The API refuses this while the scan is active.
    const n = findings.length;
    const msg =
      `Delete this scan permanently?\n\n${scan?.target_base_url ?? ""}\n\n` +
      `Its spec, credential profiles, ${n} finding${n === 1 ? "" : "s"} and run ` +
      `history are removed. This cannot be undone.`;
    if (!window.confirm(msg)) return;
    setDeleting(true);
    setErr(null);
    try {
      await api.deleteScan(id);
      router.push("/scans");
    } catch (e) {
      setDeleting(false);
      fail(e);
    }
  }, [id, findings.length, scan?.target_base_url, router, fail]);

  const saveSpec = useCallback(
    async (text: string) => {
      setErr(null);
      try {
        const { spec_report, ...updated } = await api.uploadSpec(id, text);
        setScan(updated);
        setSpecReport(spec_report);
      } catch (e) {
        fail(e);
        throw e; // keep the editor open so the draft isn't lost
      }
    },
    [id, fail, setScan],
  );

  const saveTarget = useCallback(
    async (url: string) => {
      setErr(null);
      try {
        setScan(await api.updateScan(id, url));
      } catch (e) {
        fail(e);
        throw e;
      }
    },
    [id, fail, setScan],
  );

  // Enable/disable which operations are in scope for the (re-)run.
  const setOpEnabled = useCallback(
    async (opId: string, enabled: boolean) => {
      setErr(null);
      try {
        setScan(await api.setOperations(id, [{ id: opId, enabled }]));
      } catch (e) {
        fail(e);
      }
    },
    [id, fail, setScan],
  );

  const setAllOpsEnabled = useCallback(
    async (enabled: boolean) => {
      if (!scan) return;
      setErr(null);
      try {
        setScan(
          await api.setOperations(
            id,
            scan.operations.map((o) => ({ id: o.id, enabled })),
          ),
        );
      } catch (e) {
        fail(e);
      }
    },
    [id, scan, fail, setScan],
  );

  const saveCred = useCallback(
    async (form: CredForm, editingId: string | null) => {
      setErr(null);
      try {
        if (editingId) {
          await api.updateCredential(id, editingId, form);
        } else {
          await api.addCredential(id, form);
        }
        setScan(await api.getScan(id));
      } catch (e) {
        fail(e);
        throw e; // keep the form open with the user's input
      }
    },
    [id, fail, setScan],
  );

  const removeCred = useCallback(
    async (credId: string) => {
      if (!window.confirm("Remove this credential profile?")) return;
      setErr(null);
      try {
        await api.deleteCredential(id, credId);
        setScan(await api.getScan(id));
      } catch (e) {
        fail(e);
      }
    },
    [id, fail, setScan],
  );

  const doRun = useCallback(async () => {
    setRunBusy(true);
    setCancelling(false);
    setErr(null);
    try {
      await api.runScan(id, true, {
        ...runOptions,
        requests_per_second: scan?.requests_per_second ?? 10,
      });
      setRunPanelOpen(false);
      await reload();
    } catch (e) {
      fail(e);
    } finally {
      setRunBusy(false);
    }
  }, [id, runOptions, scan?.requests_per_second, reload, fail]);

  const mark = useCallback(
    async (f: Finding, verdict: Verdict): Promise<Finding | null> => {
      // Clicking the active verdict clears it.
      const next = f.verdict === verdict ? "unreviewed" : verdict;
      let updated: Finding;
      try {
        updated = await api.setVerdict(id, f.id, next);
      } catch (e) {
        fail(e);
        return null;
      }
      setFindings((prev) => prev.map((x) => (x.id === f.id ? updated : x)));
      // A verdict changes what "needs attention" counts; a terminal scan no
      // longer polls, so the summary has to be asked for explicitly.
      await refreshSummary();
      return updated;
    },
    [id, fail, setFindings, refreshSummary],
  );

  // The project file a CLI run last recorded, or null when the web owns every
  // setting — the API answers `{}` then, which has no path to show.
  const managedConfig = useMemo(() => managedConfigOf(scan), [scan]);
  // Set once per poll so the memoised panels below are not re-rendered by a
  // freshly built set on every tick.
  const managed = useMemo(
    () => (scan ? managedFields(scan) : new Set<ManagedField>()),
    [scan],
  );
  const managedIdentities = useMemo(
    () => managedConfig?.identities ?? [],
    [managedConfig],
  );

  const handBack = useCallback(async () => {
    // The CLI owns these settings again the moment it runs from the file, so
    // the handover is confirmed rather than fired by a stray click.
    if (
      !window.confirm(
        "Let the web own these settings again?\n\nThe next CLI run from that file will manage them once more.",
      )
    ) {
      return;
    }
    setErr(null);
    setHandingBack(true);
    try {
      setScan(await api.clearManagedConfig(id));
    } catch (e) {
      fail(e);
    } finally {
      setHandingBack(false);
    }
  }, [id, fail, setScan]);

  const toggleRunPanel = useCallback(() => setRunPanelOpen((v) => !v), []);
  const closeRunPanel = useCallback(() => setRunPanelOpen(false), []);
  const clearErr = useCallback(() => setErr(null), []);

  // Distinct auth scopes the spec's operations demand — hints for profiles.
  const specScopes = useMemo(() => {
    const s = new Set<string>();
    for (const o of scan?.operations ?? []) {
      for (const part of (o.auth_scope ?? "").split(",")) {
        const t = part.trim();
        if (t) s.add(t);
      }
    }
    return [...s].sort();
  }, [scan]);

  // Per-endpoint coverage rides along on the newest run. Findings first, then
  // the busiest endpoints.
  const coverage = useMemo(() => {
    const rows = runs[0]?.coverage ?? [];
    return [...rows].sort(
      (a, b) =>
        b.findings - a.findings ||
        b.requests - a.requests ||
        a.path.localeCompare(b.path),
    );
  }, [runs]);

  // AI pre-scan plan (present only when the run used plan:true), highest risk first.
  const plan = useMemo(() => runs[0]?.plan ?? [], [runs]);

  // Resources the setup pass created or accepted from the run configuration.
  const resources = useMemo(() => runs[0]?.resources ?? [], [runs]);
  // The latest run's request log is fetched by the panel that shows it — a run
  // archives one row per call, so the rows never ride along with the run list.
  // Steps the run could not do, from the engine's own events. Deduplicated
  // because a re-run replaces events but a poll may show both.
  const gaps = useMemo(() => {
    const seen = new Set<string>();
    return events.filter((e) => {
      if (!GAP_STAGES.has(e.stage)) return false;
      const key = `${e.stage}|${e.message}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
  }, [events]);

  // Tools the run was asked for but the API reports as not run.
  const notRun = useMemo(() => runs[0]?.gaps?.not_run ?? [], [runs]);

  // Why an AI step the run asked for recorded no spend. The AI panels quote this
  // rather than implying the feature was off.
  const aiSkip = useMemo(() => {
    const options = runs[0]?.options ?? {};
    const passes: [string, string][] = [
      ["plan", "plan_skipped"],
      ["adjudicate", "ai_skipped"],
      ["security_review", "security_review_skipped"],
      ["genai_payloads", "genai_payloads_skipped"],
    ];
    for (const [option, stage] of passes) {
      if (options[option] !== true) continue;
      const event = [...events].reverse().find((e) => e.stage === stage);
      if (event) return event.message;
    }
    return null;
  }, [runs, events]);

  const traceCount = runs[0]?.trace_count ?? 0;
  const latestRun = runs[0]?.run_number ?? null;

  const latest = events.length ? events[events.length - 1] : null;
  const progressMessage = latest
    ? `${stageLabel(latest.stage)} — ${latest.message}`
    : null;

  if (!loaded) {
    return (
      <section className="wrap section" aria-busy="true">
        <div className="crumbs">
          <Link href="/scans">Scans</Link>
          <span className="sep" aria-hidden="true">›</span>
          <span>Scan</span>
        </div>
        <div style={{ maxWidth: 380, marginTop: 12 }}>
          <Skel h={30} />
        </div>
        <div style={{ marginTop: 20, maxWidth: 460 }}>
          <Skel h={20} />
        </div>
        <div style={{ marginTop: 24, maxWidth: 780 }}>
          <Skel h={78} r={12} />
        </div>
      </section>
    );
  }

  if (notFound) {
    return (
      <section className="wrap section">
        <div className="crumbs">
          <Link href="/scans">Scans</Link>
          <span className="sep" aria-hidden="true">›</span>
          <span>Scan</span>
        </div>
        <div className="specbox scan-missing">
          <h2>Scan not found</h2>
          <p>
            No scan has this id — it was deleted, or the link belongs to another
            workspace.
          </p>
          <Link className="btn sm" href="/scans">Back to scans</Link>
        </div>
      </section>
    );
  }

  return (
    <section className="wrap section scan-detail">
      <ScanHeader
        id={id}
        scan={scan}
        running={running}
        connected={connected}
        staleSeconds={staleSeconds}
        findingsCount={findings.length}
        progressMessage={progressMessage}
        cancelling={cancelling || !!scan?.cancel_requested}
        deleting={deleting}
        onSaveTarget={saveTarget}
        targetManaged={managed.has("target")}
        onToggleRunPanel={toggleRunPanel}
        onCancel={cancel}
        onDelete={destroy}
      />

      {err && <ErrorBanner message={err} onClose={clearErr} />}

      {scan && (
        <>
          {managedConfig && managed.size > 0 && (
            <div className="banner info" role="status">
              <div>
                <strong>
                  Settings managed by {managedConfig.path}
                  {managedConfig.commit ? ` @ ${managedConfig.commit.slice(0, 7)}` : ""}
                </strong>
                <p className="muted-sm" style={{ margin: "4px 0 0" }}>
                  {managedSummary(managedConfig)}
                </p>
                <p className="muted-sm" style={{ margin: "2px 0 0" }}>
                  Edits here are overwritten the next time the CLI runs from that
                  file.
                </p>
              </div>
              <button
                className="btn quiet sm"
                onClick={handBack}
                disabled={handingBack}
                style={{ marginLeft: "auto" }}
                title="Drop the project file's lock so the web owns these settings again"
              >
                {handingBack ? "Handing back…" : "Hand back to the web"}
              </button>
            </div>
          )}

          <ActivityLog events={events} status={scan.status} />

          {scan.status !== "draft" && (
            <AttentionSummary
              findings={findings}
              summary={findingsData.summary}
              // Only a successful, final page speaks for every finding: an
              // unread or failed list is "not known", never "clean".
              complete={findingsData.hasRead && !findingsData.failed && !findingsData.hasMore}
              diff={diff}
              gaps={gaps}
              notRun={notRun}
              running={running}
              onFindings={focusFindings}
              onDismissed={focusDismissed}
              onTab={setTab}
            />
          )}

          {runPanelOpen && !running && (
            <div id="run-panel">
              <OwnershipNotice scanId={scan.id} target={scan.target_base_url} />
              <RunPanel
              targetUrl={scan.target_base_url}
              options={runOptions}
              busy={runBusy}
              onChange={setRunOptions}
              onRun={doRun}
              onClose={closeRunPanel}
                showRequestRate={false}
                showResourceIds={false}
                replacesFindings={findings.length}
                verifiedHost={verifiedHost}
              />
            </div>
          )}

          <ConfigurationWorkspace
            active={configTab}
            onActiveChange={setConfigTab}
            sections={[
              {
                id: "spec",
                label: "API spec",
                meta: `${scan.operations.filter((operation) => operation.enabled).length} of ${scan.operations.length} operations`,
                content: (
                  <SpecPanel
                    operations={scan.operations}
                    specText={scan.spec_text}
                    specReport={specReport}
                    running={running}
                    specManaged={managed.has("spec")}
                    onSaveSpec={saveSpec}
                    onSetOpEnabled={setOpEnabled}
                    onSetAllOpsEnabled={setAllOpsEnabled}
                    predefinedResourceIds={runOptions.predefined_resource_ids}
                    onSetPredefinedResourceIds={(values) =>
                      setRunOptions((current) => ({
                        ...current,
                        predefined_resource_ids: values,
                      }))
                    }
                  />
                ),
              },
              {
                id: "credentials",
                label: "Credentials",
                meta: `${scan.credential_profiles.length} ${scan.credential_profiles.length === 1 ? "profile" : "profiles"}`,
                content: (
                  <CredentialsPanel
                    scanId={scan.id}
                    credentials={scan.credential_profiles}
                    specScopes={specScopes}
                    running={running}
                    managedIdentities={managedIdentities}
                    onSave={saveCred}
                    onRemove={removeCred}
                  />
                ),
              },
              {
                id: "traffic",
                label: "Traffic",
                meta: `${scan.requests_per_second} req/s`,
                content: (
                  <RequestRatePanel
                    value={scan.requests_per_second}
                    running={running}
                    managed={managed.has("requests_per_second")}
                    onSave={saveRequestRate}
                  />
                ),
              },
              {
                id: "schema",
                label: "Schema context",
                meta: "Premium · local runs",
                content: <DatabaseSchemaPanel scanId={id} running={running} />,
              },
              {
                id: "ai",
                label: "AI usage",
                meta: cost && cost.entries.length > 0
                  ? `${aiSteps} ${aiSteps === 1 ? "step" : "steps"} · $${cost.total_usd.toFixed(4)}`
                  : failed.cost
                    ? "Could not load"
                    : "No usage yet",
                content: (
                  <AiCostPanel cost={cost} failed={failed.cost} aiSkip={aiSkip} />
                ),
              },
              {
                id: "schedule",
                label: "Schedule",
                meta: scheduleSummary(scan.schedule_minutes),
                content: (
                  <SchedulePanel
                    targetUrl={scan.target_base_url}
                    minutes={scan.schedule_minutes}
                    nextRunAt={scan.next_run_at}
                    scheduleOptions={scan.schedule_options}
                    runOptions={runOptions}
                    onSchedule={schedule}
                  />
                ),
              },
            ]}
          />

          <ResultsWorkspace
            key={id}
            id={id}
            status={scan.status}
            failureReason={scan.failure_reason ?? null}
            running={running}
            findings={findings}
            plan={plan}
            coverage={coverage}
            resources={resources}
            gaps={gaps}
            notRun={notRun}
            traceCount={traceCount}
            latestRun={latestRun}
            diff={diff}
            diffFailed={failed.diff}
            findingsFailed={failed.findings}
            runsFailed={failed.runs}
            runs={runs}
            runsHasMore={runResources.hasMoreRuns}
            runsLoadingMore={runResources.loadingMoreRuns}
            onLoadMoreRuns={runResources.loadMoreRuns}
            work={work}
            onMark={mark}
            onSaveWork={saveWork}
            onDeleteWork={removeWork}
            onAddComment={addComment}
            onDeleteComment={removeComment}
            onRetest={retest}
            collaborationEnabled={collaborationEnabled}
            hasMoreFindings={findingsData.hasMore}
            loadingMoreFindings={findingsData.loadingMore}
            onLoadMoreFindings={findingsData.loadMore}
            operations={scan.operations}
            active={tab}
            onActiveChange={setTab}
            focusRequest={focusRequest}
          />
        </>
      )}
    </section>
  );
}
