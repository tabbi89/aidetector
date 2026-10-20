"use client";

import Link from "next/link";
import { useEffect, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import {
  NO_RUN_OPTIONS,
  api,
  type AuthType,
  type Credential,
  type Operation,
  type RunOptions,
  type ScanStatus,
  type SpecReport,
} from "@/lib/api";
import { CliHandoff } from "../../components/CliHandoff";
import { CredentialsPanel } from "../../components/CredentialsPanel";
import { DatabaseSchemaPanel } from "../../components/DatabaseSchemaPanel";
import { RunPanel } from "../../components/RunPanel";
import { OwnershipNotice } from "../../components/OwnershipNotice";
import { ScanReadiness } from "../../components/ScanReadiness";
import { withPresetPasses } from "../../components/checkScope";
import { SCAN_LEVELS } from "../../components/scanLevels";
import { SpecReportView } from "../../components/SpecReportView";
import { type CredForm } from "../../components/scanShared";
import { ErrorBanner } from "../../components/ui";
import { useCapabilities } from "../../components/useCapabilities";
import { useConnection } from "@/lib/connection";

type Step = 1 | 2 | 3 | 4;

/** The only state a refresh has to restore; spec, secrets and passes stay out. */
const DRAFT_KEY = "aidetector.scan-draft.v1";

interface Draft {
  scanId: string;
  target: string;
  step: Step;
}

function readDraft(): Draft | null {
  if (typeof window === "undefined") return null;
  try {
    const parsed: unknown = JSON.parse(window.sessionStorage.getItem(DRAFT_KEY) ?? "null");
    if (!parsed || typeof parsed !== "object") return null;
    const draft = parsed as Partial<Draft>;
    if (typeof draft.scanId !== "string" || !draft.scanId) return null;
    if (typeof draft.target !== "string") return null;
    if (draft.step !== 1 && draft.step !== 2 && draft.step !== 3 && draft.step !== 4) {
      return null;
    }
    return { scanId: draft.scanId, target: draft.target, step: draft.step };
  } catch {
    return null;
  }
}

function writeDraft(draft: Draft) {
  if (typeof window === "undefined") return;
  try {
    window.sessionStorage.setItem(DRAFT_KEY, JSON.stringify(draft));
  } catch {
    /* private mode or a full quota — the wizard still works without it */
  }
}

function clearDraft() {
  if (typeof window === "undefined") return;
  try {
    window.sessionStorage.removeItem(DRAFT_KEY);
  } catch {
    /* nothing to do */
  }
}

/** The scan routes answer 404 with "scan not found". */
function isNotFound(reason: unknown): boolean {
  const message = reason instanceof Error ? reason.message : String(reason);
  const m = message.trim().toLowerCase();
  return m === "scan not found" || m === "404" || m.startsWith("404 ");
}

const STEP_LABELS: Record<Step, string> = {
  1: "Target",
  2: "Spec",
  3: "Credentials",
  4: "Run",
};

function kb(bytes: number) {
  return bytes < 1024 ? `${bytes} B` : `${(bytes / 1024).toFixed(1)} KB`;
}


/** The API's target rules, mirrored so a bad URL fails before the request. */
function targetProblem(value: string): string | null {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return "Enter a full URL, for example https://api.example.com.";
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    return "The URL must start with http:// or https://.";
  }
  if (!url.hostname) return "The URL needs a hostname.";
  if (url.username || url.password) {
    return "Remove the username and password from the URL; use the credentials step instead.";
  }
  if (url.search || url.hash) {
    return "Remove the query string and fragment — this is a base URL.";
  }
  return null;
}

/** A warning, not a block: localhost is a valid URL, just not one the server can reach. */
function localhostWarning(value: string): string | null {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return null;
  }
  if (url.hostname !== "localhost" && url.hostname !== "127.0.0.1") return null;
  return `The scanner runs on the server, so ${url.hostname} is the scanner itself, not your machine. Use the API's public address.`;
}

export default function NewScan() {
  const router = useRouter();
  const [step, setStep] = useState<Step>(1);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  // step 1 — target
  const [target, setTarget] = useState("");
  const [targetError, setTargetError] = useState<string | null>(null);
  const [scanId, setScanId] = useState<string | null>(null);
  // The target as the API stored it, so "Continue" can tell an edited URL from
  // the same one without creating a second scan.
  const [scanTarget, setScanTarget] = useState<string | null>(null);
  const [scanStatus, setScanStatus] = useState<ScanStatus | null>(null);
  const [resumed, setResumed] = useState(false);
  const capabilities = useCapabilities();

  // step 2 — spec
  const [spec, setSpec] = useState("");
  const [specFile, setSpecFile] = useState<{ name: string; size: number } | null>(null);
  const [dragging, setDragging] = useState(false);
  const [ops, setOps] = useState<Operation[]>([]);
  const [specReport, setSpecReport] = useState<SpecReport | null>(null);

  // step 3 — credentials (the form itself lives in CredentialsPanel)
  const [creds, setCreds] = useState<Credential[]>([]);

  // step 4 — run. One options object so the wizard can launch every pass the
  // detail page can; it previously forwarded only four of them. Starts quick:
  // every check, with writes and AI off until explicitly switched on.
  const [runOptions, setRunOptions] = useState<RunOptions>(() =>
    withPresetPasses(NO_RUN_OPTIONS, "all"),
  );

  // The API offers a ready-made example (bundled target, spec, two identities) in dev.
  const [examples, setExamples] = useState(false);
  useEffect(() => {
    api.health().then((h) => setExamples(h.examples)).catch(() => setExamples(false));
  }, []);

  const { ready, status } = useConnection();
  // Restore the draft only once the connection is settled. On a protected
  // deployment the key lives in sessionStorage, and the provider's probe is
  // what proves it still works; fetching first would race that restore and
  // then never retry. A rejected or missing key returns to "idle" here, so
  // reconnecting is a fresh attempt rather than a dead end.
  const restoreAttempt = useRef<"idle" | "running" | "done">("idle");
  useEffect(() => {
    if (!ready) return;
    if (status !== "connected" && status !== "open") {
      if (restoreAttempt.current === "done") restoreAttempt.current = "idle";
      return;
    }
    if (restoreAttempt.current !== "idle") return;
    const draft = readDraft();
    if (!draft) {
      restoreAttempt.current = "done";
      return;
    }
    restoreAttempt.current = "running";
    let cancelled = false;
    (async () => {
      try {
        const scan = await api.getScan(draft.scanId);
        if (cancelled) return;
        // Step 3 needs parsed operations; a scan with none falls back to Spec.
        const restored: Step = scan.operations.length === 0 && draft.step >= 3 ? 2 : draft.step;
        setScanId(scan.id);
        setScanTarget(scan.target_base_url);
        setScanStatus(scan.status);
        setTarget(scan.target_base_url);
        setSpec(scan.spec_text ?? "");
        setSpecFile(null);
        setOps(scan.operations);
        setSpecReport(null);
        setCreds(scan.credential_profiles);
        setStep(restored);
        setResumed(true);
        writeDraft({ scanId: scan.id, target: scan.target_base_url, step: restored });
        restoreAttempt.current = "done";
      } catch (e) {
        if (cancelled) return;
        // A scan deleted elsewhere (or a stale id) must not trap the wizard.
        if (isNotFound(e)) {
          clearDraft();
          restoreAttempt.current = "done";
        } else {
          // Retry when the connection changes to a working one.
          restoreAttempt.current = "idle";
          setErr((e as Error).message);
        }
      }
    })();
    return () => {
      cancelled = true;
      if (restoreAttempt.current === "running") restoreAttempt.current = "idle";
    };
  }, [ready, status]);

  async function loadExampleTarget() {
    setBusy(true);
    setErr(null);
    try {
      const scan = await api.createExampleScan();
      setScanId(scan.id);
      setScanTarget(scan.target_base_url);
      setScanStatus(scan.status);
      setTarget(scan.target_base_url);
      setSpec(scan.spec_text ?? "");
      setSpecFile(null);
      setOps(scan.operations);
      setTargetError(null);
      setCreds(scan.credential_profiles);
      setResumed(false);
      // Everything is filled in; the run step still asks for authorization.
      setStep(4);
      writeDraft({ scanId: scan.id, target: scan.target_base_url, step: 4 });
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  // A step is reachable once the work it depends on is done.
  function reachable(s: Step) {
    if (s === 1) return true;
    if (!scanId) return false;
    if (s === 2) return true;
    return ops.length > 0;
  }

  function goto(s: Step) {
    if (!reachable(s)) return;
    setErr(null);
    setStep(s);
    if (scanId) writeDraft({ scanId, target: scanTarget ?? target.trim(), step: s });
  }

  /** Reset everything that belonged to the scan being replaced. */
  function resetScanState() {
    setSpec("");
    setSpecFile(null);
    setOps([]);
    setSpecReport(null);
    setCreds([]);
  }

  /** Start over: drop the draft and, for an untouched one, the abandoned scan. */
  function startOver() {
    if (!scanId) return;
    const hasContent = Boolean(spec.trim()) || ops.length > 0 || creds.length > 0;
    if (hasContent && !window.confirm("Start over? This scan's spec and credentials are discarded.")) {
      return;
    }
    // Same rule as a superseded target: delete only an empty, unrun draft.
    if (ops.length === 0 && creds.length === 0 && scanStatus === "draft") {
      void api.deleteScan(scanId).catch(() => undefined);
    }
    clearDraft();
    setScanId(null);
    setScanTarget(null);
    setScanStatus(null);
    setResumed(false);
    setTarget("");
    setTargetError(null);
    setErr(null);
    resetScanState();
    setRunOptions(withPresetPasses(NO_RUN_OPTIONS, "all"));
    setStep(1);
  }

  async function continueFromTarget() {
    const value = target.trim();
    const problem = targetProblem(value);
    if (problem) {
      setTargetError(problem);
      return;
    }
    setTargetError(null);
    // Same target as the draft: this is a step back, not a new scan.
    if (scanId && scanTarget && value === scanTarget) {
      goto(2);
      return;
    }

    setBusy(true);
    setErr(null);
    const superseded = scanId;
    const supersededEmpty =
      ops.length === 0 && creds.length === 0 && scanStatus === "draft";
    try {
      const scan = await api.createScan(value);
      // Configuration from the old scan must not leak into the new one.
      resetScanState();
      setScanId(scan.id);
      setScanTarget(scan.target_base_url);
      setScanStatus(scan.status);
      setResumed(false);
      setStep(2);
      writeDraft({ scanId: scan.id, target: scan.target_base_url, step: 2 });
      if (superseded && superseded !== scan.id && supersededEmpty) {
        void api.deleteScan(superseded).catch(() => undefined);
      }
    } catch (e) {
      // The API answers a bad target with a 422 detail; it belongs under the field.
      setTargetError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  async function readSpecFile(file: File) {
    setSpecFile({ name: file.name, size: file.size });
    setSpec(await file.text());
    setOps([]);
    setSpecReport(null);
  }

  async function uploadSpec() {
    if (!scanId) return;
    setBusy(true);
    setErr(null);
    try {
      const scan = await api.uploadSpec(scanId, spec);
      setOps(scan.operations);
      setSpecReport(scan.spec_report);
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  function toggleOp(id: string) {
    setOps((prev) =>
      prev.map((o) => (o.id === id ? { ...o, enabled: !o.enabled } : o)),
    );
  }

  function setAllOps(enabled: boolean) {
    setOps((prev) => prev.map((o) => ({ ...o, enabled })));
  }

  // Persist the endpoint selection, then advance to credentials.
  async function continueToCredentials() {
    if (!scanId) return;
    setBusy(true);
    setErr(null);
    try {
      const scan = await api.setOperations(
        scanId,
        ops.map((o) => ({ id: o.id, enabled: o.enabled })),
      );
      setOps(scan.operations);
      goto(3);
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  async function saveCred(form: CredForm, editingId: string | null) {
    if (!scanId) return;
    setErr(null);
    try {
      if (editingId) {
        const updated = await api.updateCredential(scanId, editingId, form);
        setCreds((prev) => prev.map((c) => (c.id === editingId ? updated : c)));
      } else {
        const created = await api.addCredential(scanId, form);
        setCreds((prev) => [...prev, created]);
      }
    } catch (e) {
      setErr((e as Error).message);
      throw e; // keep the form open with the user's input
    }
  }

  async function removeCred(credId: string) {
    if (!scanId) return;
    if (!window.confirm("Remove this credential profile?")) return;
    setErr(null);
    try {
      await api.deleteCredential(scanId, credId);
      setCreds((prev) => prev.filter((c) => c.id !== credId));
    } catch (e) {
      setErr((e as Error).message);
    }
  }

  async function runScan() {
    if (!scanId) return;
    setBusy(true);
    setErr(null);
    try {
      await api.runScan(scanId, true, runOptions);
      clearDraft();
      router.push(`/scans/${scanId}`);
    } catch (e) {
      setErr((e as Error).message);
      setBusy(false);
    }
  }

  const specScopes = [
    ...new Set(
      ops.flatMap((o) =>
        (o.auth_scope ?? "").split(",").map((p) => p.trim()).filter(Boolean),
      ),
    ),
  ].sort();
  const levelTitle =
    SCAN_LEVELS.find((level) => level.id === (runOptions.level ?? "quick"))?.title ?? "Quick";
  const enabledPasses = [
    levelTitle,
    runOptions.mutate && "writes",
    runOptions.ai && "AI",
  ].filter(Boolean);
  const selectedCount = ops.filter((o) => o.enabled).length;
  const targetWarning = localhostWarning(target);
  const roles = new Set(creds.map((c) => c.role));

  return (
    <section className="wrap section new-scan">
      <div className="crumbs">
        <Link href="/scans">Scans</Link>
        <span className="sep" aria-hidden="true">›</span>
        <span>New scan</span>
      </div>
      <h1 style={{ fontSize: 28 }}>New scan</h1>

      <ol className="steps" aria-label={`Step ${step} of 4: ${STEP_LABELS[step]}`}>
        {([1, 2, 3, 4] as Step[]).map((s) => {
          const state = s === step ? "active" : s < step ? "done" : "";
          return (
            <li key={s} style={{ listStyle: "none" }}>
              <button
                type="button"
                className={`step ${state}`}
                onClick={() => goto(s)}
                disabled={!reachable(s) || s === step}
                aria-current={s === step ? "step" : undefined}
              >
                <span className="n" aria-hidden="true">
                  {s < step ? "✓" : s}
                </span>
                {STEP_LABELS[s]}
              </button>
            </li>
          );
        })}
      </ol>

      {err && <ErrorBanner message={err} onClose={() => setErr(null)} />}

      {resumed && scanId && (
        <div className="draft-note" role="status">
          <span>Resumed your unfinished scan.</span>
          <button type="button" className="copybtn" onClick={startOver} disabled={busy}>
            Start over
          </button>
        </div>
      )}

      {step === 1 && (
        <div className="panel">
          <h2>Target</h2>
          <p className="hint">
            The base URL of an API you own, or are explicitly authorized to
            security-test.
          </p>
          <div className="target-help" role="note">
            <span className="target-help-label">Before you scan</span>
            <p>
              A public API is scanned only after your workspace proves it owns
              the domain — add it under{" "}
              <Link href="/workspace?section=domains">Workspace → Domains</Link>.
              The scanner runs on our server, not your machine, so use the
              API&rsquo;s public address rather than <code>localhost</code>.
            </p>
          </div>
          <label className="field">
            <span>Base URL</span>
            <input
              type="url"
              // The validation message is rendered inside this label, so without
              // an explicit name the field's accessible name changes the moment
              // it reports an error. Keep it "Base URL".
              aria-label="Base URL"
              value={target}
              onChange={(e) => {
                setTarget(e.target.value);
                setTargetError(null);
              }}
              onKeyDown={(e) => e.key === "Enter" && target.trim() && !busy && continueFromTarget()}
              placeholder="https://api.example.com"
              autoFocus
              aria-invalid={Boolean(targetError)}
            />
            {targetError ? (
              <span className="field-error" role="alert">
                {targetError}
              </span>
            ) : (
              targetWarning && <span className="target-warn">{targetWarning}</span>
            )}
          </label>
          <div className="actions">
            <button className="btn" onClick={continueFromTarget} disabled={busy || !target.trim()}>
              {busy && <span className="spinner" aria-hidden="true" />}
              {busy
                ? "Creating…"
                : scanId && scanTarget === target.trim()
                  ? "Continue"
                  : "Create & continue"}
            </button>
            {scanId && (
              <button className="btn quiet" onClick={startOver} disabled={busy}>
                Start over
              </button>
            )}
            <span className="muted-sm">
              Nothing is sent to the target until you run the scan.
            </span>
          </div>
          {examples && (
            <div className="example-target" role="note">
              <div>
                <span className="target-help-label">Trying it out?</span>
                <p>
                  Fill in the bundled vulnerable target, its spec and two identities
                  (alice and admin) in one step. You still confirm authorization before
                  anything runs.
                </p>
              </div>
              <button className="btn quiet" onClick={loadExampleTarget} disabled={busy}>
                Use example target
              </button>
            </div>
          )}
        </div>
      )}

      {step === 2 && (
        <div className="panel">
          <h2>OpenAPI / Swagger spec, HAR or Postman</h2>
          <p className="hint">
            Drop an OpenAPI/Swagger spec (JSON or YAML), a HAR capture, or a
            Postman collection — or paste it below. A HAR or collection is
            converted to a spec (paths templated, values dropped); every
            operation becomes a row in the test matrix.
          </p>

          <label
            className={`drop ${dragging ? "over" : ""}`}
            onDragOver={(e) => {
              e.preventDefault();
              setDragging(true);
            }}
            onDragLeave={() => setDragging(false)}
            onDrop={(e) => {
              e.preventDefault();
              setDragging(false);
              const f = e.dataTransfer.files?.[0];
              if (f) readSpecFile(f);
            }}
          >
            <input
              type="file"
              accept=".json,.yaml,.yml,.har,application/json,text/yaml"
              onChange={(e) => e.target.files?.[0] && readSpecFile(e.target.files[0])}
              className="visually-hidden"
            />
            <div className="big">Drop a spec file here, or click to browse</div>
            <div className="small">.json · .yaml · .yml · .har · Postman</div>
          </label>

          {specFile && (
            <div className="filechip" style={{ marginTop: 10 }}>
              <span aria-hidden="true">📄</span>
              <span className="name">{specFile.name}</span>
              <span className="size">{kb(specFile.size)}</span>
              <button
                className="copybtn"
                type="button"
                onClick={() => {
                  setSpecFile(null);
                  setSpec("");
                  setOps([]);
                  setSpecReport(null);
                }}
                aria-label="Remove spec file"
              >
                ✕
              </button>
            </div>
          )}

          <label className="field" style={{ marginTop: 18 }}>
            <span>
              Spec contents <span className="opt">— editable</span>
            </span>
            <textarea
              value={spec}
              onChange={(e) => {
                setSpec(e.target.value);
                setOps([]);
                setSpecReport(null);
              }}
              placeholder={'{ "openapi": "3.0.0", "paths": { ... } }'}
              spellCheck={false}
            />
          </label>

          <div className="actions">
            <button className="btn" onClick={uploadSpec} disabled={busy || !spec.trim()}>
              {busy && <span className="spinner" aria-hidden="true" />}
              {busy ? "Parsing…" : ops.length ? "Re-parse spec" : "Parse spec"}
            </button>
            <button className="btn quiet" onClick={() => goto(1)} disabled={busy}>
              Back
            </button>
            {ops.length > 0 && (
              <span className="ok" role="status">
                ✓ {selectedCount} of {ops.length} operation
                {ops.length === 1 ? "" : "s"} selected
              </span>
            )}
          </div>

          {specReport && <SpecReportView report={specReport} />}

          {ops.length > 0 && (
            <>
              <div className="oplist-head">
                <span className="hint">
                  Uncheck any endpoint to leave it out of the run.
                </span>
                <span className="oplist-bulk">
                  <button
                    type="button"
                    className="btn quiet sm"
                    onClick={() => setAllOps(true)}
                  >
                    Select all
                  </button>
                  <button
                    type="button"
                    className="btn quiet sm"
                    onClick={() => setAllOps(false)}
                  >
                    None
                  </button>
                </span>
              </div>
              <div className="oplist">
                {ops.map((o) => (
                  <label
                    className={`op selectable${o.enabled ? "" : " off"}`}
                    key={o.id}
                  >
                    <input
                      type="checkbox"
                      checked={o.enabled}
                      onChange={() => toggleOp(o.id)}
                    />
                    <span className={`method ${o.method.toLowerCase()}`}>{o.method}</span>
                    <span className="p">{o.path}</span>
                    {o.auth_scope && <span className="scope">{o.auth_scope}</span>}
                  </label>
                ))}
              </div>
              <div className="actions">
                <button
                  className="btn"
                  onClick={continueToCredentials}
                  disabled={busy || selectedCount === 0}
                >
                  {busy ? "Saving…" : "Continue to credentials →"}
                </button>
                {selectedCount === 0 && (
                  <span className="hint">Select at least one endpoint.</span>
                )}
              </div>
            </>
          )}
        </div>
      )}

      {step === 3 && (
        <div className="panel">
          <h2>Credentials</h2>
          <p className="hint">
            Say how this API authenticates: public, one key, or several roles.
            With <strong>two accounts</strong> (two tenants, or a user and an
            admin) the scanner can also replay requests across them to test
            BOLA/BFLA. Secrets are encrypted at rest and never shown again.
          </p>

          {/* Same panel the detail page uses, so the credential form, its
              validation and the write-only secret handling stay in one place. */}
          <CredentialsPanel
            scanId={scanId}
            credentials={creds}
            specScopes={specScopes}
            running={false}
            onSave={saveCred}
            onRemove={removeCred}
            startOpen
          />
          {scanId && <DatabaseSchemaPanel scanId={scanId} running={false} />}

          <div className="actions split" style={{ marginTop: 28 }}>
            <div style={{ display: "flex", gap: 10, alignItems: "center", flexWrap: "wrap" }}>
              <button className="btn" onClick={() => goto(4)}>
                Continue to run →
              </button>
              <button className="btn quiet" onClick={() => goto(2)}>
                Back
              </button>
            </div>
            {roles.size < 2 && (
              <span className="muted-sm">
                {creds.length === 0
                  ? "No credentials yet — only unauthenticated checks will run."
                  : "Add a second role to enable BOLA/BFLA testing."}
              </span>
            )}
          </div>
        </div>
      )}

      {step === 4 && (
        <div className="panel">
          <h2>Review &amp; run</h2>
          <p className="hint">
            The engine sends real attack payloads at the target. Confirm you are
            authorized before running.
          </p>

          <div className="review">
            <div className="r">
              <span className="k">Target</span>
              <span className="v">{target}</span>
            </div>
            <div className="r">
              <span className="k">Operations</span>
              <span className={`v ${selectedCount === 0 ? "warn" : ""}`}>
                {selectedCount} of {ops.length} selected
              </span>
            </div>
            <div className="r">
              <span className="k">Credentials</span>
              <span className={`v ${roles.size < 2 ? "warn" : ""}`}>
                {creds.length === 0
                  ? "none — unauthenticated checks only"
                  : `${creds.length} (${[...roles].join(", ")})${
                      roles.size < 2 ? " — BOLA/BFLA skipped" : ""
                    }`}
              </span>
            </div>
            <div className="r">
              <span className="k">Optional passes</span>
              <span className="v">{enabledPasses.join(" · ")}</span>
            </div>
          </div>

          {scanId && <OwnershipNotice scanId={scanId} target={target} />}

          <ScanReadiness
            target={target}
            operations={ops}
            credentials={creds}
            options={runOptions}
            entitlement={capabilities.premium}
          />

          {/* Same panel the detail page uses, so both routes offer the same
              passes and the same authorization gate. */}
          <RunPanel
            targetUrl={target}
            options={runOptions}
            busy={busy}
            onChange={setRunOptions}
            onRun={runScan}
            onClose={() => goto(3)}
            closeLabel="Back"
          />

          {scanId && (
            <CliHandoff scanId={scanId} target={target} credentials={creds} />
          )}

          <div className="actions">
            <span className="muted-sm">
              Runs in the background — live progress on the next screen.
            </span>
          </div>
        </div>
      )}
    </section>
  );
}
