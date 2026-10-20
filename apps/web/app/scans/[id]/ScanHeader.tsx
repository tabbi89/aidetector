"use client";

import { memo, useState } from "react";
import Link from "next/link";
import type { Scan } from "@/lib/api";
import { ExportMenu } from "../../components/ExportMenu";
import { OwnershipChip } from "../../components/OwnershipNotice";
import { Ago, CopyButton } from "../../components/ui";

/**
 * Breadcrumb, target URL (with inline editing), status line with the run /
 * cancel / export / delete actions, and the live progress bar.
 *
 * The target-edit form owns its own draft state so typing in it never touches
 * the page's polled scan state.
 */
function ScanHeaderImpl({
  id,
  scan,
  running,
  connected,
  staleSeconds,
  findingsCount,
  progressMessage,
  cancelling,
  deleting,
  onSaveTarget,
  onToggleRunPanel,
  onCancel,
  onDelete,
  targetManaged = false,
}: {
  id: string;
  scan: Scan | null;
  running: boolean;
  /** The project file owns the target URL, so the inline editor stays closed. */
  targetManaged?: boolean;
  /** The last poll answered; when false the numbers below are the last known. */
  connected: boolean;
  /** Seconds since the last answered poll, while disconnected. */
  staleSeconds: number | null;
  findingsCount: number;
  progressMessage: string | null;
  cancelling: boolean;
  deleting: boolean;
  onSaveTarget: (url: string) => Promise<void>;
  onToggleRunPanel: () => void;
  onCancel: () => void;
  onDelete: () => void;
}) {
  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState("");
  const [busy, setBusy] = useState(false);

  async function save() {
    const next = draft.trim();
    if (!next) return;
    setBusy(true);
    try {
      await onSaveTarget(next);
      setEditing(false);
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <div className="crumbs">
        <Link href="/scans">Scans</Link>
        <span className="sep" aria-hidden="true">›</span>
        <span>Scan</span>
      </div>

      <div className="title-row">
        {scan && editing ? (
          <form
            className="target-edit"
            onSubmit={(e) => {
              e.preventDefault();
              save();
            }}
          >
            <input
              type="url"
              value={draft}
              onChange={(e) => setDraft(e.target.value)}
              placeholder="https://api.example.com"
              autoFocus
            />
            <button className="btn sm" type="submit" disabled={busy}>
              {busy ? "Saving…" : "Save"}
            </button>
            <button
              className="btn quiet sm"
              type="button"
              onClick={() => setEditing(false)}
              disabled={busy}
            >
              Cancel
            </button>
          </form>
        ) : (
          <>
            <h1>{scan?.target_base_url ?? "Scan"}</h1>
            {scan && <CopyButton value={scan.target_base_url} label="Copy target URL" />}
            {scan && !running && (
              <>
                {targetManaged && (
                  <span className="muted-sm" title="The target URL comes from the project file">
                    set by aidetector.yml
                  </span>
                )}
                <button
                  className="btn quiet sm"
                  onClick={() => {
                    setDraft(scan.target_base_url);
                    setEditing(true);
                  }}
                  disabled={targetManaged}
                  title={
                    targetManaged
                      ? "The target URL comes from the project file"
                      : "Edit the target base URL"
                  }
                >
                  Edit
                </button>
              </>
            )}
          </>
        )}
      </div>

      {scan && (
        <>
          {editing && (
            <p className="target-edit-hint" role="note">
              The scanner runs on our server, not your machine: use the
              API&rsquo;s public address, not <code>localhost</code>.
            </p>
          )}
          <div className="statline">
            <span className={`st-chip ${scan.status}`}>{scan.status}</span>
            <span className="muted-sm">
              {findingsCount} finding{findingsCount === 1 ? "" : "s"}
            </span>
            <span className="muted-sm">
              started <Ago iso={scan.created_at} />
            </span>
            <OwnershipChip scanId={scan.id} target={scan.target_base_url} />
            {scan.cost_usd > 0 && (
              <span className="cost-chip" title="AI cost for this scan">
                AI ${scan.cost_usd.toFixed(4)}
              </span>
            )}
            <span className="spacer" />
            {!running && (
              <button
                className="btn sm"
                onClick={onToggleRunPanel}
                disabled={scan.operations.length === 0}
                title={
                  scan.operations.length === 0
                    ? "Upload a spec first"
                    : "Run this scan now"
                }
              >
                ▶ Run now
              </button>
            )}
            {running && (
              <button
                className="btn danger sm"
                onClick={() => {
                  // The engine cannot roll a run back, so the stop is confirmed
                  // rather than fired by a stray click.
                  if (
                    window.confirm(
                      "Stop this scan at the next check boundary? Findings so far are kept.",
                    )
                  ) {
                    onCancel();
                  }
                }}
                disabled={cancelling}
                title={
                  cancelling
                    ? "Cancel requested — the engine stops at the next safe point (an external tool in progress finishes first)"
                    : "Stop the scan"
                }
              >
                {cancelling ? "Cancelling…" : "Cancel scan"}
              </button>
            )}
            {!running && findingsCount > 0 && <ExportMenu id={id} />}
            {!running && (
              <button
                className="btn danger sm"
                onClick={onDelete}
                disabled={deleting}
                title="Delete this scan and all of its data"
              >
                {deleting ? "Deleting…" : "Delete scan"}
              </button>
            )}
          </div>

          {running && cancelling && (
            <p className="muted-sm" role="status">
              Cancellation requested. Waiting for the worker to reach a safe
              stopping point; an external tool already in progress finishes first.
            </p>
          )}

          {(running || scan.progress > 0) && (
            <div className="progress-wrap">
              <div
                className="progress"
                role="progressbar"
                aria-valuenow={scan.progress}
                aria-valuemin={0}
                aria-valuemax={100}
                aria-label="Scan progress"
              >
                <div
                  className={`bar ${running ? "live" : ""}`}
                  style={{ width: `${scan.progress}%` }}
                />
              </div>
              <div className="prog-meta" aria-live="polite">
                {running && connected && (
                  <span className="live-tag" title="Auto-refreshing every second">
                    <span className="live-dot" aria-hidden="true" />
                    live
                  </span>
                )}
                {running && !connected && (
                  <span
                    className="live-tag reconnecting"
                    title="The last poll failed — retrying with backoff"
                  >
                    <span className="live-dot" aria-hidden="true" />
                    Reconnecting… (last update {staleSeconds ?? 0}s ago)
                  </span>
                )}
                <span className="pct">{scan.progress}%</span>
                {progressMessage && <span className="msg">{progressMessage}</span>}
              </div>
            </div>
          )}
        </>
      )}
    </>
  );
}

export const ScanHeader = memo(ScanHeaderImpl);
