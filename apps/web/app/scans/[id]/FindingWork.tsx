"use client";

import { PlanBadge } from "../../components/PlanBadge";

import { ExpandingTextarea } from "../../components/ExpandingTextarea";

import { ValidatedForm } from "../../components/ValidatedForm";
import { useConfirmation } from "../../components/Confirmation";

import { useEffect, useMemo, useRef, useState, type FormEvent } from "react";
import {
  api,
  type Finding,
  type FindingWork as FindingWorkItem,
  type FindingWorkInput,
  type FindingWorkStatus,
  type WorkspaceMember,
} from "@/lib/api";
import { Ago } from "../../components/ui";

export const STATUS_LABEL: Record<FindingWorkStatus, string> = {
  open: "Open",
  in_progress: "In progress",
  resolved: "Resolved",
  accepted_risk: "Accepted risk",
};

type Field = "owner" | "due_date" | "status" | "clear" | "comment";

/**
 * The per-finding team workflow: assignment, due date, status and discussion.
 *
 * Collapsed by default so a list of findings stays scannable. Owner saves on
 * blur and the other two on change; nothing is sent per keystroke. Copy and
 * retest never carry evidence values, and retest only narrows the page's run
 * scope — the RunPanel's authorization gate still decides whether a run starts.
 */
export function FindingWork({
  id,
  finding,
  work,
  endpoint,
  onSaveWork,
  onDeleteWork,
  onAddComment,
  onDeleteComment,
  onRetest,
}: {
  id: string;
  finding: Finding;
  /** Missing when the work list has not loaded, or this finding has none yet. */
  work: FindingWorkItem | undefined;
  /** "METHOD /path", with no evidence values, or null when the finding has none. */
  endpoint: string | null;
  onSaveWork: (fingerprint: string, input: FindingWorkInput) => Promise<void>;
  onDeleteWork: (fingerprint: string) => Promise<void>;
  onAddComment: (fingerprint: string, body: string) => Promise<void>;
  onDeleteComment: (commentId: string) => Promise<void>;
  onRetest: (check: string) => void;
}) {
  const [ownerUserId, setOwnerUserId] = useState(work?.owner_user_id ?? "");
  const confirmAction = useConfirmation();
  const [members, setMembers] = useState<WorkspaceMember[]>([]);
  const [membersLoaded, setMembersLoaded] = useState(false);
  const [dueDate, setDueDate] = useState(work?.due_date ?? "");
  const [status, setStatus] = useState<FindingWorkStatus>(work?.status ?? "open");
  const [draft, setDraft] = useState("");
  const [busy, setBusy] = useState<Field | null>(null);
  const [deletingComment, setDeletingComment] = useState<string | null>(null);
  const [errors, setErrors] = useState<Partial<Record<Field, string>>>({});
  const [saved, setSaved] = useState(false);
  const [copyState, setCopyState] = useState<"idle" | "done" | "error">("idle");
  const [retestNotice, setRetestNotice] = useState(0);
  const savedTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const copyTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  // Each field syncs on its own value, so a refresh from saving the status
  // cannot clobber an owner that is still being typed.
  useEffect(() => setOwnerUserId(work?.owner_user_id ?? ""), [work?.owner_user_id]);
  useEffect(() => setDueDate(work?.due_date ?? ""), [work?.due_date]);
  useEffect(() => setStatus(work?.status ?? "open"), [work?.status]);

  function loadMembers() {
    if (membersLoaded) return;
    setMembersLoaded(true);
    void api.listMembers().then(setMembers).catch(() => setMembers([]));
  }

  useEffect(
    () => () => {
      if (savedTimer.current) clearTimeout(savedTimer.current);
      if (copyTimer.current) clearTimeout(copyTimer.current);
    },
    [],
  );

  // Oldest first: the discussion reads in the order it happened.
  const comments = useMemo(
    () =>
      [...(work?.comments ?? [])].sort((a, b) =>
        a.created_at.localeCompare(b.created_at),
      ),
    [work],
  );
  const activity = (work?.owner_user_id || work?.owner ? 1 : 0) + comments.length;
  const assigned =
    !!work &&
    (!!work.owner_user_id || !!work.owner || !!work.due_date || work.status !== "open");

  async function persist(field: Field, input: FindingWorkInput) {
    setBusy(field);
    setErrors((prev) => ({ ...prev, [field]: undefined }));
    try {
      await onSaveWork(finding.fingerprint, input);
      setSaved(true);
      if (savedTimer.current) clearTimeout(savedTimer.current);
      savedTimer.current = setTimeout(() => setSaved(false), 1600);
    } catch (e) {
      setErrors((prev) => ({ ...prev, [field]: (e as Error).message }));
    } finally {
      setBusy(null);
    }
  }

  function changeOwner(value: string) {
    setOwnerUserId(value);
    if (value === (work?.owner_user_id ?? "")) return;
    void persist("owner", { owner_user_id: value || null });
  }

  function changeDue(value: string) {
    setDueDate(value);
    if (value === (work?.due_date ?? "")) return;
    void persist("due_date", { due_date: value || null });
  }

  function changeStatus(value: FindingWorkStatus) {
    setStatus(value);
    if (value === (work?.status ?? "open")) return;
    void persist("status", { status: value });
  }

  async function clearAssignment() {
    await confirmAction({ title: "Clear assignment and status?", description: `Remove the owner and due date for “${finding.title}” and reset its work status.`, actionLabel: "Clear assignment", intent: "warning", action: async () => {
      setBusy("clear");
      setErrors((prev) => ({ ...prev, clear: undefined }));
      try { await onDeleteWork(finding.fingerprint); setOwnerUserId(""); setDueDate(""); setStatus("open"); }
      finally { setBusy(null); }
    } });
  }

  async function submitComment(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const body = draft.trim();
    if (!body || body.length > 4000) return;
    setBusy("comment");
    setErrors((prev) => ({ ...prev, comment: undefined }));
    try {
      await onAddComment(finding.fingerprint, body);
      setDraft("");
    } catch (e) {
      setErrors((prev) => ({ ...prev, comment: (e as Error).message }));
    } finally {
      setBusy(null);
    }
  }

  async function removeComment(commentId: string) {
    setDeletingComment(commentId);
    setErrors((prev) => ({ ...prev, comment: undefined }));
    try {
      await onDeleteComment(commentId);
    } catch (e) {
      setErrors((prev) => ({ ...prev, comment: (e as Error).message }));
    } finally {
      setDeletingComment(null);
    }
  }

  /** A ticket-ready block: no evidence values, requests, headers or credentials. */
  function ticketText(): string {
    const lines = [`## [${finding.severity.toUpperCase()}] ${finding.title}`, ""];
    if (endpoint) lines.push(`- **Endpoint:** \`${endpoint}\``);
    lines.push(`- **Confidence:** ${finding.confidence}`);
    lines.push(`- **Fingerprint:** \`${finding.fingerprint}\``);
    if (typeof window !== "undefined") {
      lines.push(`- **Scan:** ${window.location.origin}/scans/${id}`);
    }
    if (finding.remediation) {
      lines.push("", "### Remediation", finding.remediation);
    }
    return lines.join("\n");
  }

  async function copyTicket() {
    try {
      await navigator.clipboard.writeText(ticketText());
      setCopyState("done");
      if (copyTimer.current) clearTimeout(copyTimer.current);
      copyTimer.current = setTimeout(() => setCopyState("idle"), 1600);
    } catch {
      setCopyState("error");
    }
  }

  return (
    <details
      className="finding-work"
      onToggle={(event) => {
        if (event.currentTarget.open) loadMembers();
      }}
    >
      <summary>
        <span>Assignment &amp; discussion</span>
        <PlanBadge premium />
        {activity > 0 && (
          <span className="fw-count" title="Owner and comments recorded">
            {activity}
          </span>
        )}
      </summary>

      <div className="fw-body">
        <div className="fw-grid">
          <label className="fw-field">
            <span>Owner</span>
            <select
              value={ownerUserId}
              onChange={(e) => changeOwner(e.target.value)}
              disabled={busy === "owner"}
            >
              <option value="">Unassigned</option>
              {members.map((member) => (
                <option key={member.user_id} value={member.user_id}>
                  {member.display_name}
                </option>
              ))}
              {ownerUserId &&
                !members.some((member) => member.user_id === ownerUserId) && (
                  <option value={ownerUserId}>
                    {work?.owner ?? "Former member"}
                  </option>
                )}
              {work?.owner && !work.owner_user_id && (
                <option value="" disabled>
                  {work.owner} (legacy)
                </option>
              )}
            </select>
            {errors.owner && (
              <span className="fw-error" role="alert">
                {errors.owner}
              </span>
            )}
          </label>

          <label className="fw-field">
            <span>Due date</span>
            <input
              type="date"
              value={dueDate}
              onChange={(e) => changeDue(e.target.value)}
              disabled={busy === "due_date"}
            />
            {errors.due_date && (
              <span className="fw-error" role="alert">
                {errors.due_date}
              </span>
            )}
          </label>

          <label className="fw-field">
            <span>Status</span>
            <select
              value={status}
              onChange={(e) => changeStatus(e.target.value as FindingWorkStatus)}
              disabled={busy === "status"}
            >
              {(Object.keys(STATUS_LABEL) as FindingWorkStatus[]).map((key) => (
                <option key={key} value={key}>
                  {STATUS_LABEL[key]}
                </option>
              ))}
            </select>
            {errors.status && (
              <span className="fw-error" role="alert">
                {errors.status}
              </span>
            )}
          </label>
        </div>

        <div className="fw-actions">
          {saved && (
            <span className="fw-saved" role="status">
              Saved
            </span>
          )}
          <button
            type="button"
            className="btn quiet sm"
            onClick={clearAssignment}
            disabled={!assigned || busy !== null}
          >
            Clear assignment
          </button>
        </div>
        {errors.clear && (
          <p className="fw-error" role="alert">
            {errors.clear}
          </p>
        )}

        <section className="fw-comments">
          <h4>Discussion</h4>
          {comments.length === 0 ? (
            <p className="fw-empty">No comments yet.</p>
          ) : (
            <ul className="fw-comment-list">
              {comments.map((comment) => (
                <li key={comment.id}>
                  <div className="fw-comment-head">
                    <span className="fw-author">{comment.author}</span>
                    <span className="fw-time">
                      <Ago iso={comment.created_at} />
                    </span>
                    <button
                      type="button"
                      className="fw-del"
                      onClick={() => removeComment(comment.id)}
                      disabled={deletingComment === comment.id}
                      aria-label="Delete comment"
                    >
                      ✕
                    </button>
                  </div>
                  {/* React text only: a comment is never rendered as HTML. */}
                  <p className="fw-comment-body">{comment.body}</p>
                </li>
              ))}
            </ul>
          )}

          <ValidatedForm className="fw-compose" onSubmit={submitComment}>
            <ExpandingTextarea
              value={draft}
              onChange={(e) => setDraft(e.target.value)}
              maxLength={4000}
              rows={3}
              placeholder="Add a comment…"
              aria-label="New comment"
            />
            <div className="fw-compose-row">
              <span className="fw-counter">{draft.length}/4000</span>
              <button
                type="submit"
                className="btn sm"
                disabled={!draft.trim() || busy === "comment"}
              >
                {busy === "comment" ? "Adding…" : "Add"}
              </button>
            </div>
          </ValidatedForm>
          {errors.comment && (
            <p className="fw-error" role="alert">
              {errors.comment}
            </p>
          )}
        </section>

        <div className="fw-tools">
          <button type="button" className="btn quiet sm" onClick={copyTicket}>
            {copyState === "done" ? "✓ Copied" : "Copy as ticket"}
          </button>
          <button
            type="button"
            className="btn quiet sm"
            onClick={() => {
              onRetest(finding.check);
              setRetestNotice((n) => n + 1);
            }}
          >
            Retest this check
          </button>
        </div>
        {copyState === "error" && (
          <p className="fw-error" role="alert">
            Could not copy — the clipboard is unavailable in this browser.
          </p>
        )}
        {retestNotice > 0 && (
          <p className="fw-notice" role="status" key={retestNotice}>
            Run scope set to {finding.check}; confirm authorization to retest.
          </p>
        )}
      </div>
    </details>
  );
}
