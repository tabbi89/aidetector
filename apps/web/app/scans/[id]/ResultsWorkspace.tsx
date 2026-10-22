"use client";

import { useMemo } from "react";
import type { CoverageRow, Finding, FindingWork, FindingWorkInput, Operation, PlanRow, ResourceRow, RunDiff, ScanEvent, ScanRun, ScanStatus, Severity, Verdict } from "@/lib/api";
import { SidebarWorkspace } from "../../components/SidebarWorkspace";
import { RANK, gapCountLabel } from "../../components/scanShared";
import { SecurityDesignReview } from "./SecurityDesignReview";
import { AskPanel } from "./AskPanel";
import { FindingsSection, revealFinding } from "./FindingsSection";
import { STATUS_LABEL } from "./FindingWork";
import { CoverageTable, MutationTable, PlanTable, ResourceTable, RunDiffPanel, RunGaps, RunHistory } from "./RunInsights";

function EmptyResult({ title, children }: { title: string; children: string }) {
  return (
    <div className="specbox result-empty">
      <h3>{title}</h3>
      <p>{children}</p>
    </div>
  );
}

/** "YYYY-MM-DD" in local time, the shape the API stores due dates in. */
function todayIso(): string {
  const now = new Date();
  return `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, "0")}-${String(now.getDate()).padStart(2, "0")}`;
}

function dueLabel(date: string): string {
  const parsed = new Date(`${date}T00:00:00`);
  return Number.isNaN(parsed.getTime()) ? date : parsed.toLocaleDateString();
}

/** Dated items first, in date order; an unset due date sorts last. */
function compareDue(a: string | null, b: string | null): number {
  if (a === b) return 0;
  if (!a) return 1;
  if (!b) return -1;
  return a.localeCompare(b);
}

interface WorkRow {
  item: FindingWork;
  /** Null when the finding is outside the loaded page of the list. */
  finding: Finding | null;
  overdue: boolean;
}

const UNKNOWN_RANK = 99;

/** The work list joined to its live finding: overdue first, then due, then severity. */
function workRows(work: Map<string, FindingWork>, findings: Finding[]): WorkRow[] {
  const today = todayIso();
  const byFingerprint = new Map(findings.map((f) => [f.fingerprint, f]));
  return [...work.values()]
    .flatMap((item) => {
      // Keep every assignment: an overdue task attached to a finding beyond
      // the loaded page must not silently disappear from the queue.
      const finding = byFingerprint.get(item.fingerprint) ?? null;
      const overdue =
        !!item.due_date &&
        item.due_date < today &&
        (item.status === "open" || item.status === "in_progress");
      return [{ item, finding, overdue }];
    })
    .sort(
      (a, b) =>
        Number(b.overdue) - Number(a.overdue) ||
        compareDue(a.item.due_date, b.item.due_date) ||
        (a.finding ? RANK[a.finding.severity] : UNKNOWN_RANK) -
          (b.finding ? RANK[b.finding.severity] : UNKNOWN_RANK) ||
        (a.finding?.title ?? a.item.fingerprint).localeCompare(
          b.finding?.title ?? b.item.fingerprint,
        ),
    );
}

function WorkQueue({ rows }: { rows: WorkRow[] }) {
  return (
    <div className="work-queue">
      {rows.map(({ item, finding, overdue }) => {
        const label = finding?.title ?? "Finding beyond the loaded page";
        return (
          <button
            type="button"
            className={`work-queue-row${overdue ? " overdue" : ""}`}
            key={item.fingerprint}
            // The findings search matches fingerprints server-side, so a task
            // whose finding is not loaded still opens it.
            onClick={() => revealFinding(finding ? finding.title : item.fingerprint)}
            title={
              finding
                ? `Show ${finding.title} in Findings`
                : `Find fingerprint ${item.fingerprint} in Findings`
            }
          >
            {finding ? (
              <span className={`sev-badge ${finding.severity}`}>{finding.severity}</span>
            ) : (
              <span className="sev-badge">?</span>
            )}
            <span className="wq-title">{label}</span>
            <span className="wq-meta">
              <span className="wq-owner">{item.owner ?? "Unassigned"}</span>
              <span className={`wq-due${overdue ? " overdue" : ""}`}>
                {item.due_date ? `Due ${dueLabel(item.due_date)}` : "No due date"}
              </span>
              <span className={`wq-status ${item.status}`}>{STATUS_LABEL[item.status]}</span>
            </span>
          </button>
        );
      })}
    </div>
  );
}

export function ResultsWorkspace({
  id, status, failureReason, running, findings, work, plan, coverage, resources, gaps, notRun, traceCount, latestRun, diff, diffFailed, findingsFailed, runsFailed, runs, runsHasMore, runsLoadingMore, onLoadMoreRuns, onMark, onSaveWork, onDeleteWork, onAddComment, onDeleteComment, onRetest, operations,
  active, onActiveChange, focusRequest, collaborationEnabled,
  hasMoreFindings, loadingMoreFindings, onLoadMoreFindings,
}: {
  id: string;
  status: ScanStatus;
  /** The API's short reason when the scan failed; null otherwise. */
  failureReason: string | null;
  running: boolean;
  findings: Finding[];
  /** The scan's operations, so a finding's operation_id resolves to a route. */
  operations: Operation[];
  plan: PlanRow[];
  coverage: CoverageRow[];
  /** Steps the engine reported it could not do, with its own message for each. */
  gaps: ScanEvent[];
  /** Tools the latest run was asked for but never ran, per the run's own record. */
  notRun: string[];
  resources: ResourceRow[];
  /** How many request-trace rows the latest run archived; the rows load lazily. */
  traceCount: number;
  /** Run number the trace belongs to, or null when the scan has never run. */
  latestRun: number | null;
  diff: RunDiff | null;
  /** The run list read failed: the run-derived panels say so rather than "none". */
  runsFailed: boolean;
  runsHasMore?: boolean;
  runsLoadingMore?: boolean;
  onLoadMoreRuns?: () => void;
  /** The diff read failed (a scan with fewer than two runs is not a failure). */
  diffFailed: boolean;
  /** The findings read failed: an empty list means "could not load", not "clean". */
  findingsFailed: boolean;
  runs: ScanRun[];
  /** Assignment and discussion for live findings, keyed by fingerprint. */
  work: Map<string, FindingWork>;
  onMark: (finding: Finding, verdict: Verdict) => Promise<Finding | null>;
  onSaveWork: (fingerprint: string, input: FindingWorkInput) => Promise<void>;
  onDeleteWork: (fingerprint: string) => Promise<void>;
  onAddComment: (fingerprint: string, body: string) => Promise<void>;
  onDeleteComment: (commentId: string) => Promise<void>;
  /** Narrows the page's run scope to one check and opens the RunPanel. */
  onRetest: (check: string) => void;
  /** Assignment and discussion are a premium capability. */
  collaborationEnabled: boolean;
  hasMoreFindings?: boolean;
  loadingMoreFindings?: boolean;
  onLoadMoreFindings?: () => void;
  /** The section open in the URL; the workspace follows it. */
  active?: string;
  onActiveChange?: (id: string) => void;
  /** A "needs attention" row asked the findings list to narrow itself. */
  focusRequest?: { sev?: Severity; dismissed?: boolean; nonce: number };
}) {
  const workQueue = useMemo(() => workRows(work, findings), [work, findings]);
  const emptyFindings = running
    ? "Findings will appear here as the scan progresses."
    : status === "draft"
      ? "Configure your inputs, then authorize a run to start collecting evidence."
      : status === "completed"
        ? "This run recorded no findings. Review endpoint coverage to see what was tested."
        : status === "failed"
          ? failureReason
            ? `This run failed: ${failureReason} — the activity log above has the details.`
            : "This run failed before it recorded findings; the activity log above has the details."
          : `This scan ended as "${status}" before recording findings.`;
  // The gaps panel says what a run could not do. Findings is where the user
  // lands, so it carries the pointer instead of leaving the caveat a tab away.
  const caveat = gaps.length
    ? gapCountLabel(gaps)
    : notRun.length
      ? "Requested tools did not run"
      : null;
  const findingsMeta = [
    findingsFailed && findings.length === 0 ? "Could not load" : `${findings.length} recorded`,
    ...(caveat ? [caveat] : []),
  ].join(" · ");
  // A plan the run asked for and did not get is not an invitation to enable it.
  const planSkipped = gaps.find((e) => e.stage === "plan_skipped");
  const createdResourceCount = resources.filter((resource) => resource.source !== "predefined").length;
  const suppliedResourceCount = resources.length - createdResourceCount;

  return (
    <div className="results-workspace">
      <SidebarWorkspace
        id="results"
        title="Scan results"
        eyebrow="Review"
        description="Explore findings, endpoint coverage, and changes between runs."
        defaultSection="findings"
        active={active}
        onActiveChange={onActiveChange}
        sections={[
          // Its own section, not a footnote under coverage: a run that could not
          // test something is a caveat on every result below it.
          ...(gaps.length || notRun.length
            ? [
                {
                  id: "gaps",
                  label: "What this run could not do",
                  meta: gaps.length
                    ? gapCountLabel(gaps)
                    : "Requested tools did not run",
                  content: <RunGaps events={gaps} notRun={notRun} />,
                },
              ]
            : []),
          // Only when there is something to work: an empty queue is noise, and
          // assignment lives on each finding anyway.
          ...(collaborationEnabled && workQueue.length
            ? [
                {
                  id: "work",
                  label: "Work queue",
                  premium: true,
                  meta: `${workQueue.length} assigned`,
                  content: <WorkQueue rows={workQueue} />,
                },
              ]
            : []),
          {
            id: "findings",
            label: "Findings",
            meta: findingsMeta,
            content: findings.length ? (
              <FindingsSection
                id={id}
                findings={findings}
                operations={operations}
                work={work}
                onMark={onMark}
                focusRequest={focusRequest}
                onSaveWork={onSaveWork}
                onDeleteWork={onDeleteWork}
                onAddComment={onAddComment}
                onDeleteComment={onDeleteComment}
                onRetest={onRetest}
                collaborationEnabled={collaborationEnabled}
                hasMoreFindings={hasMoreFindings}
                loadingMoreFindings={loadingMoreFindings}
                onLoadMoreFindings={onLoadMoreFindings}
                resultRevision={`${status}:${latestRun ?? 0}`}
                beforeList={!running ? <AskPanel id={id} /> : undefined}
              />
            ) : findingsFailed ? (
              <EmptyResult title="Could not load findings">
                Could not read this scan&apos;s findings, so an empty list would be
                misleading. Reload the page to try again.
              </EmptyResult>
            ) : (
              <EmptyResult title={running ? "Scan in progress" : "No findings recorded"}>{emptyFindings}</EmptyResult>
            ),
          },
          {
            id: "security-review", label: "Security improvements",
            meta: runs[0]?.security_review?.status === "completed"
              ? `${runs[0].security_review.suggestions.length} AI ${runs[0].security_review.suggestions.length === 1 ? "suggestion" : "suggestions"}` : "AI design review",
            content: <SecurityDesignReview review={runs[0]?.security_review}
              pending={running && runs[0]?.options?.security_review === true} />,
          },
          {
            id: "mutations",
            label: "Request log",
            meta: traceCount ? `${traceCount} calls` : "No calls recorded",
            content: traceCount && latestRun !== null ? (
              <MutationTable scanId={id} runNumber={latestRun} total={traceCount} />
            ) : (
              <EmptyResult title="No calls recorded">
                Core-engine request and response traces appear here, so you can
                see exactly what was sent and what came back — including which
                writes were accepted with a 2xx response.
              </EmptyResult>
            ),
          },
          {
            id: "plan",
            label: "AI scan plan",
            meta: plan.length
              ? `${plan.length} ranked endpoints`
              : planSkipped
                ? "Planner did not run"
                : runsFailed
                  ? "Could not load"
                  : "No plan recorded",
            content: plan.length ? <PlanTable plan={plan} /> : planSkipped ? (
              <EmptyResult title="AI plan unavailable">
                {`This run asked for an AI pre-scan plan, but the planner did not run: ${planSkipped.message}`}
              </EmptyResult>
            ) : runsFailed ? (
              <EmptyResult title="Could not load the AI plan">
                Could not load the latest run. Reload the page to try again.
              </EmptyResult>
            ) : (
              <EmptyResult title="No AI plan available">
                {"Open Run now and enable Use AI or select Risk plan under Choose AI passes. The next run will record its plan here when the AI runtime is available."}
              </EmptyResult>
            ),
          },
          {
            id: "coverage",
            label: "Endpoint coverage",
            meta: runsFailed && coverage.length === 0
              ? "Could not load"
              : `${coverage.length} endpoints · latest run`,
            content: coverage.length ? (
              <CoverageTable coverage={coverage} />
            ) : runsFailed ? (
              <EmptyResult title="Could not load endpoint coverage">
                Could not load the latest run. Reload the page to try again.
              </EmptyResult>
            ) : (
              <EmptyResult title="No endpoint coverage yet">
                Coverage is saved with the run and shows requests, findings, and checks for each endpoint.
              </EmptyResult>
            ),
          },
          {
            id: "resources",
            label: "Prepared resources",
            meta: resources.length
              ? `${createdResourceCount} created · ${suppliedResourceCount} supplied`
              : "None prepared",
            content: resources.length ? <ResourceTable resources={resources} /> : (
              <EmptyResult title="No resources prepared">
                Provide an existing resource ID, or enable Test writes so the run
                can create spec-shaped prerequisites for dependent operations.
              </EmptyResult>
            ),
          },
          {
            id: "changes",
            label: "Changes",
            meta: diff
              ? `Run ${diff.from_run} → ${diff.to_run}`
              : diffFailed
                ? "Could not load"
                : "Compare consecutive runs",
            content: diff ? <RunDiffPanel diff={diff} /> : (
              <EmptyResult title={diffFailed ? "Could not load the comparison" : "No comparison available"}>
                {diffFailed
                  ? "Could not load the comparison. Reload the page to try again."
                  : "After two recorded runs, compare new, fixed, and unchanged findings here."}
              </EmptyResult>
            ),
          },
          {
            id: "history",
            label: "Run history",
            meta: runsFailed && runs.length === 0
              ? "Could not load"
              : `${runs.length} ${runs.length === 1 ? "run" : "runs"} recorded`,
            content: runs.length ? (
              <RunHistory
                runs={runs}
                hasMore={runsHasMore}
                loadingMore={runsLoadingMore}
                onLoadMore={onLoadMoreRuns}
              />
            ) : (
              <EmptyResult title={runsFailed ? "Could not load run history" : "No runs recorded"}>
                {runsFailed
                  ? "Could not load this scan's runs. Reload the page to try again."
                  : "Recorded runs will appear here with their archived findings and request counts."}
              </EmptyResult>
            ),
          },
        ]}
      />
    </div>
  );
}
