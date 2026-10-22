"use client";

import { memo, useCallback, useEffect, useId, useMemo, useRef, useState, type ReactNode } from "react";
import { api, type Finding, type FindingWork as FindingWorkItem, type FindingWorkInput, type Operation, type Severity, type Verdict } from "@/lib/api";
import { useUrlState } from "@/lib/useUrlState";
import { Ago } from "../../components/ui";
import { ExportMenu } from "../../components/ExportMenu";
import { PlanBadge } from "../../components/PlanBadge";
import { FindingWork } from "./FindingWork";
import { revealRequestLog } from "./RunInsights";
import {
  CONFIDENCE_HINT,
  CONFIDENCE_RANK,
  RANK,
  SEVERITIES,
} from "../../components/scanShared";

/** How many matching findings the list renders before asking to show more. */
const PAGE_SIZE = 25;
/** Server page size for a filtered query; a full page means "load more". */
const FILTER_PAGE = 500;
/** The server's per-request ceiling; a refresh re-reads at most this many rows. */
const MAX_FILTER_ROWS = 5000;

/** The query the work queue wants the findings list filtered to, if any. */
let findingFocus: string | null = null;
const findingFocusListeners = new Set<(query: string | null) => void>();

function setFindingFocus(query: string | null) {
  findingFocus = query;
  for (const listener of findingFocusListeners) listener(query);
}

/**
 * Show Findings filtered to one title: activate its workspace tab — the ids are
 * the ones ResultsWorkspace declares — and scroll it into view. Like the
 * request-log handoff, the two sections are siblings owned elsewhere, so the
 * query goes through the store above rather than through props.
 */
export function revealFinding(query: string) {
  setFindingFocus(query);
  document.getElementById("results-tab-findings")?.click();
  requestAnimationFrame(() =>
    document
      .getElementById("results-panel-findings")
      ?.scrollIntoView({ block: "start" }),
  );
}

type SortKey = "severity" | "endpoint" | "check" | "newest";

const VERDICTS = new Set<string>(["unreviewed", "confirmed", "dismissed"]);
const SORTS = new Set<string>(["severity", "endpoint", "check", "newest"]);

/** The filter state a shared link encodes, read back on first render. */
function initialFilters() {
  const params =
    typeof window === "undefined"
      ? new URLSearchParams()
      : new URLSearchParams(window.location.search);
  const sev = params.get("sev");
  const verdict = params.get("verdict");
  const sort = params.get("sort");
  return {
    sevFilter: (sev && SEVERITIES.includes(sev as Severity)
      ? sev
      : "all") as Severity | "all",
    checkFilter: params.get("check") || "all",
    endpointFilter: params.get("endpoint") || "all",
    verdictFilter: (verdict && VERDICTS.has(verdict)
      ? verdict
      : "all") as Verdict | "all",
    sortBy: (sort && SORTS.has(sort) ? sort : "severity") as SortKey,
    verifiedOnly: params.get("verified") === "1",
    premiumOnly: params.get("premium") === "1",
    query: params.get("q") ?? "",
    showDismissed: params.get("dismissed") === "1",
    grouped: params.get("group") === "check",
  };
}

/** An endpoint as this list names it: "METHOD /path". */
interface Endpoint {
  method: string;
  path: string;
  label: string;
}

function evidenceText(value: unknown): string | null {
  return typeof value === "string" && value ? value : null;
}

/**
 * The endpoint a finding is about: the operation it names, else the method and
 * route its evidence recorded — adjunct and confirmation findings carry no
 * operation id, but they do carry what they hit.
 */
function endpointOf(f: Finding, operations: Map<string, Operation>): Endpoint | null {
  const op = f.operation_id ? operations.get(f.operation_id) : undefined;
  const method = (op?.method ?? evidenceText(f.evidence.method))?.toUpperCase();
  const path = op?.path ?? evidenceText(f.evidence.route) ?? evidenceText(f.evidence.path);
  if (!method || !path) return null;
  return { method, path, label: `${method} ${path}` };
}

/** Request-log sequence numbers this finding's evidence cites. */
function traceSequences(f: Finding): number[] {
  const raw = f.evidence.trace;
  if (!Array.isArray(raw)) return [];
  return raw.map(Number).filter((n) => Number.isInteger(n));
}

/** The default order: worst first, and proven before leads at equal severity. */
const byRank = (a: Finding, b: Finding) =>
  RANK[a.severity] - RANK[b.severity] ||
  CONFIDENCE_RANK[a.confidence] - CONFIDENCE_RANK[b.confidence];

/**
 * The remediation to show once for a whole check group, or null when the
 * members differ. The texts are compared with each member's own path blanked
 * out, because a remediation names the route it applies to.
 */
function sharedRemediation(
  members: Finding[],
  endpoints: Map<string, Endpoint | null>,
): string | null {
  const first = members[0];
  if (!first?.remediation) return null;
  const shaped = (f: Finding) => {
    const path = endpoints.get(f.id)?.path;
    return path && path.length > 1 ? f.remediation.split(path).join("{path}") : f.remediation;
  };
  const key = shaped(first);
  return members.every((f) => shaped(f) === key) ? first.remediation : null;
}

function EndpointCode({ endpoint }: { endpoint: Endpoint | null }) {
  if (!endpoint) return null;
  return (
    <code className="finding-ep">
      <span className="cov-method">{endpoint.method}</span> {endpoint.path}
    </code>
  );
}

/** The two triage buttons, shared by the full card and the compact group rows. */
function VerdictButtons({
  finding,
  onMark,
}: {
  finding: Finding;
  onMark: (f: Finding, verdict: Verdict) => unknown;
}) {
  return (
    <div className="fbtns">
      <button
        className={`btn quiet sm ${finding.verdict === "confirmed" ? "on" : ""}`}
        onClick={() => onMark(finding, "confirmed")}
        aria-pressed={finding.verdict === "confirmed"}
      >
        {finding.verdict === "confirmed" ? "✓ Confirmed" : "Confirm"}
      </button>
      <button
        className={`btn quiet sm ${finding.verdict === "dismissed" ? "on" : ""}`}
        onClick={() => onMark(finding, "dismissed")}
        aria-pressed={finding.verdict === "dismissed"}
      >
        {finding.verdict === "dismissed" ? "✓ False positive" : "False positive"}
      </button>
    </div>
  );
}

/** Opens the request log filtered to the calls this finding's evidence cites. */
function RequestsButton({ finding }: { finding: Finding }) {
  const sequences = traceSequences(finding);
  if (sequences.length === 0) return null;
  return (
    <button
      className="btn quiet sm trace-btn"
      onClick={() => revealRequestLog({ title: finding.title, sequences })}
      title="Show the requests this finding's evidence cites"
    >
      Requests ({sequences.length})
    </button>
  );
}

/**
 * The findings list with its severity counts, filters and verdict controls.
 *
 * Filter state (severity, check, endpoint, verdict, confidence, search,
 * show-dismissed) lives here rather than on the page, so typing in the search
 * box does not re-render the spec, credential and coverage panels above it.
 *
 * A scan can hold hundreds of findings, so the list renders a page at a time,
 * can be grouped by check, and every finding names the endpoint it is about.
 */
function FindingsSectionImpl({
  id,
  findings,
  operations,
  work,
  onMark,
  focusRequest,
  onSaveWork,
  onDeleteWork,
  onAddComment,
  onDeleteComment,
  onRetest,
  collaborationEnabled,
  beforeList,
  hasMoreFindings,
  loadingMoreFindings,
  onLoadMoreFindings,
  resultRevision,
}: {
  id: string;
  /**
   * Changes whenever the scan's result set may have changed (a new run, the
   * run finishing, findings arriving). A filtered list re-reads its query then.
   */
  resultRevision?: string;
  /** The scan's operations, so a finding's operation_id resolves to its route. */
  operations: Operation[];
  findings: Finding[];
  /** Assignment and discussion, keyed by fingerprint. */
  work: Map<string, FindingWorkItem>;
  /** Resolves with the row the server stored, or null when the change failed. */
  onMark: (f: Finding, verdict: Verdict) => Promise<Finding | null>;
  onSaveWork: (fingerprint: string, input: FindingWorkInput) => Promise<void>;
  onDeleteWork: (fingerprint: string) => Promise<void>;
  onAddComment: (fingerprint: string, body: string) => Promise<void>;
  onDeleteComment: (commentId: string) => Promise<void>;
  /** Narrows the page's run scope to one check and opens the RunPanel. */
  onRetest: (check: string) => void;
  /** Assignment and discussion are a premium capability. */
  collaborationEnabled: boolean;
  /**
   * A "needs attention" row asking the already-mounted list to narrow itself.
   * The nonce makes a second request for the same filter apply again.
   */
  focusRequest?: { sev?: Severity; dismissed?: boolean; nonce: number };
  beforeList?: ReactNode;
  /** Older findings still exist on the server. */
  hasMoreFindings?: boolean;
  loadingMoreFindings?: boolean;
  onLoadMoreFindings?: () => void;
}) {
  const [sevFilter, setSevFilter] = useState<Severity | "all">("all");
  const [checkFilter, setCheckFilter] = useState<string>("all");
  const [endpointFilter, setEndpointFilter] = useState<string>("all");
  const [verdictFilter, setVerdictFilter] = useState<Verdict | "all">("all");
  const [sortBy, setSortBy] = useState<SortKey>("severity");
  const [grouped, setGrouped] = useState(false);
  const [verifiedOnly, setVerifiedOnly] = useState(false);
  const [premiumOnly, setPremiumOnly] = useState(false);
  const [query, setQuery] = useState("");
  const [showDismissed, setShowDismissed] = useState(false);
  const [shown, setShown] = useState(PAGE_SIZE);
  const [moreFiltersOpen, setMoreFiltersOpen] = useState(false);
  const filterPanelId = useId();
  const searchRef = useRef<HTMLInputElement>(null);
  const [filtersReady, setFiltersReady] = useState(false);
  const [composing, setComposing] = useState(false);
  const { set: setUrlState } = useUrlState();
  useEffect(() => {
    const restore = () => {
      const initial = initialFilters();
      setSevFilter(initial.sevFilter);
      setCheckFilter(initial.checkFilter);
      setEndpointFilter(initial.endpointFilter);
      setVerdictFilter(initial.verdictFilter);
      setSortBy(initial.sortBy);
      setVerifiedOnly(initial.verifiedOnly);
      setPremiumOnly(initial.premiumOnly);
      setQuery(initial.query);
      setShowDismissed(initial.showDismissed);
      setGrouped(initial.grouped);
      setFiltersReady(true);
    };
    restore();
    window.addEventListener("popstate", restore);
    return () => window.removeEventListener("popstate", restore);
  }, []);
  useEffect(() => {
    if (!filtersReady || composing) return;
    setUrlState({
      sev: sevFilter === "all" ? null : sevFilter,
      check: checkFilter === "all" ? null : checkFilter,
      endpoint: endpointFilter === "all" ? null : endpointFilter,
      verdict: verdictFilter === "all" ? null : verdictFilter,
      sort: sortBy === "severity" ? null : sortBy,
      verified: verifiedOnly ? "1" : null,
      premium: premiumOnly ? "1" : null,
      q: query || null,
      dismissed: showDismissed ? "1" : null,
      group: grouped ? "check" : null,
    });
  }, [filtersReady, composing, setUrlState, sevFilter, checkFilter, endpointFilter, verdictFilter, sortBy, verifiedOnly, premiumOnly, query, showDismissed, grouped]);
  const extraFilterCount = [checkFilter !== "all", endpointFilter !== "all", verdictFilter !== "all", premiumOnly, showDismissed].filter(Boolean).length;
  useEffect(() => {
    if (checkFilter !== "all" || endpointFilter !== "all" || verdictFilter !== "all" || premiumOnly || showDismissed) setMoreFiltersOpen(true);
  }, [checkFilter, endpointFilter, verdictFilter, premiumOnly, showDismissed]);
  // When a filter is active the server owns the filtered set. It is read a
  // page at a time: a permanent 5,000-row window silently hid matches beyond
  // it, and a page of dismissed rows could fill the whole window.
  const [serverRows, setServerRows] = useState<Finding[] | null>(null);
  const [serverLoading, setServerLoading] = useState(false);
  const [serverLoadingMore, setServerLoadingMore] = useState(false);
  const [serverHasMore, setServerHasMore] = useState(false);
  const [serverError, setServerError] = useState<string | null>(null);
  const [retryNonce, setRetryNonce] = useState(0);
  // Bumped after a stored triage change, so the filtered query is re-read.
  const [refreshNonce, setRefreshNonce] = useState(0);
  // A filter change supersedes any filtered page request still in flight.
  const serverGeneration = useRef(0);
  const source = serverRows ?? findings;

  // The attention summary sits above the workspace, so its rows act on a list
  // that is already mounted. A nonce (rather than the value alone) makes a
  // second click on the same severity apply again.
  useEffect(() => {
    if (!focusRequest) return;
    if (focusRequest.sev) setSevFilter(focusRequest.sev);
    if (focusRequest.dismissed) setShowDismissed(true);
  }, [focusRequest]);

  // The work queue hands a finding title over while this section is mounted
  // (its panel is only hidden), so the filter updates without a reload.
  useEffect(() => {
    const listener = (value: string | null) => setQuery(value ?? "");
    findingFocusListeners.add(listener);
    if (findingFocus) setQuery(findingFocus);
    return () => {
      findingFocusListeners.delete(listener);
      if (findingFocusListeners.size === 0) findingFocus = null;
    };
  }, []);

  const endpoints = useMemo(() => {
    const byId = new Map(operations.map((op) => [op.id, op]));
    const map = new Map<string, Endpoint | null>();
    for (const f of source) map.set(f.id, endpointOf(f, byId));
    return map;
  }, [source, operations]);

  const dismissedCount = useMemo(
    () => source.filter((f) => f.verdict === "dismissed").length,
    [source],
  );
  const activeCount = source.length - dismissedCount;
  const availableFindings = showDismissed
    ? source
    : source.filter((f) => f.verdict !== "dismissed");
  const availableCounts = useMemo(() => {
    const c: Record<string, number> = {};
    for (const f of availableFindings) c[f.severity] = (c[f.severity] ?? 0) + 1;
    return c;
  }, [availableFindings]);

  const verifiedCount = useMemo(
    () => availableFindings.filter((f) => f.confidence === "verified").length,
    [availableFindings],
  );

  const premiumCount = useMemo(
    () => availableFindings.filter((f) => f.premium).length,
    [availableFindings],
  );

  // Facet options are counted over the findings the severity and dismissed
  // filters leave, so their numbers agree with the chips beside them.
  const checkOptions = useMemo(() => {
    const c = new Map<string, number>();
    for (const f of availableFindings) c.set(f.check, (c.get(f.check) ?? 0) + 1);
    return [...c].sort((a, b) => a[0].localeCompare(b[0]));
  }, [availableFindings]);

  const endpointOptions = useMemo(() => {
    const c = new Map<string, number>();
    for (const f of availableFindings) {
      const endpoint = endpoints.get(f.id);
      if (endpoint) c.set(endpoint.label, (c.get(endpoint.label) ?? 0) + 1);
    }
    return [...c].sort((a, b) => a[0].localeCompare(b[0]));
  }, [availableFindings, endpoints]);

  const matches = useCallback(
    (f: Finding, includeDismissed: boolean) => {
      const q = query.trim().toLowerCase();
      const endpoint = endpoints.get(f.id);
      return (
        (sevFilter === "all" || f.severity === sevFilter) &&
        (checkFilter === "all" || f.check === checkFilter) &&
        (endpointFilter === "all" || endpoint?.label === endpointFilter) &&
        (verdictFilter === "all" || f.verdict === verdictFilter) &&
        (includeDismissed || f.verdict !== "dismissed") &&
        (!verifiedOnly || f.confidence === "verified") &&
        (!premiumOnly || f.premium) &&
        (!q ||
          f.title.toLowerCase().includes(q) ||
          f.description.toLowerCase().includes(q) ||
          f.check.toLowerCase().includes(q) ||
          f.remediation.toLowerCase().includes(q) ||
          (endpoint?.label ?? "").toLowerCase().includes(q) ||
          (f.owasp_id ?? "").toLowerCase().includes(q))
      );
    },
    [
      query,
      sevFilter,
      checkFilter,
      endpointFilter,
      verdictFilter,
      verifiedOnly,
      premiumOnly,
      endpoints,
    ],
  );

  // Any active filter makes the server own the filter/full-set question. The
  // local filters below then only refine the returned rows (the endpoint label
  // and the local verdict changes).
  const serverFiltered =
    sevFilter !== "all" ||
    checkFilter !== "all" ||
    endpointFilter !== "all" ||
    verdictFilter !== "all" ||
    verifiedOnly ||
    premiumOnly ||
    query.trim() !== "" ||
    showDismissed ||
    sortBy !== "severity";

  const visible = useMemo(() => {
    // In filtered mode the server already applied every predicate and the
    // ordering. Re-running the local filters would drop rows whose endpoint
    // label is not in the loaded page's map. Before the first response there
    // are no filtered rows to show.
    if (serverFiltered) return serverRows ?? [];
    const rows = source.filter((f) => matches(f, showDismissed));
    const endpointLabel = (f: Finding) => endpoints.get(f.id)?.label ?? "";
    // `serverFiltered` aliases `sortBy !== "severity"`, and control-flow
    // analysis narrows sortBy to the remaining literal after the early return.
    // The cast keeps the switch over the full SortKey union.
    switch (sortBy as SortKey) {
      case "endpoint":
        return rows.sort(
          (a, b) => endpointLabel(a).localeCompare(endpointLabel(b)) || byRank(a, b),
        );
      case "check":
        return rows.sort((a, b) => a.check.localeCompare(b.check) || byRank(a, b));
      case "newest":
        return rows.sort((a, b) => b.created_at.localeCompare(a.created_at) || byRank(a, b));
      default:
        return rows.sort(byRank);
    }
  }, [serverFiltered, serverRows, source, matches, showDismissed, sortBy, endpoints]);

  const hiddenDismissed = useMemo(() => {
    if (showDismissed) return 0;
    return source.filter((f) => f.verdict === "dismissed" && matches(f, true)).length;
  }, [source, showDismissed, matches]);

  const filtering =
    sevFilter !== "all" ||
    checkFilter !== "all" ||
    endpointFilter !== "all" ||
    verdictFilter !== "all" ||
    verifiedOnly ||
    premiumOnly ||
    query.trim() !== "";

  const filterParams = useMemo(
    () => ({
      severity: sevFilter === "all" ? undefined : sevFilter,
      check: checkFilter === "all" ? undefined : checkFilter,
      // The label itself, not an operation id looked up from loaded rows: an
      // off-page finding, or one with no operation (adjunct evidence), still
      // narrows correctly.
      endpoint: endpointFilter === "all" ? undefined : endpointFilter,
      verdict: verdictFilter === "all" ? undefined : verdictFilter,
      confidence: verifiedOnly ? ("verified" as const) : undefined,
      premium: premiumOnly ? true : undefined,
      q: query.trim() || undefined,
      sort: sortBy,
      include_dismissed: showDismissed,
    }),
    [
      sevFilter,
      checkFilter,
      endpointFilter,
      verdictFilter,
      verifiedOnly,
      premiumOnly,
      query,
      sortBy,
      showDismissed,
    ],
  );
  const queryKey = useMemo(() => JSON.stringify(filterParams), [filterParams]);

  // What the loaded unfiltered page looks like plus the parent's revision: a
  // completed run, new findings or a stored verdict all change it, and the
  // filtered list must then re-read its query instead of freezing.
  const findingsSignature = useMemo(
    () => findings.map((f) => `${f.id}:${f.verdict}`).join("|"),
    [findings],
  );
  const revision = `${resultRevision ?? ""}#${findingsSignature}#${refreshNonce}`;

  // Rows already loaded for the current query; a refresh re-reads that many so
  // paging the user already did is not lost. Synced in an effect (declared
  // before the fetch effect, so it runs first) rather than written in render.
  const loadedCount = useRef(0);
  useEffect(() => {
    loadedCount.current = serverRows?.length ?? 0;
  }, [serverRows]);
  // The query whose rows are on screen — not merely the last one requested: a
  // revision arriving before the first answer of a new query must not keep
  // the previous query's rows up as if they answered it.
  const displayedKey = useRef<string | null>(null);

  useEffect(() => {
    if (composing) {
      serverGeneration.current += 1;
      return;
    }
    if (!serverFiltered) {
      serverGeneration.current += 1;
      displayedKey.current = null;
      setServerRows(null);
      setServerLoading(false);
      setServerLoadingMore(false);
      setServerHasMore(false);
      setServerError(null);
      return;
    }
    // Every effect run supersedes whatever was in flight — the first page of
    // an older query and any load-more page for it.
    const generation = ++serverGeneration.current;
    setServerLoadingMore(false);
    const sameQuery = displayedKey.current === queryKey;
    const limit = sameQuery
      ? Math.min(MAX_FILTER_ROWS, Math.max(FILTER_PAGE, loadedCount.current))
      : FILTER_PAGE;
    if (!sameQuery) setServerLoading(true);
    setServerError(null);
    let alive = true;
    const timer = setTimeout(
      () => {
        // A refresh of the same query keeps its rows on screen meanwhile.
        void api
          .getFindings(id, limit, 0, filterParams)
          .then((rows) => {
            if (!alive || generation !== serverGeneration.current) return;
            displayedKey.current = queryKey;
            setServerRows(rows);
            setServerHasMore(rows.length === limit);
          })
          .catch((error: unknown) => {
            if (!alive || generation !== serverGeneration.current) return;
            // The previous filter's page no longer answers this one; drop it
            // rather than presenting it under the new controls.
            if (!sameQuery) {
              displayedKey.current = queryKey;
              setServerRows([]);
            }
            setServerHasMore(false);
            setServerError((error as Error).message);
          })
          .finally(() => {
            if (alive && generation === serverGeneration.current) {
              setServerLoading(false);
            }
          });
      },
      sameQuery ? 0 : 250,
    );
    return () => {
      alive = false;
      clearTimeout(timer);
    };
  }, [id, filterParams, queryKey, serverFiltered, retryNonce, revision, composing]);

  const mark = useCallback(
    async (finding: Finding, verdict: Verdict) => {
      // The server's answer is the truth: a refused change leaves the row as
      // it was, and a stored one shows the verdict the server actually kept
      // (clicking the active verdict clears it).
      const updated = await onMark(finding, verdict);
      if (!updated) return;
      const stillListed =
        (showDismissed || updated.verdict !== "dismissed") &&
        (verdictFilter === "all" || updated.verdict === verdictFilter);
      setServerRows((prev) =>
        prev
          ? stillListed
            ? prev.map((row) => (row.id === updated.id ? updated : row))
            : prev.filter((row) => row.id !== updated.id)
          : prev,
      );
      // Re-read the query so its pages and counts agree with the server.
      setRefreshNonce((n) => n + 1);
    },
    [onMark, showDismissed, verdictFilter],
  );

  const loadMoreFiltered = useCallback(async () => {
    if (!serverRows || serverLoadingMore) return;
    // A filter change (or refresh) while this page is in flight bumps the
    // generation; the old query's page must not land in the new list.
    const generation = serverGeneration.current;
    setServerLoadingMore(true);
    try {
      const next = await api.getFindings(
        id,
        FILTER_PAGE,
        serverRows.length,
        filterParams,
      );
      if (generation !== serverGeneration.current) return;
      setServerRows((prev) => {
        if (!prev) return next;
        const seen = new Set(prev.map((row) => row.id));
        return [...prev, ...next.filter((row) => !seen.has(row.id))];
      });
      setServerHasMore(next.length === FILTER_PAGE);
    } catch (error: unknown) {
      if (generation !== serverGeneration.current) return;
      setServerError((error as Error).message);
    } finally {
      if (generation === serverGeneration.current) setServerLoadingMore(false);
    }
  }, [id, filterParams, serverRows, serverLoadingMore]);

  // A new filter set means a new list, so paging starts over with it.
  useEffect(() => {
    setShown(PAGE_SIZE);
  }, [
    sevFilter,
    checkFilter,
    endpointFilter,
    verdictFilter,
    verifiedOnly,
    premiumOnly,
    query,
    showDismissed,
    sortBy,
  ]);

  const paged = serverFiltered ? visible : visible.slice(0, shown);
  const remaining = serverFiltered ? 0 : visible.length - paged.length;

  // Groups come from the rendered page, so a group's members are what is shown.
  const groups = grouped
    ? [
        ...paged.reduce((byCheck, f) => {
          const members = byCheck.get(f.check);
          if (members) members.push(f);
          else byCheck.set(f.check, [f]);
          return byCheck;
        }, new Map<string, Finding[]>()),
      ].map(([check, members]) => ({
        check,
        members,
        remediation: sharedRemediation(members, endpoints),
      }))
    : null;

  if (source.length === 0 && !serverFiltered) return null;

  return (
    <>
      <div className="section-head findings-heading">
        <div>
          <h2>Findings</h2>
          <p className="muted-sm">{source.length} loaded · {activeCount} active{dismissedCount > 0 ? ` · ${dismissedCount} dismissed` : ""}</p>
        </div>
        <ExportMenu id={id} />
      </div>

      <div className="findings-toolbar">
        <div className="searchbox">
          <span className="icon" aria-hidden="true">⌕</span>
          <input ref={searchRef} type="search" value={query} onChange={(e) => setQuery(e.target.value)} onCompositionStart={() => setComposing(true)} onCompositionEnd={(e) => { setQuery(e.currentTarget.value); setComposing(false); }} placeholder="Search findings…" aria-label="Search findings" />
          {query && <button className="clear" onClick={() => { setQuery(""); searchRef.current?.focus(); }} aria-label="Clear search">✕</button>}
        </div>
        <label className="sort-pick">
          <span>Sort</span>
          <select value={sortBy} onChange={(e) => setSortBy(e.target.value as SortKey)} aria-label="Sort findings">
            <option value="severity">Severity</option>
            <option value="endpoint">Endpoint</option>
            <option value="check">Check</option>
            <option value="newest">Newest</option>
          </select>
        </label>
        <button type="button" className={`btn quiet sm${extraFilterCount ? " filters-active" : ""}`} aria-expanded={moreFiltersOpen} aria-controls={filterPanelId} onClick={() => setMoreFiltersOpen((open) => !open)}>
          More filters{extraFilterCount ? ` · ${extraFilterCount} active` : ""}
        </button>
      </div>
      <div className="filters findings-severity" role="group" aria-label="Filter findings by severity and evidence">
        <button
          className={`chipbtn ${sevFilter === "all" ? "on" : ""}`}
          onClick={() => setSevFilter("all")}
          aria-pressed={sevFilter === "all"}
        >
          all<span className="c">{availableFindings.length}</span>
        </button>
        {SEVERITIES.filter((s) => availableCounts[s]).map((s) => (
          <button
            key={s}
            className={`chipbtn ${s} ${sevFilter === s ? "on" : ""}`}
            onClick={() => setSevFilter(sevFilter === s ? "all" : s)}
            aria-pressed={sevFilter === s}
          >
            {s}<span className="c">{availableCounts[s]}</span>
          </button>
        ))}

        {verifiedCount > 0 && (
          <button
            className={`chipbtn verified ${verifiedOnly ? "on" : ""}`}
            onClick={() => setVerifiedOnly((v) => !v)}
            aria-pressed={verifiedOnly}
            title={CONFIDENCE_HINT.verified}
          >
            verified only<span className="c">{verifiedCount}</span>
          </button>
        )}

      </div>
      <div className="filters findings-extra-filters" id={filterPanelId} hidden={!moreFiltersOpen}>
        {premiumCount > 0 && (
          <button
            className={`chipbtn premium ${premiumOnly ? "on" : ""}`}
            onClick={() => setPremiumOnly((v) => !v)}
            aria-pressed={premiumOnly}
            title="Findings produced by premium-tier checks (premium:true run)"
          >
            premium only<span className="c">{premiumCount}</span>
          </button>
        )}

        <select
          className="pick"
          value={checkFilter}
          onChange={(e) => setCheckFilter(e.target.value)}
          aria-label="Filter findings by check"
        >
          <option value="all">any check ({availableFindings.length})</option>
          {checkOptions.map(([check, n]) => (
            <option key={check} value={check}>
              {check} ({n})
            </option>
          ))}
        </select>

        <select
          className="pick"
          value={endpointFilter}
          onChange={(e) => setEndpointFilter(e.target.value)}
          aria-label="Filter findings by endpoint"
        >
          <option value="all">any endpoint ({availableFindings.length})</option>
          {endpointOptions.map(([label, n]) => (
            <option key={label} value={label}>
              {label} ({n})
            </option>
          ))}
        </select>

        <select
          className="pick"
          value={verdictFilter}
          onChange={(e) => setVerdictFilter(e.target.value as Verdict | "all")}
          aria-label="Filter findings by verdict"
        >
          <option value="all">any verdict</option>
          <option value="unreviewed">unreviewed</option>
          <option value="confirmed">confirmed</option>
          <option value="dismissed">false positive</option>
        </select>

        <label
          className="toggle-sm group-toggle"
          title="Collapse the list into one section per check"
        >
          <input
            type="checkbox"
            checked={grouped}
            onChange={(e) => setGrouped(e.target.checked)}
            aria-label="Group findings by check"
          />
          <span>group by check</span>
        </label>

        <label
          className="toggle-sm dismissed-toggle"
          title={
            dismissedCount +
            " dismissed finding" +
            (dismissedCount === 1 ? "" : "s") +
            " hidden by default"
          }
        >
          <input
            type="checkbox"
            checked={showDismissed}
            onChange={(e) => setShowDismissed(e.target.checked)}
            aria-label={"Show dismissed findings (" + dismissedCount + ")"}
          />
          <span>show dismissed</span>
          <span className="toggle-count">{dismissedCount}</span>
        </label>
      </div>

      <details className="findings-help">
        <summary>How to read findings</summary>
      <div className="legend" aria-label="Badge legend">
        <span className="item">
          <span className="conf-badge verified">verified</span>
          {CONFIDENCE_HINT.verified}
        </span>
        <span className="item">
          <span className="conf-badge heuristic">heuristic</span>
          {CONFIDENCE_HINT.heuristic}
        </span>
        <span className="item">
          <span
            className="dismissed-badge"
            title="AI adjudication can assign this when enabled, or a reviewer can mark it manually"
          >
            dismissed
          </span>
          AI adjudication (when enabled) or a reviewer marked it as a false positive; it remains saved and is hidden by default
        </span>
        {premiumCount > 0 && (
          <span className="item">
            <PlanBadge premium />
            Produced by a premium-tier check
          </span>
        )}
      </div>

      </details>

      {beforeList}

      <div className="findings">
        {groups
          ? groups.map((g) => (
              <details className="finding-group" key={g.check}>
                <summary>
                  <span className="fg-check">{g.check}</span>
                  <span className="fg-count">{g.members.length}</span>
                  <span className="fg-sevs">
                    {SEVERITIES.filter((s) => g.members.some((f) => f.severity === s)).map(
                      (s) => (
                        <span className={`sev-badge ${s}`} key={s}>
                          {g.members.filter((f) => f.severity === s).length} {s}
                        </span>
                      ),
                    )}
                  </span>
                </summary>
                {g.remediation && (
                  <div className="fix">
                    <span className="fix-tag">Fix</span>
                    <p>{g.remediation}</p>
                  </div>
                )}
                <ul className="fg-members">
                  {g.members.map((f) => (
                    <li key={f.id} className={f.verdict === "dismissed" ? "dim" : ""}>
                      <span className={`sev-badge ${f.severity}`}>{f.severity}</span>
                      <span
                        className={`conf-badge ${f.confidence}`}
                        title={CONFIDENCE_HINT[f.confidence]}
                      >
                        {f.confidence}
                      </span>
                      <span className="fg-title">{f.title}</span>
                      <EndpointCode endpoint={endpoints.get(f.id) ?? null} />
                      {f.verdict !== "unreviewed" && (
                        <span className={`vd ${f.verdict}`}>{f.verdict}</span>
                      )}
                      {!g.remediation && f.remediation && (
                        <p className="fg-fix">{f.remediation}</p>
                      )}
                      <RequestsButton finding={f} />
                      <VerdictButtons finding={f} onMark={mark} />
                      {collaborationEnabled && (
                        <FindingWork
                          id={id}
                          finding={f}
                          work={work.get(f.fingerprint)}
                          endpoint={endpoints.get(f.id)?.label ?? null}
                          onSaveWork={onSaveWork}
                          onDeleteWork={onDeleteWork}
                          onAddComment={onAddComment}
                          onDeleteComment={onDeleteComment}
                          onRetest={onRetest}
                        />
                      )}
                    </li>
                  ))}
                </ul>
              </details>
            ))
          : paged.map((f) => (
              <article
                className={`finding ${f.severity} ${f.verdict === "dismissed" ? "dim" : ""}`}
                key={f.id}
              >
                <div className="fhead">
                  <span className={`sev-badge ${f.severity}`}>{f.severity}</span>
                  <span
                    className={`conf-badge ${f.confidence}`}
                    title={CONFIDENCE_HINT[f.confidence]}
                  >
                    {f.confidence}
                  </span>
                  {f.owasp_id && <span className="owasp">{f.owasp_id}</span>}
                  {f.premium && (
                    <PlanBadge premium />
                  )}
                  <span className="ftitle">{f.title}</span>
                  {f.verdict !== "unreviewed" && (
                    <span className={`vd ${f.verdict}`}>{f.verdict}</span>
                  )}
                </div>
                <p className="fdesc">{f.description}</p>
                {f.remediation && (
                  <div className="fix">
                    <span className="fix-tag">Fix</span>
                    <p>{f.remediation}</p>
                    {f.references.length > 0 && (
                      <div className="refs">
                        {f.references.map((url) => (
                          <a
                            key={url}
                            href={url}
                            target="_blank"
                            rel="noreferrer noopener"
                          >
                            {url}
                          </a>
                        ))}
                      </div>
                    )}
                  </div>
                )}
                {f.ai_rationale && (
                  <p className="ai-note">
                    <span className="ai-tag">AI</span> {f.ai_rationale}
                  </p>
                )}
                <div className="fmeta">
                  <EndpointCode endpoint={endpoints.get(f.id) ?? null} />
                  <span>{f.check}</span>
                  <span aria-hidden="true">·</span>
                  <span>
                    <Ago iso={f.created_at} />
                  </span>
                  <RequestsButton finding={f} />
                </div>
                <details className="ev">
                  <summary>Evidence</summary>
                  <pre>{JSON.stringify(f.evidence, null, 2)}</pre>
                </details>
                <VerdictButtons finding={f} onMark={mark} />
                {collaborationEnabled && (
                  <FindingWork
                    id={id}
                    finding={f}
                    work={work.get(f.fingerprint)}
                    endpoint={endpoints.get(f.id)?.label ?? null}
                    onSaveWork={onSaveWork}
                    onDeleteWork={onDeleteWork}
                    onAddComment={onAddComment}
                    onDeleteComment={onDeleteComment}
                    onRetest={onRetest}
                  />
                )}
              </article>
            ))}
      </div>

      {remaining > 0 && (
        <button
          className="btn quiet show-more"
          onClick={() => setShown((n) => n + PAGE_SIZE)}
        >
          Show {Math.min(PAGE_SIZE, remaining)} more ({remaining} left)
        </button>
      )}

      {hasMoreFindings && !serverFiltered && (
        <button
          className="btn quiet show-more"
          type="button"
          onClick={onLoadMoreFindings}
          disabled={loadingMoreFindings}
        >
          {loadingMoreFindings
            ? "Loading older findings…"
            : `Load older findings (${source.length} loaded)`}
        </button>
      )}

      {serverFiltered && serverLoading && (
        <p className="hint" role="status">Loading filtered findings…</p>
      )}

      {serverFiltered && serverError && (
        <div className="banner error" role="alert">
          <span>Could not load filtered findings: {serverError}</span>
          <button
            className="btn quiet"
            type="button"
            onClick={() => setRetryNonce((n) => n + 1)}
          >
            Retry
          </button>
        </div>
      )}

      {serverFiltered && serverHasMore && (
        <button
          className="btn quiet show-more"
          type="button"
          onClick={() => void loadMoreFiltered()}
          disabled={serverLoadingMore}
        >
          {serverLoadingMore
            ? "Loading more…"
            : `Load more filtered findings (${visible.length} loaded)`}
        </button>
      )}

      {visible.length === 0 && !serverLoading && !serverError && (
        <div className="empty">
          <div className="glyph" aria-hidden="true">⌕</div>
          {hiddenDismissed > 0 ? (
            <>
              <h3>{hiddenDismissed} matching finding{hiddenDismissed === 1 ? " is" : "s are"} hidden</h3>
              <p>AI adjudication (when enabled) or a reviewer can mark findings dismissed. Show them to review the full result set.</p>
              <button className="btn quiet" onClick={() => setShowDismissed(true)}>
                Show dismissed findings
              </button>
            </>
          ) : (
            <>
              <h3>No findings match</h3>
              <p>Try a different severity, drop the verified-only filter, or clear the search.</p>
            </>
          )}
          {filtering && hiddenDismissed === 0 && (
            <button
              className="btn quiet"
              onClick={() => {
                setSevFilter("all");
                setCheckFilter("all");
                setEndpointFilter("all");
                setVerdictFilter("all");
                setVerifiedOnly(false);
                setPremiumOnly(false);
                setQuery("");
              }}
            >
              Clear filters
            </button>
          )}
        </div>
      )}
    </>
  );
}

export const FindingsSection = memo(FindingsSectionImpl);
