"use client";

import {
  useCallback,
  useEffect,
  useRef,
  useState,
  type Dispatch,
  type SetStateAction,
} from "react";
import {
  api,
  type Cost,
  type Finding,
  type FindingSummaryState,
  type RunDiff,
  type Scan,
  type ScanEvent,
  type ScanRun,
} from "@/lib/api";
import { ACTIVE } from "../../components/scanShared";

/** The poll cadence, and the ceiling a failing poll backs off to. */
const POLL_MS = 1000;
const MAX_POLL_MS = 15000;
/** Findings grow during a run, but far slower than the progress line. */
const FINDINGS_MS = 5000;
/** How many findings a page load adds; the API caps a single page at 5000. */
const FINDINGS_PAGE = 500;
/** How many runs a page load adds; the API caps a single page at 200. */
const RUNS_PAGE = 50;

/**
 * Keep the previous value when a poll returns identical data.
 *
 * The progress hook re-fetches every second while a scan is active, and each
 * response deserialises into fresh objects. Holding the old reference when
 * nothing changed is what lets the memoised panels below skip re-rendering —
 * without it, every tick re-renders the whole tree.
 */
function keepIfSame<T>(prev: T, next: T): T {
  return JSON.stringify(prev) === JSON.stringify(next) ? prev : next;
}

/**
 * `req` throws the API's `detail` string — or the bare status when the body has
 * none. The scan routes answer 404 with "scan not found".
 */
function isNotFound(reason: unknown): boolean {
  const m = (reason as Error).message.trim().toLowerCase();
  return m === "scan not found" || m === "404" || m.startsWith("404 ");
}

/**
 * `GET /diff` has nothing to return until the scan has two runs: the API answers
 * 409, the e2e fixture 404. Neither means the connection is down.
 */
function isNoDiffYet(reason: unknown): boolean {
  const m = (reason as Error).message.trim().toLowerCase();
  return m.includes("diff") || m.includes("no runs") || m === "404" || m === "409";
}

/** What one scan poll saw. */
type Poll = { ok: boolean; missing: boolean };

export interface ScanProgress {
  scan: Scan | null;
  events: ScanEvent[];
  connected: boolean;
  staleSeconds: number | null;
  notFound: boolean;
  error: string | null;
  reload: () => Promise<void>;
  /** Lets an action that returned the updated scan write it without a refetch. */
  setScan: Dispatch<SetStateAction<Scan | null>>;
}

/**
 * The scan and its activity log, polled while the worker is still writing.
 *
 * This is the only read that repeats every second. Everything else on the page
 * fetches once, or when the section that shows it is opened.
 */
export function useScanProgress(id: string): ScanProgress {
  const [scan, setScan] = useState<Scan | null>(null);
  // The first read needs the full scan (operations, credentials, schedule).
  // After it lands, the one-second poll only fetches the progress row.
  const fullLoaded = useRef(false);
  const [events, setEvents] = useState<ScanEvent[]>([]);
  // Poll health. False means the page is showing the previous values after a
  // failed poll; the header says so rather than claiming to be live.
  const [connected, setConnected] = useState(true);
  const [staleSeconds, setStaleSeconds] = useState<number | null>(null);
  // The scan is gone: there is nothing to poll for and nothing to show.
  const [notFound, setNotFound] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async (): Promise<Poll> => {
    // Each read is isolated: the scan itself is required, the events list keeps
    // its previous value when it fails, so one flaky call cannot blank the page.
    // The expensive full read happens once; every later tick is the light one.
    const [s, ev] = await Promise.allSettled([
      fullLoaded.current ? api.getScanProgress(id) : api.getScan(id),
      api.getEvents(id, 500),
    ]);

    if (s.status === "rejected") {
      if (isNotFound(s.reason)) {
        setNotFound(true);
        return { ok: false, missing: true };
      }
      setError((s.reason as Error).message);
      return { ok: false, missing: false };
    }

    const value = s.value;
    if ("operations" in value) {
      fullLoaded.current = true;
      setScan((prev) => keepIfSame(prev, value));
    } else {
      setScan((prev) => {
        if (!prev) return prev;
        const next: Scan = {
          ...prev,
          status: value.status,
          progress: value.progress,
          cancel_requested: value.cancel_requested,
          failure_reason: value.failure_reason,
          cost_cents: value.cost_cents,
          // The progress row carries cents; the header renders cost_usd.
          cost_usd: value.cost_cents / 100,
          schedule_minutes: value.schedule_minutes,
          next_run_at: value.next_run_at,
        };
        return keepIfSame(prev, next);
      });
    }
    setError(null);
    let ok = true;
    if (ev.status === "fulfilled") setEvents((prev) => keepIfSame(prev, ev.value));
    else ok = false;
    return { ok, missing: false };
  }, [id]);

  // Whether the chain should keep re-arming, derived from state rather than a
  // local variable: a chain that ended on a terminal status had no way to notice
  // a re-run, so starting one from this page left the progress UI frozen at
  // "queued" until a reload. A null scan means no poll has answered yet — keep
  // trying so the page can recover instead of sitting dead.
  const polling = scan === null || ACTIVE.has(scan.status);

  // Poll while the scan is active, backing off while polls fail; a hidden tab
  // stops polling and becoming visible resumes it.
  useEffect(() => {
    let alive = true;
    let failures = 0;
    let timer: ReturnType<typeof setTimeout> | null = null;

    async function tick() {
      const res = await load();
      if (!alive) return;
      if (res.missing) return; // the scan is gone — nothing left to poll for
      setConnected(res.ok);
      if (document.hidden) return; // resumed by visibilitychange
      failures = res.ok ? 0 : failures + 1;
      // 1s, 2s, 4s … capped, so a failing API is not hammered.
      const wait =
        failures === 0
          ? POLL_MS
          : Math.min(POLL_MS * 2 ** (failures - 1), MAX_POLL_MS);
      if (polling) {
        timer = setTimeout(tick, wait);
      }
    }

    function onVisibility() {
      if (document.hidden) {
        if (timer) clearTimeout(timer);
        timer = null;
        return;
      }
      failures = 0;
      void tick();
    }

    // The first read happens even in a background tab — a page opened with
    // cmd-click must not sit on a skeleton; only the repeat polling pauses.
    void tick();
    document.addEventListener("visibilitychange", onVisibility);
    return () => {
      alive = false;
      document.removeEventListener("visibilitychange", onVisibility);
      if (timer) clearTimeout(timer);
    };
  }, [load, polling]);

  const reload = useCallback(async () => {
    // An action may have changed more than the progress fields; get the full
    // row again, then let the poll fall back to the light read.
    fullLoaded.current = false;
    const res = await load();
    if (!res.missing) setConnected(res.ok);
  }, [load]);

  // Re-render once a second while disconnected, so "last update Ns ago" counts
  // up: the poll itself is backing off, which is too coarse a clock for that.
  useEffect(() => {
    if (connected) {
      setStaleSeconds(null);
      return;
    }
    setStaleSeconds(0);
    const t = setInterval(() => setStaleSeconds((n) => (n ?? 0) + 1), POLL_MS);
    return () => clearInterval(t);
  }, [connected]);

  return {
    scan,
    events,
    connected,
    staleSeconds,
    notFound,
    error,
    reload,
    setScan,
  };
}

export interface FindingsData {
  findings: Finding[];
  /** The read failed: an empty list means "could not load", not "clean". */
  failed: boolean;
  /** A read has succeeded: before that an empty list means "not read yet". */
  hasRead: boolean;
  setFindings: Dispatch<SetStateAction<Finding[]>>;
  refresh: () => Promise<void>;
  /** Older findings remain on the server; this fetches the next page. */
  hasMore: boolean;
  loadingMore: boolean;
  loadMore: () => Promise<void>;
  /** Counts over every finding, not just the loaded page — or why there are none. */
  summary: FindingSummaryState;
  /** Re-read the counts after a mutation (triage) or a completed run. */
  refreshSummary: () => Promise<void>;
}

/**
 * The findings list, fetched once and then refreshed on a slow tick only while
 * the scan is active (findings grow as checks finish).
 */
export function useFindings(id: string, active: boolean): FindingsData {
  const [findings, setFindings] = useState<Finding[]>([]);
  const [failed, setFailed] = useState(false);
  const [hasRead, setHasRead] = useState(false);
  const [hasMore, setHasMore] = useState(false);
  const [loadingMore, setLoadingMore] = useState(false);
  const [summary, setSummary] = useState<FindingSummaryState>({ status: "loading" });
  // Poll refreshes and explicit post-triage refreshes race; only the newest
  // summary read may land.
  const summaryGeneration = useRef(0);
  // A poll tick and an explicit refresh can overlap; only the newest read may
  // land, or a slow older response would restore findings the run has moved on
  // from (a completed run's list overwritten by its pre-run one).
  const generation = useRef(0);
  const loaded = useRef(FINDINGS_PAGE);

  const refresh = useCallback(async () => {
    const mine = ++generation.current;
    const mineSummary = ++summaryGeneration.current;
    // The summary settles on its own: a failed findings read must not leave
    // it "loading" forever, and a failed summary read must not leave the
    // previous counts on screen as if they still described this result set.
    const summaryRead = api.getFindingSummary(id).then(
      (next) => {
        if (mineSummary === summaryGeneration.current) {
          setSummary({ status: "ready", summary: next });
        }
      },
      () => {
        if (mineSummary === summaryGeneration.current) {
          setSummary({ status: "unavailable" });
        }
      },
    );
    try {
      // 5,000 is the documented completeness cap for the unfiltered view;
      // filtered views page through the server instead of widening this window.
      const limit = Math.min(5000, Math.max(FINDINGS_PAGE, loaded.current));
      const next = await api.getFindings(id, limit, 0);
      await summaryRead;
      if (mine !== generation.current) return;
      setFindings((prev) => keepIfSame(prev, next));
      loaded.current = next.length;
      setHasMore(next.length === limit);
      setFailed(false);
      setHasRead(true);
    } catch {
      await summaryRead;
      if (mine !== generation.current) return;
      setFailed(true);
    }
  }, [id]);

  const refreshSummary = useCallback(async () => {
    const mine = ++summaryGeneration.current;
    try {
      const next = await api.getFindingSummary(id);
      if (mine === summaryGeneration.current) setSummary({ status: "ready", summary: next });
    } catch {
      // Explicitly unavailable, never the previous run's numbers.
      if (mine === summaryGeneration.current) setSummary({ status: "unavailable" });
    }
  }, [id]);

  const loadMore = useCallback(async () => {
    if (loadingMore) return;
    setLoadingMore(true);
    const mine = generation.current;
    try {
      const next = await api.getFindings(id, FINDINGS_PAGE, loaded.current);
      if (mine !== generation.current) return;
      setFindings((prev) => {
        const seen = new Set(prev.map((finding) => finding.id));
        return [...prev, ...next.filter((finding) => !seen.has(finding.id))];
      });
      loaded.current += next.length;
      setHasMore(next.length === FINDINGS_PAGE);
      setFailed(false);
    } catch {
      setFailed(true);
    } finally {
      setLoadingMore(false);
    }
  }, [id, loadingMore]);

  useEffect(() => {
    let alive = true;
    let timer: ReturnType<typeof setTimeout> | null = null;

    async function tick() {
      await refresh();
      if (!alive || !active) return;
      timer = setTimeout(tick, FINDINGS_MS);
    }

    void tick();
    return () => {
      alive = false;
      if (timer) clearTimeout(timer);
    };
  }, [refresh, active]);

  return {
    findings,
    failed,
    hasRead,
    setFindings,
    refresh,
    refreshSummary,
    hasMore,
    loadingMore,
    loadMore,
    summary,
  };
}

/** Which of the optional run reads the open sections currently need. */
export interface RunResourcesWanted {
  runs: boolean;
  diff: boolean;
  cost: boolean;
}

export interface RunResources {
  runs: ScanRun[];
  /** 409 until the scan has two runs — a normal state, not an error. */
  diff: RunDiff | null;
  cost: Cost | null;
  /** Which optional read last failed, so a panel can say "could not load". */
  failed: { runs: boolean; diff: boolean; cost: boolean };
  /** Older runs remain on the server; this fetches the next page. */
  hasMoreRuns: boolean;
  loadingMoreRuns: boolean;
  loadMoreRuns: () => Promise<void>;
  /** Drop the cache and re-read whatever is wanted now. */
  refresh: () => void;
}

/**
 * The heavier run-derived reads, fetched only when a section that shows them is
 * open. Each result is cached until the newest run number changes or an action
 * explicitly refreshes it, so opening a section twice does not refetch.
 */
export function useRunResources(
  id: string,
  wanted: RunResourcesWanted,
): RunResources {
  const [runs, setRuns] = useState<ScanRun[]>([]);
  const [runHasMore, setRunHasMore] = useState(false);
  const [runsLoadingMore, setRunsLoadingMore] = useState(false);
  const [diff, setDiff] = useState<RunDiff | null>(null);
  const [cost, setCost] = useState<Cost | null>(null);
  const [failed, setFailed] = useState({
    runs: false,
    diff: false,
    cost: false,
  });
  // The newest run number is the cache key for diff and cost.
  const [runKey, setRunKey] = useState<number | null>(null);
  const [nonce, setNonce] = useState(0);

  // Cached promises, not "started" flags. A flag set before the response
  // arrives makes StrictMode's replay and a quick tab switch skip the only
  // request in flight and show an empty panel forever. A rejected promise is
  // dropped, so reopening the section retries.
  const runsRequest = useRef<Promise<ScanRun[]> | null>(null);
  const diffRequest = useRef<{
    key: number | null;
    promise: Promise<RunDiff | null>;
  } | null>(null);
  const costRequest = useRef<{ key: number | null; promise: Promise<Cost> } | null>(null);
  // Requests from a superseded generation may still be in flight. Without this,
  // a slow pre-run response that lands after a refresh overwrites the new run's
  // coverage/history — exactly the stale data the refresh was meant to replace.
  const requestGeneration = useRef(0);

  const refresh = useCallback(() => {
    requestGeneration.current += 1;
    runsRequest.current = null;
    diffRequest.current = null;
    costRequest.current = null;
    setNonce((n) => n + 1);
  }, []);

  const loadMoreRuns = useCallback(async () => {
    if (runsLoadingMore) return;
    setRunsLoadingMore(true);
    const generation = requestGeneration.current;
    try {
      const next = await api.getRuns(id, RUNS_PAGE, runs.length);
      if (generation !== requestGeneration.current) return;
      setRuns((prev) => {
        const seen = new Set(prev.map((run) => run.id));
        return [...prev, ...next.filter((run) => !seen.has(run.id))];
      });
      setRunHasMore(next.length === RUNS_PAGE);
      setFailed((prev) => (prev.runs ? { ...prev, runs: false } : prev));
    } catch {
      setFailed((prev) => (prev.runs ? prev : { ...prev, runs: true }));
    } finally {
      setRunsLoadingMore(false);
    }
  }, [id, runs.length, runsLoadingMore]);

  useEffect(() => {
    if (!wanted.runs) return;
    if (!runsRequest.current) {
      const generation = requestGeneration.current;
      const request = api.getRuns(id, RUNS_PAGE, 0).then(
        (next) => {
          if (generation !== requestGeneration.current) return next;
          setRuns((prev) => keepIfSame(prev, next));
          setRunHasMore(next.length === RUNS_PAGE);
          setFailed((prev) => (prev.runs ? { ...prev, runs: false } : prev));
          setRunKey(next[0]?.run_number ?? null);
          return next;
        },
        (reason: unknown) => {
          if (generation !== requestGeneration.current) throw reason;
          runsRequest.current = null;
          setFailed((prev) => (prev.runs ? prev : { ...prev, runs: true }));
          throw reason;
        },
      );
      runsRequest.current = request;
      // The stored promise is observed by the next mount; this keeps a
      // rejected request from surfacing as an unhandled rejection meanwhile.
      void request.catch(() => undefined);
    }
  }, [id, wanted.runs, nonce]);

  useEffect(() => {
    if (!wanted.diff) return;
    if (diffRequest.current?.key === runKey) return;
    const generation = requestGeneration.current;
    const request: Promise<RunDiff | null> = api.getDiff(id).then(
      (next) => {
        if (generation !== requestGeneration.current || diffRequest.current?.promise !== request) return next;
        setDiff((prev) => keepIfSame(prev, next));
        setFailed((prev) => (prev.diff ? { ...prev, diff: false } : prev));
        return next;
      },
      (reason: unknown) => {
        if (generation !== requestGeneration.current || diffRequest.current?.promise !== request) throw reason;
        if (isNoDiffYet(reason)) {
          // Fewer than two runs is the normal pre-comparison state, not a
          // connection failure.
          setDiff((prev) => keepIfSame(prev, null));
          setFailed((prev) => (prev.diff ? { ...prev, diff: false } : prev));
          return null;
        }
        diffRequest.current = null; // reopening retries
        setFailed((prev) => (prev.diff ? prev : { ...prev, diff: true }));
        throw reason;
      },
    );
    diffRequest.current = { key: runKey, promise: request };
    void request.catch(() => undefined);
  }, [id, wanted.diff, runKey, nonce]);

  useEffect(() => {
    if (!wanted.cost) return;
    if (costRequest.current?.key === runKey) return;
    const generation = requestGeneration.current;
    // A new run key also supersedes the previous read without an explicit
    // refresh, so generation alone cannot decide which response is current.
    const request: Promise<Cost> = api.getCost(id).then(
      (next) => {
        if (generation !== requestGeneration.current || costRequest.current?.promise !== request) return next;
        setCost((prev) => keepIfSame(prev, next));
        setFailed((prev) => (prev.cost ? { ...prev, cost: false } : prev));
        return next;
      },
      (reason: unknown) => {
        if (generation !== requestGeneration.current || costRequest.current?.promise !== request) throw reason;
        costRequest.current = null; // reopening retries
        setFailed((prev) => (prev.cost ? prev : { ...prev, cost: true }));
        throw reason;
      },
    );
    costRequest.current = { key: runKey, promise: request };
    void request.catch(() => undefined);
  }, [id, wanted.cost, runKey, nonce]);

  return {
    runs,
    diff,
    cost,
    failed,
    refresh,
    hasMoreRuns: runHasMore,
    loadingMoreRuns: runsLoadingMore,
    loadMoreRuns,
  };
}
