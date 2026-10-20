"use client";

import Link from "next/link";
import { useEffect, useMemo, useRef, useState } from "react";
import { api, connectionGeneration, onConnectionChange, type ScanSummary, type Severity } from "@/lib/api";
import { useConnection } from "@/lib/connection";
import { SEVERITIES } from "../components/scanShared";
import { Ago, ErrorBanner, Skel } from "../components/ui";

const ACTIVE = new Set(["queued", "running"]);
/** How many scans a page load adds; the API caps a single page at 1000. */
const SCAN_PAGE = 200;

const STATUS_FILTERS = ["all", "running", "completed", "failed", "draft"] as const;
type StatusFilter = (typeof STATUS_FILTERS)[number];

/** "60" → "1h". Coarse on purpose: the row only needs the interval's shape. */
function everyLabel(minutes: number): string {
  if (minutes % 1440 === 0) return `${minutes / 1440}d`;
  if (minutes % 60 === 0) return `${minutes / 60}h`;
  return `${minutes}m`;
}

/** Non-zero finding counts, critical first; nothing at all when the scan is clean. */
function SevCounts({ counts }: { counts?: Record<Severity, number> }) {
  if (!counts) return null;
  const shown = SEVERITIES.filter((severity) => (counts[severity] ?? 0) > 0);
  if (shown.length === 0) return null;
  return (
    <span className="sev-counts">
      {shown.map((severity) => (
        <span className={`sev-badge ${severity}`} key={severity}>
          {counts[severity]} {severity}
        </span>
      ))}
    </span>
  );
}

export default function ScansIndex() {
  const {
    ready,
    status: connectionStatus,
    refresh,
  } = useConnection();
  const [scans, setScans] = useState<ScanSummary[] | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [query, setQuery] = useState("");
  const [status, setStatus] = useState<StatusFilter>("all");
  // Bumped by Retry; the poll effect below depends on it, so it re-arms the chain.
  const [pollRun, setPollRun] = useState(0);
  const [connectionVersion, setConnectionVersion] = useState(connectionGeneration);
  const [hasMore, setHasMore] = useState(false);
  const [loadingMore, setLoadingMore] = useState(false);
  const loaded = useRef(SCAN_PAGE);

  useEffect(() => onConnectionChange(() => {
    setConnectionVersion(connectionGeneration());
    // Rows from another server or tenant must not remain visible while its
    // replacement request is pending (or if that request fails).
    setScans(null);
    setErr(null);
    loaded.current = SCAN_PAGE;
    setHasMore(false);
  }), []);

  // Keep the list fresh while anything is still running. A failed load ends the
  // chain — Retry starts it again.
  //
  // The list belongs to a connection: wait for the stored key/server to be
  // restored before the first read, and re-read whenever the connection settles
  // — otherwise a reconnect leaves the 401 answer on screen until Retry.
  useEffect(() => {
    if (!ready || connectionStatus === "checking") return;
    let alive = true;
    let timer: ReturnType<typeof setTimeout> | null = null;
    async function tick() {
      try {
        const limit = Math.min(1000, Math.max(SCAN_PAGE, loaded.current));
        const list = await api.listScans(limit, 0);
        if (!alive || connectionVersion !== connectionGeneration()) return;
        setScans(list);
        if (list.length < limit) setHasMore(false);
        else if (list.length === SCAN_PAGE) setHasMore(true);
        setErr(null);
        if (list.some((s) => ACTIVE.has(s.status))) {
          timer = setTimeout(tick, 3000);
        }
      } catch (e) {
        if (!alive || connectionVersion !== connectionGeneration()) return;
        // Keep the last list for a failure on this connection, and explain it
        // rather than rendering an empty account.
        setErr((e as Error).message);
      }
    }
    tick();
    return () => {
      alive = false;
      if (timer) clearTimeout(timer);
    };
  }, [pollRun, ready, connectionStatus, connectionVersion]);

  async function loadMore() {
    if (!scans || loadingMore) return;
    // The server/key can change while this page is in flight. Capture the
    // generation at call time and drop the response if the connection moved on;
    // appending then would splice the previous connection's rows into the new
    // account.
    const generation = connectionGeneration();
    setLoadingMore(true);
    try {
      const next = await api.listScans(SCAN_PAGE, scans.length);
      if (generation !== connectionGeneration()) return;
      setScans((prev) => (prev ? [...prev, ...next] : next));
      loaded.current = scans.length + next.length;
      setHasMore(next.length === SCAN_PAGE);
      setErr(null);
    } catch (e) {
      if (generation !== connectionGeneration()) return;
      setErr((e as Error).message);
    } finally {
      setLoadingMore(false);
    }
  }

  const list = useMemo(() => scans ?? [], [scans]);
  // Nothing loaded (or nothing survived) plus an error: that is a failure to
  // report, not an empty account.
  const failed = err !== null && list.length === 0;
  const shown = useMemo(() => {
    const q = query.trim().toLowerCase();
    return list.filter(
      (s) =>
        // "running" means in flight, which includes a scan still queued.
        (status === "all" ||
          (status === "running" ? ACTIVE.has(s.status) : s.status === status)) &&
        (q === "" || s.target_base_url.toLowerCase().includes(q)),
    );
  }, [list, query, status]);

  const retry = () => {
    setErr(null);
    void refresh();
    setPollRun((n) => n + 1);
  };

  return (
    <section className="wrap" style={{ padding: "40px 24px 80px" }}>
      <div className="eyebrow">OWASP API Top 10</div>
      <h1>API security scans</h1>
      <p className="lead">
        Upload an OpenAPI spec and two sets of credentials, then run active
        tests — BOLA, BFLA, broken auth, injection, SSRF, misconfiguration —
        against a target you own. The browser runs the fast engine scan; the CLI
        adds the heavy passes — ZAP, Kali tools, confirmation and AI review.
      </p>

      <div style={{ marginTop: 26, display: "flex", gap: 12, alignItems: "center", flexWrap: "wrap" }}>
        <Link className="btn" href="/scans/new">
          <span aria-hidden="true">+</span> New scan
        </Link>
        <Link className="btn quiet" href="/coverage">
          What we check
        </Link>
      </div>

      {err && (
        <div className="err-row">
          <ErrorBanner message={err} onClose={() => setErr(null)} />
          <button className="btn quiet sm" onClick={retry} type="button">
            Retry
          </button>
        </div>
      )}

      <div className="section-head">
        <h2>Recent scans</h2>
        {list.length > 0 && (
          <span className="count">
            {shown.length === list.length ? list.length : `${shown.length} / ${list.length}`}
          </span>
        )}
      </div>

      {list.length > 0 && (
        <div className="filters">
          {STATUS_FILTERS.map((option) => (
            <button
              key={option}
              className={`chipbtn ${status === option ? "on" : ""}`}
              onClick={() => setStatus(option)}
              aria-pressed={status === option}
              type="button"
            >
              {option}
            </button>
          ))}
          <div className="searchbox">
            <span className="icon" aria-hidden="true">⌕</span>
            <input
              type="search"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Filter by target URL…"
              aria-label="Filter scans by target URL"
            />
            {query && (
              <button className="clear" onClick={() => setQuery("")} aria-label="Clear filter">
                ✕
              </button>
            )}
          </div>
        </div>
      )}

      {scans === null && !err ? (
        <div className="scan-list" aria-busy="true" aria-label="Loading scans">
          {[0, 1, 2].map((i) => (
            <div className="scan-row" key={i}>
              <div>
                <Skel w={240} h={13} />
                <div style={{ marginTop: 7 }}>
                  <Skel w={110} h={10} />
                </div>
              </div>
              <span />
              <Skel w={70} h={18} r={5} />
            </div>
          ))}
        </div>
      ) : failed ? (
        <div className="empty">
          <div className="glyph" aria-hidden="true">⚠</div>
          <h3>Couldn’t load scans</h3>
          <p>{err}</p>
          <button className="btn" onClick={retry} type="button">
            Retry
          </button>
        </div>
      ) : list.length === 0 ? (
        <div className="empty">
          <div className="glyph" aria-hidden="true">◎</div>
          <h3>No scans yet</h3>
          <p>
            Point the scanner at the public address of an API you own. Verify
            its domain under{" "}
            <Link href="/workspace?section=domains">Workspace → Domains</Link>{" "}
            first.
          </p>
          <Link className="btn" href="/scans/new">
            Create your first scan
          </Link>
        </div>
      ) : shown.length === 0 ? (
        <p className="muted-sm">No scans match this filter.</p>
      ) : (
        <div className="scan-list">
          {shown.map((s) => (
            <Link key={s.id} href={`/scans/${s.id}`} className="scan-row">
              <span>
                <span className="target">{s.target_base_url}</span>
                {/* Several scans often share a target; the id tells them apart. */}
                <code className="scan-id" title={s.id}>
                  #{s.id.slice(0, 8)}
                </code>
                <span className="sub">
                  {"created "}
                  <Ago iso={s.created_at} />
                  {s.last_run_at && (
                    <>
                      {" · last run "}
                      <Ago iso={s.last_run_at} />
                    </>
                  )}
                  {s.schedule_minutes
                    ? ` · scheduled every ${everyLabel(s.schedule_minutes)}`
                    : null}
                </span>
                <SevCounts counts={s.finding_counts} />
              </span>
              {ACTIVE.has(s.status) ? (
                <span
                  className="minibar"
                  role="progressbar"
                  aria-valuenow={s.progress}
                  aria-valuemin={0}
                  aria-valuemax={100}
                  aria-label={`Scan progress ${s.progress}%`}
                >
                  <i style={{ width: `${s.progress}%` }} />
                </span>
              ) : (
                <span />
              )}
              <span className={`st-chip ${s.status}`}>{s.status}</span>
            </Link>
          ))}
        </div>
      )}

      {hasMore && scans && scans.length > 0 && (
        <button
          className="btn quiet show-more"
          type="button"
          onClick={() => void loadMore()}
          disabled={loadingMore}
        >
          {loadingMore ? "Loading older scans…" : "Load older scans"}
        </button>
      )}
    </section>
  );
}
