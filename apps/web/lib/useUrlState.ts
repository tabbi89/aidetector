"use client";

import { useRouter } from "next/navigation";
import { useCallback, useEffect, useState } from "react";

/** A query-string value; null/undefined/"" removes the key. */
export type UrlValue = string | null | undefined;

type Listener = (search: string) => void;

const listeners = new Set<Listener>();

/**
 * The query string this tab last wrote.
 *
 * `router.replace` does not promise that `window.location` is updated by the
 * time the next keystroke arrives, so successive writes build on this value
 * rather than on the browser's (possibly stale) copy. It is also what lets two
 * components on one page — the tab owner and the findings filters — observe
 * each other's writes without waiting for a navigation round-trip.
 */
let latest: string | null = null;
let latestPath: string | null = null;

function browserSearch(): string {
  return typeof window === "undefined"
    ? ""
    : window.location.search.replace(/^\?/, "");
}

/** Keep the cache tied to the route: a new scan starts with its own URL. */
function ensurePath() {
  if (typeof window === "undefined") return;
  const path = window.location.pathname;
  if (latestPath !== path) {
    latestPath = path;
    latest = browserSearch();
  }
}

function current(): string {
  ensurePath();
  return latest ?? browserSearch();
}

function publish(next: string) {
  latest = next;
  for (const listener of listeners) listener(next);
}

/**
 * Read and write shareable view state in the query string.
 *
 * Writes use `router.replace(..., { scroll: false })` so a filter change does
 * not push a history entry or jump the page. Defaults are never written: pass
 * null (or "") to remove a key, which is what makes a shared link reproduce the
 * exact view without appending every default.
 */
export function useUrlState() {
  const router = useRouter();
  // Read on mount rather than during render, so the server's empty search and
  // the client's first render agree.
  const [search, setSearch] = useState("");

  useEffect(() => {
    const receive = (next: string) => setSearch(next);
    listeners.add(receive);
    ensurePath();
    receive(current());

    const onPop = () => {
      latestPath = window.location.pathname;
      latest = browserSearch();
      for (const listener of listeners) listener(latest);
    };
    window.addEventListener("popstate", onPop);
    return () => {
      listeners.delete(receive);
      window.removeEventListener("popstate", onPop);
    };
  }, []);

  const get = useCallback(
    (key: string) => new URLSearchParams(search).get(key),
    [search],
  );

  const set = useCallback(
    (updates: Record<string, UrlValue>) => {
      const next = new URLSearchParams(current());
      for (const [key, value] of Object.entries(updates)) {
        if (value === null || value === undefined || value === "") next.delete(key);
        else next.set(key, value);
      }
      const query = next.toString();
      if (query === current()) return;
      router.replace(
        `${window.location.pathname}${query ? `?${query}` : ""}`,
        { scroll: false },
      );
      publish(query);
    },
    [router],
  );

  return { get, set, search };
}