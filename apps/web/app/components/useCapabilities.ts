"use client";

import { useCallback, useEffect, useState } from "react";
import {
  api,
  connectionGeneration,
  onConnectionChange,
  type Capabilities,
} from "@/lib/api";

/**
 * What the tenant's plan includes. The shared `Capabilities` type predates this
 * field, so it is declared here and read off the response with a cast: an API
 * older than the entitlement simply omits it, which reads as "unknown", not
 * "locked".
 */
export interface TenantEntitlement {
  available: boolean;
  plan: "premium" | "free";
  reason: string | null;
}

type Passes = Capabilities["passes"];

interface Snapshot {
  passes: Passes;
  premium: TenantEntitlement | null;
}

export interface CapabilitiesState {
  passes: Passes;
  premium: TenantEntitlement | null;
  loading: boolean;
  error: string | null;
  reload: () => void;
}

/** The server caches its probes for 30s; the wizard and the panel share one. */
const CACHE_MS = 30_000;

/**
 * Scoped to one connection. A capability answer belongs to a server *and* a
 * tenant: showing the previous server's or key's answer after a reconnect is
 * how a locked feature reads as available (or the reverse).
 */
let cached: { at: number; generation: number; value: Snapshot } | null = null;
let inflight: { generation: number; promise: Promise<Snapshot> } | null = null;
const snapshotListeners = new Set<(value: Snapshot) => void>();

async function fetchSnapshot(): Promise<Snapshot> {
  const raw = (await api.capabilities()) as Capabilities & { premium?: TenantEntitlement };
  return { passes: raw.passes ?? {}, premium: raw.premium ?? null };
}

function freshCached(): Snapshot | null {
  const generation = connectionGeneration();
  return cached && cached.generation === generation && Date.now() - cached.at < CACHE_MS
    ? cached.value
    : null;
}

function load(force: boolean): Promise<Snapshot> {
  const generation = connectionGeneration();
  if (!force && cached && cached.generation === generation && Date.now() - cached.at < CACHE_MS) {
    return Promise.resolve(cached.value);
  }
  if (inflight && inflight.generation === generation) return inflight.promise;
  const request = fetchSnapshot().then((value) => {
    // A response that arrived after the connection changed must not seed the
    // next connection's cache.
    if (connectionGeneration() === generation) {
      cached = { at: Date.now(), generation, value };
      // A retry can be initiated by any consumer. Keep already mounted run,
      // schedule, export and question controls on the same entitlement answer.
      for (const listener of snapshotListeners) listener(value);
    }
    return value;
  });
  inflight = { generation, promise: request };
  void request.then(
    () => {
      if (inflight?.promise === request) inflight = null;
    },
    () => {
      if (inflight?.promise === request) inflight = null;
    },
  );
  return request;
}

/**
 * Deployment capabilities plus the tenant's entitlement. One request is shared
 * by every caller on this connection for 30 seconds; a reconnect drops the
 * cache, and `reload()` bypasses it. Rejections become `error` — the hook never
 * throws, and a panel that cannot check still leaves the run's own gates in
 * charge.
 */
export function useCapabilities(): CapabilitiesState {
  const initial = freshCached();
  const [state, setState] = useState<Snapshot & { loading: boolean; error: string | null }>(
    () => ({
      passes: initial?.passes ?? {},
      premium: initial?.premium ?? null,
      loading: initial === null,
      error: null,
    }),
  );
  const [nonce, setNonce] = useState(0);
  const [generation, setGeneration] = useState(connectionGeneration);

  // A reconnect (new server, key, or an explicit retry) invalidates the answer.
  useEffect(() => onConnectionChange(() => setGeneration(connectionGeneration())), []);

  useEffect(() => {
    const update = (value: Snapshot) => setState({ ...value, loading: false, error: null });
    snapshotListeners.add(update);
    return () => { snapshotListeners.delete(update); };
  }, []);

  useEffect(() => {
    let cancelled = false;
    const snapshot = freshCached();
    if (nonce === 0 && snapshot) {
      // The module cache answered already; no probe and no loading flicker.
      setState({ ...snapshot, loading: false, error: null });
      return;
    }
    setState((prev) => ({ ...prev, loading: true, error: null }));
    load(nonce > 0).then(
      (value) => {
        if (!cancelled && generation === connectionGeneration()) setState({ ...value, loading: false, error: null });
      },
      (reason: unknown) => {
        if (!cancelled) {
          setState((prev) => ({
            ...prev,
            loading: false,
            error: (reason as Error).message ?? "could not check feature availability",
          }));
        }
      },
    );
    return () => {
      cancelled = true;
    };
  }, [nonce, generation]);

  const reload = useCallback(() => setNonce((n) => n + 1), []);

  return { ...state, reload };
}
