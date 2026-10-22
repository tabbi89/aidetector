// Transport for the runpentests FastAPI service: base URL, API key, errors and
// the two fetch paths (JSON and file). Feature modules build on `request`.
const BASE = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

/** Base URL of the FastAPI service, fixed at build time. */
export const API_BASE = BASE;

//: Bumped whenever the key changes. Module caches (capabilities) key
//: on it so an answer from one connection is never shown for another.
let connectionEpoch = 0;
const connectionListeners = new Set<() => void>();

/** Run `listener` on every connection change (key, or explicit reconnect). */
export function onConnectionChange(listener: () => void): () => void {
  connectionListeners.add(listener);
  return () => { connectionListeners.delete(listener); };
}

function bumpConnection() {
  connectionEpoch += 1;
  for (const listener of connectionListeners) {
    try {
      listener();
    } catch {
      /* a listener must not break the transport */
    }
  }
}

/** The server this tab talks to (NEXT_PUBLIC_API_URL). */
export function getServerUrl(): string { return BASE; }

/** Which connection the current requests belong to. */
export function connectionGeneration(): number { return connectionEpoch; }

/**
 * Invalidate connection-scoped caches even when the key is unchanged — a new
 * sign-in after a rejected session must re-ask the server.
 */
export function refreshConnection(): void { bumpConnection(); }

let apiKey = "";
/**
 * Kept in memory only. Reloading the page clears the key; persistence is the
 * connection layer's decision (sessionStorage, this tab only).
 */
export function setApiKey(value: string) {
  if (value === apiKey) return;
  apiKey = value;
  bumpConnection();
}

/** The key `request` sends as `X-API-Key`; empty when none is set. */
export function getApiKey(): string { return apiKey; }

/** Whether a key is set, without exposing it. */
export function hasApiKey(): boolean { return apiKey !== ""; }

const unauthorizedListeners = new Set<() => void>();

/**
 * Run `listener` whenever a response comes back 401; returns the unsubscribe.
 * The key is left alone — deciding what a rejected key means is the caller's.
 */
export function onUnauthorized(listener: () => void): () => void {
  unauthorizedListeners.add(listener);
  return () => { unauthorizedListeners.delete(listener); };
}

function reportUnauthorized() {
  for (const listener of unauthorizedListeners) {
    try {
      listener();
    } catch {
      /* a listener must not mask the response error */
    }
  }
}

/**
 * A failed API call. `message` is the server's `detail` — or the status code
 * when there is no body — so call sites showing `(e as Error).message` keep
 * their text.
 */
export class ApiError extends Error {
  readonly status: number;
  /** FastAPI validation `type` for a 422 field error; null otherwise. */
  readonly code: string | null;
  /** Per-field messages from a 422, keyed by the last `loc` element. */
  readonly fields: Record<string, string[]>;

  constructor(
    message: string,
    status: number,
    code: string | null = null,
    fields: Record<string, string[]> = {},
  ) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
    this.fields = fields;
  }
}

/** `RequestInit` plus this client's timeout and cancellation options. */
export interface RequestOptions extends RequestInit {
  signal?: AbortSignal;
  /** How long to wait before aborting; defaults to 30 seconds. */
  timeoutMs?: number;
}

const DEFAULT_TIMEOUT_MS = 30_000;

/**
 * Turn a failed response into an `ApiError`. FastAPI reports failures as a
 * `detail` string and 422s as a list of `{loc, msg, type}` entries; the string
 * form is the text the UI has always displayed.
 */
async function apiError(res: Response): Promise<ApiError> {
  let detail: unknown;
  try {
    const body = await res.json();
    detail = body?.detail;
  } catch {
    /* not JSON — fall through to the status code */
  }
  if (typeof detail === "string") return new ApiError(detail, res.status);
  if (detail === undefined) return new ApiError(`${res.status}`, res.status);
  if (Array.isArray(detail)) {
    const fields: Record<string, string[]> = {};
    let code: string | null = null;
    for (const item of detail as Array<Record<string, unknown>>) {
      const loc = Array.isArray(item?.loc) ? item.loc : [];
      const field = loc.length ? String(loc[loc.length - 1]) : "body";
      const msg = typeof item?.msg === "string" ? item.msg : JSON.stringify(item);
      (fields[field] ??= []).push(msg);
      if (code === null && typeof item?.type === "string") code = item.type;
    }
    return new ApiError(JSON.stringify(detail), res.status, code, fields);
  }
  return new ApiError(JSON.stringify(detail), res.status);
}

/** A caller's signal and the timeout signal, as one abort source. */
function combineSignals(caller: AbortSignal | null | undefined, timeout: AbortSignal): AbortSignal {
  if (!caller) return timeout;
  if (typeof AbortSignal.any === "function") return AbortSignal.any([caller, timeout]);
  // Older browsers: mirror either abort onto one controller.
  const combined = new AbortController();
  const abort = () => combined.abort();
  caller.addEventListener("abort", abort, { once: true });
  timeout.addEventListener("abort", abort, { once: true });
  if (caller.aborted || timeout.aborted) combined.abort();
  return combined.signal;
}

/**
 * Start a request's timeout and combine it with the caller's signal. The
 * returned `timedOut` tells the catch block whether an abort was ours.
 */
function startRequest(init: RequestOptions | undefined): {
  init: Omit<RequestOptions, "signal" | "timeoutMs">;
  signal: AbortSignal;
  timedOut: () => boolean;
  done: () => void;
} {
  const { timeoutMs = DEFAULT_TIMEOUT_MS, signal: caller, ...rest } = init ?? {};
  const controller = new AbortController();
  let timedOut = false;
  const timer = setTimeout(() => {
    timedOut = true;
    controller.abort();
  }, timeoutMs);
  return {
    init: rest,
    signal: combineSignals(caller, controller.signal),
    timedOut: () => timedOut,
    done: () => clearTimeout(timer),
  };
}

/**
 * `fetch` rejects with a bare TypeError ("Failed to fetch") when the server is
 * down, unreachable, or answered without CORS headers. Say which server, so the
 * message points at something to check; an abort passes through unchanged.
 */
function unreachable(e: unknown): unknown {
  if (e instanceof TypeError) {
    return new ApiError(
      `Could not reach the API at ${getServerUrl()}. Check that it is running and reachable from this browser.`,
      0,
      "network",
    );
  }
  return e;
}

export async function request<T>(path: string, init?: RequestOptions): Promise<T> {
  const started = startRequest(init);
  // A response belongs to the connection it was sent on. A 401 from a request
  // that left before a reconnect must not flip the freshly accepted connection
  // back to "rejected" — the page's in-flight reads race the connect call.
  const generation = connectionEpoch;
  try {
    const res = await fetch(`${getServerUrl()}${path}`, {
      cache: "no-store",
      headers: { "Content-Type": "application/json", ...(apiKey ? { "X-API-Key": apiKey } : {}) },
      ...started.init,
      signal: started.signal,
    });
    // A 401 from the sign-in form is a wrong password, not a rejected key: it
    // must not open the connection dialog over the form that asked.
    if (res.status === 401 && generation === connectionEpoch && path !== "/auth/login") {
      reportUnauthorized();
    }
    if (!res.ok) throw await apiError(res);
    if (res.status === 204) return undefined as T;
    // Await the body inside the timed section: a server that sends headers and
    // then stalls would otherwise escape the timeout in the finally below.
    return (await res.json()) as T;
  } catch (e) {
    if (started.timedOut()) throw new ApiError("The request timed out.", 0, "timeout");
    throw unreachable(e);
  } finally {
    started.done();
  }
}

/** Filename the server suggested for a download, else the caller's default. */
function suggestedFilename(res: Response, fallback: string): string {
  const header = res.headers.get("Content-Disposition") ?? "";
  const match = /filename\*?=(?:UTF-8'')?["']?([^"';]+)/i.exec(header);
  return match ? decodeURIComponent(match[1].trim()) : fallback;
}

/**
 * Fetch a report or export with the API key attached.
 *
 * A bare <a href> cannot send the key, so every download goes through here —
 * `request` cannot be used because the payload is a file, not JSON.
 */
export async function requestFile(
  path: string,
  fallback: string,
  init?: RequestOptions,
): Promise<{ blob: Blob; name: string }> {
  const started = startRequest(init);
  const generation = connectionEpoch;
  try {
    const res = await fetch(`${getServerUrl()}${path}`, {
      cache: "no-store",
      headers: { ...(apiKey ? { "X-API-Key": apiKey } : {}) },
      ...started.init,
      signal: started.signal,
    });
    if (res.status === 401 && generation === connectionEpoch) reportUnauthorized();
    if (!res.ok) throw await apiError(res);
    return { blob: await res.blob(), name: suggestedFilename(res, fallback) };
  } catch (e) {
    if (started.timedOut()) throw new ApiError("The request timed out.", 0, "timeout");
    throw unreachable(e);
  } finally {
    started.done();
  }
}

/** Hand a fetched file to the browser's download path. */
export function saveFile(blob: Blob, name: string) {
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = name;
  link.click();
  // Revoked late: the download the click started still has to resolve the URL.
  setTimeout(() => URL.revokeObjectURL(url), 10_000);
}

export async function downloadFile(path: string, fallback: string): Promise<void> {
  const { blob, name } = await requestFile(path, fallback);
  saveFile(blob, name);
}
