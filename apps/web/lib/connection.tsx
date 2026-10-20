"use client";

// The tab's session: whether it is signed in and what the server says about it.
// The API address is fixed at build time (NEXT_PUBLIC_API_URL). The session
// token lives in memory in the transport and — once a sign-in succeeds — in
// sessionStorage for this tab only.
import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import {
  ApiError,
  api,
  getApiKey,
  getServerUrl,
  hasApiKey,
  onUnauthorized,
  refreshConnection,
  setApiKey,
  type SignInInput,
  type WorkspaceRole,
  type WorkspaceUser,
} from "@/lib/api";

/** What the probe found; `AuthGate` and the sign-in form read it. */
export type ConnectionStatus =
  | "checking"
  | "open"
  | "connected"
  | "needs-key"
  | "rejected"
  | "unreachable";

// Session storage: a session in this tab is not shared with other tabs and is
// gone when the tab closes. Never localStorage.
const KEY_STORAGE = "aidetector.api-key";

// Restore before React mounts. A child's effect runs before the provider's, so
// anything that fetches on mount (the wizard's draft resume, the scans list)
// would otherwise call the API without the session this tab already holds.
if (typeof window !== "undefined") {
  try {
    const storedKey = sessionStorage.getItem(KEY_STORAGE);
    if (storedKey) setApiKey(storedKey);
  } catch {
    /* storage unavailable — the tab starts signed out */
  }
}

export interface Connection {
  status: ConnectionStatus;
  /** True once the first determination has settled; false while probing. */
  ready: boolean;
  tenant: string | null;
  authRequired: boolean | null;
  /**
   * A session was accepted: the gate lets this tab see the app pages. It holds
   * its last settled value while a re-check is in flight, so the header does
   * not flip to the signed-out links for the length of a probe.
   */
  authenticated: boolean;
  /** The signed-in member; null before sign-in. */
  user: WorkspaceUser | null;
  role: WorkspaceRole | null;
  error: string | null;
  /** Sign in with email and password; the session token becomes this tab's key. */
  signIn: (input: SignInInput) => Promise<boolean>;
  signOut: () => Promise<void>;
  refresh: () => Promise<boolean>;
  /** The API this build talks to, for links and CLI hand-offs. */
  serverUrl: string;
}

const ConnectionContext = createContext<Connection | null>(null);

/**
 * One session for the whole app: restores this tab's saved token, probes
 * `/auth/status`, and turns a 401 from any later call into "rejected" (or
 * "needs-key"), which `AuthGate` answers with the sign-in form. The token
 * itself is never rendered.
 */
export function ConnectionProvider({ children }: { children: React.ReactNode }) {
  const [status, setStatus] = useState<ConnectionStatus>("checking");
  const [ready, setReady] = useState(false);
  const [tenant, setTenant] = useState<string | null>(null);
  const [authRequired, setAuthRequired] = useState<boolean | null>(null);
  const [user, setUser] = useState<WorkspaceUser | null>(null);
  const [role, setRole] = useState<WorkspaceRole | null>(null);
  const [error, setError] = useState<string | null>(null);
  // The last status a probe (or a 401) settled on; "checking" never lands here.
  const [settled, setSettled] = useState<ConnectionStatus | null>(null);
  useEffect(() => {
    if (status !== "checking") setSettled(status);
  }, [status]);

  // The newest probe wins; an older response must not overwrite a newer state.
  const generation = useRef(0);
  // A probe's own 401 is reported to `status` below, not twice.
  const probing = useRef(0);

  const probe = useCallback(async (): Promise<boolean> => {
    const run = ++generation.current;
    probing.current += 1;
    setStatus("checking");
    setError(null);
    try {
      const info = await api.authStatus();
      if (run !== generation.current) return false;
      setTenant(info.tenant);
      setAuthRequired(info.auth_required);
      setUser(info.user);
      setRole(info.role);
      setStatus(hasApiKey() ? "connected" : "open");
      return true;
    } catch (e) {
      if (run !== generation.current) return false;
      setTenant(null);
      setUser(null);
      setRole(null);
      if (e instanceof ApiError && e.status === 401) {
        setAuthRequired(true);
        setStatus(hasApiKey() ? "rejected" : "needs-key");
      } else {
        setStatus("unreachable");
        setError((e as Error).message || "Can't reach the server.");
      }
      return false;
    } finally {
      probing.current -= 1;
      setReady(true);
    }
  }, []);

  const handleUnauthorized = useCallback(() => {
    if (probing.current > 0) return;
    const keyed = hasApiKey();
    setTenant(null);
    setUser(null);
    setRole(null);
    setAuthRequired(true);
    setStatus((current) =>
      current === "rejected" || current === "needs-key"
        ? current
        : keyed
          ? "rejected"
          : "needs-key",
    );
  }, []);

  useEffect(() => {
    // The token was already restored synchronously at module load, before any
    // child effect could fetch.
    void probe();
    return onUnauthorized(handleUnauthorized);
  }, [probe, handleUnauthorized]);

  const signIn = useCallback(
    async ({ email, password }: SignInInput): Promise<boolean> => {
      setError(null);
      let token: string;
      try {
        token = (await api.signIn({ email, password })).token;
      } catch (e) {
        // The server's detail says why: bad credentials, or a pending account.
        setError((e as Error).message);
        return false;
      }
      const previous = getApiKey();
      setApiKey(token);
      // Invalidate connection-scoped caches even if a stale token was equal.
      refreshConnection();
      if (!(await probe())) {
        setApiKey(previous);
        setError("The server rejected the new session.");
        return false;
      }
      try {
        sessionStorage.setItem(KEY_STORAGE, token);
      } catch {
        /* private mode — the session holds for this page load */
      }
      return true;
    },
    [probe],
  );

  const signOut = useCallback(async () => {
    try {
      await api.signOut();
    } catch {
      /* the local session ends either way */
    }
    setApiKey("");
    refreshConnection();
    try {
      sessionStorage.removeItem(KEY_STORAGE);
    } catch {
      /* nothing stored to clear */
    }
    await probe();
  }, [probe]);

  const value = useMemo<Connection>(
    () => ({
      status,
      ready,
      tenant,
      authRequired,
      // The live status when there is one; the remembered one mid-probe.
      authenticated: (status === "checking" ? settled : status) === "connected",
      user,
      role,
      error,
      signIn,
      signOut,
      refresh: probe,
      serverUrl: getServerUrl(),
    }),
    [status, settled, ready, tenant, authRequired, user, role, error, signIn, signOut, probe],
  );

  return (
    <ConnectionContext.Provider value={value}>
      {children}
    </ConnectionContext.Provider>
  );
}

export function useConnection(): Connection {
  const value = useContext(ConnectionContext);
  if (!value) throw new Error("useConnection must be used inside ConnectionProvider");
  return value;
}
