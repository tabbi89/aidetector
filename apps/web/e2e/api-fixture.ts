import { test as base, expect } from "@playwright/test";
import type {
  AuthHints, Cost, Finding, FindingComment, FindingWork, Scan, ScanRun, TargetOwnership,
} from "../lib/api";

export const sid = "00000000-0000-4000-8000-000000000001";
export const spec = JSON.stringify({
  openapi: "3.0.0", info: { title: "Browser fixture", version: "1" },
  paths: { "/items": { get: {} } },
});
export const finding: Finding = {
  id: "finding-1", operation_id: "op-1", check: "security_headers",
  fingerprint: "fixture-fingerprint", owasp_id: "API8:2023", severity: "medium",
  confidence: "verified", title: "Missing security header", description: "Fixture evidence",
  evidence: {}, remediation: "Set the header", references: [], verdict: "unreviewed",
  ai_rationale: null, created_at: "2026-01-01T00:00:00Z", premium: false,
};

type State = {
  scan: Scan;
  findings: Finding[];
  runs: ScanRun[];
  work: FindingWork[];
  requests: { method: string; path: string; body: Record<string, unknown> | null }[];
  failNext: string | null;
  deferCancellation: boolean;
  /** When true, every API call without `X-API-Key: good` answers 401. */
  requireKey: boolean;
  /** `/auth/status` answers as an open server (no admin has a password yet). */
  openServer: boolean;
  /** `/scans/{id}/ownership`; the default target is exempt (private). */
  ownership: TargetOwnership;
  /** `/scans/{id}/auth-hints`; null answers 409, as a scan with no spec does. */
  authHints: AuthHints | null;
  /** `/scans/{id}/cost`; null answers an empty ledger. */
  cost: Cost | null;
  nextComment: number;
};

/** The fingerprint is the second-to-last path segment on work/comment routes. */
function fingerprintOf(path: string): string {
  const parts = path.split("/");
  return decodeURIComponent(parts[parts.length - 2]);
}

export const test = base.extend<{ api: State }>({
  api: async ({ context }, use) => {
    const state: State = {
      scan: {
        id: sid, tenant_id: "default", target_base_url: "http://target.test", status: "draft", progress: 0,
        cancel_requested: false, requests_per_second: 10, cost_cents: 0, cost_usd: 0,
        schedule_minutes: null, next_run_at: null, schedule_options: {},
        spec_text: null, failure_reason: null, created_at: "2026-01-01T00:00:00Z", credential_profiles: [],
        // The fixture scan is web-owned, the shape the API sends when no project file manages it.
        managed_config: {},
        operations: [{ id: "op-1", method: "GET", path: "/items", params: [],
          auth_scope: null, enabled: true }],
      },
      findings: [], runs: [], work: [], requests: [], failNext: null,
      deferCancellation: false, requireKey: false, openServer: false, nextComment: 1,
      authHints: null, cost: null,
      ownership: { host: "target.test", allowed: true, required: false, exempt: "private",
        domain_id: null, verified_at: null, last_error: null, reason: null },
    };
    // Every page but /login is behind a session now, so a test starts signed
    // in unless it clears or replaces the key (page scripts run after this).
    await context.addInitScript(() => {
      if (!sessionStorage.getItem("aidetector.api-key")) {
        sessionStorage.setItem("aidetector.api-key", "fixture-session");
      }
    });
    const unexpected: string[] = [];
    await context.route("**/*", async (route) => {
      const request = route.request();
      const url = new URL(request.url());
      if (url.origin === "http://127.0.0.1:3107") return route.continue();
      if (url.origin !== "http://api.test") {
        unexpected.push(request.url());
        return route.abort();
      }
      const path = url.pathname;
      const method = request.method();
      const body = request.postData() ? request.postDataJSON() : null;
      state.requests.push({ method, path, body });
      // The protected-deployment switch: one working key, everything else 401.
      // The connection probe and every page read share it, which is what the
      // reconnect regression test needs.
      const signingIn = path === "/auth/login" || path === "/auth/signup";
      if (state.requireKey && !signingIn && request.headers()["x-api-key"] !== "good") {
        return route.fulfill({ status: 401, json: { detail: "missing or invalid API key" } });
      }
      if (state.failNext === path) {
        state.failNext = null;
        return route.fulfill({ status: 503, json: { detail: "Temporary fixture failure" } });
      }
      if (path.endsWith("/export")) {
        return route.fulfill({ contentType: "application/json",
          headers: { "Content-Disposition": 'attachment; filename="scan.json"',
            "Access-Control-Allow-Origin": "*", "Access-Control-Expose-Headers": "Content-Disposition" },
          body: JSON.stringify({ findings: state.findings }) });
      }
      let response: unknown;
      if (path === "/health") response = { status: "ok" };
      else if (path === "/auth/status") {
        if (state.openServer && !request.headers()["x-api-key"]) {
          response = { tenant: "default", auth_required: false, role: "admin", user: null };
        } else if (!state.openServer && !request.headers()["x-api-key"]) {
          return route.fulfill({ status: 401, json: { detail: "missing or invalid API key" } });
        } else {
          response = {
            tenant: "default", auth_required: true, role: "admin",
            user: { id: "user-admin", email: "admin@example.test", display_name: "Admin" },
          };
        }
      }
      else if (path === "/auth/login") {
        if (body?.password !== "correct horse battery") {
          return route.fulfill({ status: 401, json: { detail: "invalid email or password" } });
        }
        response = {
          token: "good", expires_at: "2099-01-01T00:00:00Z", tenant: "default", role: "admin",
          user: { id: "user-admin", email: body.email, display_name: "Admin" },
        };
      }
      else if (path === "/auth/logout") response = { status: "signed_out" };
      else if (path === "/auth/signup") return route.fulfill({ status: 202, json: { status: "pending" } });
      else if (path === "/workspace/signups") response = [];
      else if (path === "/workspace") response = {
        tenant: "default", name: "Default workspace", plan: "premium",
        role: "admin", user: null, members: 0,
      };
      else if (path === "/workspace/members") response = method === "POST"
        ? { user_id: "user-fixture", email: body.email, display_name: body.display_name,
            role: body.role, created_at: new Date().toISOString() }
        : [];
      else if (path === "/workspace/tokens") response = [];
      else if (path === "/workspace/domains") response = [];
      else if (path === "/workspace/audit") response = [];
      else if (path === "/workspace/notifications") response = [];
      else if (path === "/workspace/notifications/deliveries") response = [];
      else if (path === "/workspace/budgets") response = {
        tenant: "default", plan: "premium", ai_monthly_micros: null,
        ai_per_scan_micros: null, max_concurrent_runs: null,
        max_queued_runs: null, scans_per_day: null, month_spent_micros: 0,
        month_remaining_micros: null, active_runs: 0, queued_runs: 0,
      };
      else if (path === "/capabilities") response = {
        passes: Object.fromEntries(
          ["zap", "kali", "confirm", "plan", "adjudicate", "security_review", "genai_payloads"]
            .map((pass) => [pass, { available: true, reason: null }])),
        premium: { available: true, plan: "premium", reason: null },
      };
      else if (path === "/scans") response = method === "POST" ? state.scan : [{ ...state.scan,
        finding_counts: { critical: 0, high: 0, medium: 0, low: 0, info: 0 }, last_run_at: null }];
      else if (path === `/scans/${sid}`) response = state.scan;
      else if (path === `/scans/${sid}/progress`) response = {
        id: state.scan.id, status: state.scan.status, progress: state.scan.progress,
        cancel_requested: state.scan.cancel_requested,
        failure_reason: state.scan.failure_reason, heartbeat_at: null,
        cost_cents: state.scan.cost_cents, schedule_minutes: state.scan.schedule_minutes,
        next_run_at: state.scan.next_run_at, created_at: state.scan.created_at,
      };
      else if (path.endsWith("/request-rate")) {
        state.scan.requests_per_second = body.requests_per_second;
        response = state.scan;
      } else if (path.endsWith("/schedule")) {
        const { minutes, authorized: _authorized, ...options } = body;
        state.scan.schedule_minutes = minutes || null;
        state.scan.next_run_at = minutes ? "2026-01-01T01:00:00Z" : null;
        state.scan.schedule_options = minutes ? options : {};
        response = state.scan;
      } else if (path.endsWith("/spec")) {
        state.scan.spec_text = body.content;
        response = { ...state.scan, spec_report: { operations: state.scan.operations.length,
          skipped: [], warnings: [] } };
      } else if (path.endsWith("/operations")) response = state.scan;
      else if (path.endsWith("/credentials")) {
        // The real API never echoes the submitted secret.
        const { secret: _secret, ...profile } = body;
        response = { ...profile, id: `cred-${state.scan.credential_profiles.length}` };
        state.scan.credential_profiles.push(response as Scan["credential_profiles"][number]);
      } else if (path.endsWith("/run")) {
        state.scan.cancel_requested = false;
        state.scan.status = "running";
        state.scan.progress = 10;
        response = { scan_id: sid, status: "queued" };
      } else if (path.endsWith("/cancel")) {
        state.scan.cancel_requested = true;
        if (!state.deferCancellation) state.scan.status = "cancelled";
        response = state.scan;
      } else if (path.endsWith("/events")) response = [{ stage: state.scan.status,
        pct: state.scan.progress, message: "Fixture scan progress", created_at: state.scan.created_at }];
      else if (path.endsWith("/schema-context")) {
        response = method === "DELETE" ? { removed: 0 } : { latest: null, snapshot: null };
      }
      else if (path === `/scans/${sid}/findings/summary`) {
        const active = state.findings.filter((f) => f.verdict !== "dismissed");
        const severity: Record<string, number> = {};
        for (const f of active) severity[f.severity] = (severity[f.severity] ?? 0) + 1;
        const verified = active.filter((f) => f.confidence === "verified");
        response = {
          total: state.findings.length,
          active: active.length,
          dismissed: state.findings.length - active.length,
          verified_critical: verified.filter((f) => f.severity === "critical").length,
          verified_high: verified.filter((f) => f.severity === "high").length,
          severity,
        };
      }
      else if (path.endsWith("/findings")) response = state.findings;
      else if (path === `/scans/${sid}/work`) response = state.work;
      else if (method === "PUT" && /\/findings\/[^/]+\/work$/.test(path)) {
        const fingerprint = fingerprintOf(path);
        const existing = state.work.find((item) => item.fingerprint === fingerprint);
        if (existing) Object.assign(existing, body);
        else state.work.push({
          scan_id: sid, fingerprint, owner: null, due_date: null, status: "open",
          updated_at: new Date().toISOString(), comments: [],
          ...body,
        });
        response = state.work.find((item) => item.fingerprint === fingerprint);
      } else if (method === "DELETE" && /\/findings\/[^/]+\/work$/.test(path)) {
        const fingerprint = fingerprintOf(path);
        state.work = state.work.filter((item) => item.fingerprint !== fingerprint);
        response = { status: "deleted" };
      } else if (method === "POST" && /\/findings\/[^/]+\/comments$/.test(path)) {
        // Commenting before an assignment creates the synthetic item the real
        // API returns, so a reload can read the discussion back.
        const fingerprint = fingerprintOf(path);
        let item = state.work.find((row) => row.fingerprint === fingerprint);
        if (!item) {
          item = {
            scan_id: sid, fingerprint, owner: null, due_date: null, status: "open",
            updated_at: new Date().toISOString(), comments: [],
          };
          state.work.push(item);
        }
        const comment: FindingComment = {
          id: `comment-${state.nextComment++}`, scan_id: sid, fingerprint,
          author: "default", body: (body as { body: string }).body,
          created_at: new Date().toISOString(),
        };
        item.comments.push(comment);
        return route.fulfill({ status: 201, json: comment });
      } else if (method === "DELETE" && /\/comments\/[^/]+$/.test(path)) {
        const id = path.split("/").pop();
        for (const item of state.work) {
          item.comments = item.comments.filter((comment) => comment.id !== id);
        }
        response = { status: "deleted" };
      }
      else if (path === `/scans/${sid}/ownership`) response = state.ownership;
      // Credential hints are advisory; with none set the panel gets the same
      // "nothing to suggest yet" 409 a scan without a spec answers.
      else if (path.endsWith("/auth-hints")) {
        if (!state.authHints) return route.fulfill({ status: 409, json: { detail: "upload a spec first" } });
        response = state.authHints;
      }
      else if (path.endsWith("/cost")) {
        response = state.cost ?? { scan_id: sid, total_usd: 0, entries: [], models: [] };
      }
      else if (path.endsWith("/runs")) {
        // The client pages run history with ?limit=&offset=; serve the slice a
        // single response would carry instead of the whole fixture list.
        const limit = Number(url.searchParams.get("limit") ?? state.runs.length);
        const offset = Number(url.searchParams.get("offset") ?? 0);
        response = state.runs.slice(offset, offset + limit);
      } else if (path.endsWith("/coverage")) response = state.runs;
      else if (path.endsWith("/diff")) return route.fulfill({ status: 404, json: { detail: "No runs" } });
      else {
        unexpected.push(`${method} ${path}`);
        return route.abort();
      }
      return route.fulfill({ json: response });
    });
    await use(state);
    expect(unexpected, "No unmocked API or external traffic").toEqual([]);
  },
});
export { expect };
