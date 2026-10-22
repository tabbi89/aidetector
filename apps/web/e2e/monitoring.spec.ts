import { test, expect } from "./api-fixture";

const monitorId = "00000000-0000-4000-8000-000000000099";

function iso(minutesAgo = 0) {
  return new Date(Date.now() - minutesAgo * 60_000).toISOString();
}

test("monitoring v2 leads with a five-minute pulse and daily evidence", async ({ page, api }) => {
  // The fixture signs the tab in and answers the shell's reads; the monitoring
  // routes below are this test's own (page routes outrank the context's).
  void api;
  const day = new Date(Date.now() - 86_400_000).toISOString().slice(0, 10);
  const monitor = {
    id: monitorId, tenant_id: "default", name: "Production API", target_binding: "https://api.example.com",
    source_ids: ["source-1"], schedule_minutes: 1440, minimum_baseline_days: 7,
    schedule_enabled: true, rapid_enabled: true, retention_days: 90, scan_id: "scan-1",
    status: "active", last_observation_date: day, last_run_at: iso(20), created_at: iso(10_000),
  };
  const observation = {
    type: "injection_attempts", fingerprint: "rapid-attack", route_family: "/users/{id}",
    method: "GET", severity: "high", confidence: "heuristic", basis: "complete_rolling_window",
    current: { hits: 14, waf_allowed: 2, labels: ["sql-database:SQLi_QueryArguments"] },
    remediation: "Review the allowed requests and tighten the matching WAF rule.", disposition: "candidate",
  };
  const rapid = {
    id: "rapid-1", monitor_id: monitorId, window_start: iso(60), window_end: iso(1),
    observations: [observation], skipped: {}, waf_count: 18_420, application_count: 42,
    pulse: {
      minutes: 5, requests: 1842, allowed: 1290, blocked: 510, challenged: 42, counted: 0,
      other_actions: 0, attack_requests: 73, attack_allowed: 9, off_spec_requests: 96,
      distinct_routes: 31, distinct_clients: 248, bot_requests: 320, unverified_bot_requests: 112,
      application_events: 8,
      top_attack_labels: [
        { label: "sql-database:SQLi_QueryArguments", requests: 51 },
        { label: "core-rule-set:GenericLFI_URIPath", requests: 22 },
      ],
      top_routes: [
        { route: "GET /users/{id}", requests: 410 },
        { route: "POST /login", requests: 288 },
      ],
    },
    created_at: iso(1),
  };
  const run = {
    id: "run-1", monitor_id: monitorId, observation_date: day, status: "complete", state: "anomaly",
    error_code: null, scope_revision: "v1", correlations: [], baseline_start: day, baseline_end: day,
    baseline_days_available: 8, data_quality: "sufficient", source_revisions: {},
    metrics: {
      event_count: 124_800, unmapped_count: 714,
      routes: {
        "/users/{id}": { requests: 50_000, blocked_requests: 8_000 },
        "/login": { requests: 32_000, blocked_requests: 3_200 },
      },
      clients: { clients: [{ attack_requests: 920, attack_allowed: 41 }] },
      origin: { hours: [{ hour: 14, requests: 8_000, target_2xx: 7_300, target_3xx: 100,
        target_4xx: 500, target_5xx: 100, elb_4xx: 25, elb_5xx: 0,
        rejected_connections: 0, target_connection_errors: 0, response_avg: .12, response_p99: .8 }] },
    },
    observations: [], started_at: iso(30), finished_at: iso(20), created_at: iso(30),
  };
  const responses: Record<string, unknown> = {
    [`/monitoring/${monitorId}/runs`]: [run],
    [`/monitoring/${monitorId}/rapid-runs`]: [rapid],
    [`/monitoring/${monitorId}/alerts`]: [],
    [`/monitoring/${monitorId}/bots`]: { days: 1, requests: 124_800, bot_requests: 320,
      ai_requests: 120, verified_ai: 80, unverified_ai: 40, verified_ai_pct: 66.7,
      unverified_ai_pct: 33.3, by_category: { ai: 120 }, crawlers: [], crawler_count: 0,
      series: [{ day, by_category: { ai: 120 } }] },
    [`/monitoring/${monitorId}/routes`]: { days: 1, sampled: false, minimum_baseline_days: 7,
      routes: [{ route: "/users/{id}", total_requests: 50_000, latest_day: day,
        latest_requests: 50_000, latest_share: .4, baseline_share: .2, change: 1, score: 4,
        state: "anomaly", series: [{ day, requests: 50_000, share: .4, blocked: 8_000, not_found: 0 }] }] },
    [`/monitoring/${monitorId}/clients`]: { day, sampled: false, clients_total: 0,
      without_fingerprint: 124_800, clients: [] },
    [`/monitoring/${monitorId}/briefing`]: { status: "none", requested_at: null,
      finished_at: null, days: null, evidence_through: null, evidence_trimmed: [], reason: null,
      provider: null, model: null, text: null, structured: null, tokens_in: null, tokens_out: null, log: [] },
  };

  await page.route("http://api.test/monitoring**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path === "/monitoring") return route.fulfill({ json: [monitor] });
    const response = responses[path];
    return response === undefined ? route.fulfill({ status: 404, json: { detail: "missing fixture" } }) : route.fulfill({ json: response });
  });

  await page.goto(`/monitoring/${monitorId}`);
  await expect(page.getByRole("heading", { name: "Last five minutes" })).toBeVisible();
  await expect(page.getByText("1.84K", { exact: true }).first()).toBeVisible();
  await expect(page.getByText("96", { exact: true }).first()).toBeVisible();
  await expect(page.getByRole("heading", { name: "Attack episodes" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Daily evidence and decisions" })).toBeVisible();
  await expect(page.getByText("OpenAPI contract", { exact: true })).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
  await page.setViewportSize({ width: 390, height: 844 });
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);

  // Retention and permanent deletion use the same in-app confirmation owner.
  const lifecycle = page.locator(".monitor-lifecycle");
  await lifecycle.getByRole("combobox").selectOption("31");
  const retention = page.getByRole("dialog", { name: "Delete older monitoring evidence?" });
  await expect(retention).toContainText("This cannot be undone.");
  await retention.getByRole("button", { name: "Cancel", exact: true }).click();
  await expect(lifecycle.getByRole("combobox")).toHaveValue("90");
  await lifecycle.getByRole("button", { name: "Delete monitor", exact: true }).click();
  const deletion = page.getByRole("dialog", { name: "Delete monitor permanently?" });
  const confirm = deletion.getByRole("button", { name: "Delete monitor", exact: true });
  await expect(confirm).toBeDisabled();
  await deletion.getByRole("textbox").fill("wrong name");
  await expect(confirm).toBeDisabled();
  await deletion.getByRole("textbox").fill("Production API");
  await expect(confirm).toBeEnabled();
  await deletion.getByRole("button", { name: "Cancel", exact: true }).click();
  await expect(lifecycle.getByRole("button", { name: "Delete monitor", exact: true })).toBeFocused();
});
