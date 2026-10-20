import { test, expect, sid, finding } from "./api-fixture";
import type { ScanRun } from "../lib/api";

const endpoint = "/v1/merchants/{merchant_id}/hardware/offerings/{offering_id}/payment-keys";
const rationale = "Cross-tenant access to merchant payment keys can expose sensitive configuration. Prioritize authorization checks across identities before lower-risk endpoints.";

test("scan results preserve filters and keep long endpoint tables readable across viewports", async ({ page, api }, testInfo) => {
  api.scan.status = "completed";
  api.findings = [finding];
  await page.route("**/schema-context", route => route.fulfill({ json: { latest: null, snapshot: null } }));
  await page.route(url => new URL(url).pathname === `/scans/${sid}/runs`, route => route.fulfill({ json: [{
    id: "run-1", run_number: 1, status: "completed", started_at: "2026-01-01T00:00:00Z",
    finished_at: "2026-01-01T00:01:00Z", requests: 42, findings_count: 1,
    findings_snapshot: [],
    plan: [{ operation_id: "op-1", method: "GET", path: endpoint, priority: "high", rationale }],
    coverage: [{ operation_id: "op-1", method: "GET", path: endpoint, enabled: true,
      requests: 42, findings: 1, checks: ["broken_auth", "data_exposure", "reflected_injection", "security_headers", "signature_injection"] }],
  }] }));
  await page.goto(`/scans/${sid}`);
  const workspace = page.getByRole("region", { name: "Scan results", exact: true });
  const nav = workspace.getByRole("tablist");
  const ask = workspace.getByText("Ask your scan", { exact: true });
  const findingCard = workspace.locator(".findings .finding").first();
  await expect(ask).toBeVisible();
  await expect(findingCard).toBeVisible();
  expect((await ask.boundingBox())!.y).toBeLessThan((await findingCard.boundingBox())!.y);
  await workspace.getByRole("searchbox", { name: "Search findings" }).fill("header");
  await nav.getByRole("tab", { name: /AI scan plan/ }).click();
  await expect(workspace.getByText(rationale)).toBeVisible();
  expect(await workspace.getByText(rationale).evaluate(el => el.getBoundingClientRect().width)).toBeGreaterThan(220);
  await nav.getByRole("tab", { name: /AI scan plan/ }).press("ArrowDown");
  await expect(nav.getByRole("tab", { name: /Endpoint coverage/ })).toBeFocused();
  await expect(workspace.getByRole("columnheader", { name: "Requests" })).toBeVisible();
  await nav.getByRole("tab", { name: /Endpoint coverage/ }).press("End");
  await expect(workspace.getByRole("heading", { name: "History", exact: true })).toBeVisible();
  await nav.getByRole("tab", { name: /Run history/ }).press("Home");
  await expect(workspace.getByRole("searchbox", { name: "Search findings" })).toHaveValue("header");

  for (const width of [1440, 768, 390]) {
    await page.setViewportSize({ width, height: 1000 });
    await nav.getByRole("tab", { name: /AI scan plan/ }).click();
    await expect(workspace.getByText(rationale)).toBeVisible();
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
    await workspace.screenshot({ path: testInfo.outputPath(`plan-${width}.png`) });
    await nav.getByRole("tab", { name: /Endpoint coverage/ }).click();
    const region = workspace.getByRole("region", { name: "Endpoint coverage table" });
    await expect(region).toBeVisible();
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
    await workspace.screenshot({ path: testInfo.outputPath(`coverage-${width}.png`) });
  }
  await page.evaluate(() => document.documentElement.dataset.theme = "dark");
  await workspace.screenshot({ path: testInfo.outputPath("dark.png") });
});

test("a finished run replaces the cached run resources", async ({ page, api }) => {
  // The page is opened while the scan runs, so the first /runs answer is empty.
  api.scan.status = "running";
  api.scan.progress = 40;
  api.runs = [];
  await page.goto(`/scans/${sid}`);
  const workspace = page.getByRole("region", { name: "Scan results", exact: true });
  await expect(page.getByText("Fixture scan progress").first()).toBeVisible();

  // The worker finishes while the page stays open.
  api.scan.status = "completed";
  api.scan.progress = 100;
  api.runs = [
    {
      id: "run-1", run_number: 1, status: "completed",
      started_at: "2026-01-01T00:00:00Z", finished_at: "2026-01-01T00:01:00Z",
      requests: 12, findings_count: 0, findings_snapshot: [], plan: [],
      coverage: [{
        operation_id: "op-1", method: "GET", path: "/completion-marker",
        enabled: true, requests: 12, findings: 0, checks: ["security_headers"],
      }],
    } as unknown as ScanRun,
  ];

  // No reload: the status transition invalidates the cached resources.
  await workspace.getByRole("tab", { name: /Endpoint coverage/ }).click();
  await expect(workspace.getByText("/completion-marker")).toBeVisible({ timeout: 10_000 });
});

test("a protected draft resumes after signing in again", async ({ page, api }) => {
  api.requireKey = true;
  api.scan.status = "draft";
  await page.addInitScript(([scanId]) => {
    sessionStorage.setItem("aidetector.api-key", "stale");
    sessionStorage.setItem(
      "aidetector.scan-draft.v1",
      JSON.stringify({ scanId, target: "http://target.test", step: 2 }),
    );
  }, [sid]);

  await page.goto("/scans/new");
  // The stored session was refused; sign-in takes the wizard's place.
  await page.getByLabel("Email").fill("admin@example.test");
  await page.getByLabel("Password").fill("correct horse battery");
  await page.getByRole("button", { name: "Sign in", exact: true }).click();

  // Signing in shows the wizard, which resumes the draft the tab kept.
  await expect(page.getByText("Resumed your unfinished scan.")).toBeVisible({ timeout: 10_000 });
});

test("a comment written before assignment survives a reload", async ({ page, api }) => {
  api.scan.status = "completed";
  api.findings = [finding];
  await page.goto(`/scans/${sid}`);

  await page.getByText("Assignment & discussion").first().click();
  await page.getByLabel("New comment").fill("first note");
  await page.getByRole("button", { name: "Add", exact: true }).click();
  await expect(page.getByText("first note")).toBeVisible();

  // The read-back is a synthetic unassigned item, not an empty work list.
  await page.reload();
  await page.getByText("Assignment & discussion").first().click();
  await expect(page.getByText("first note")).toBeVisible({ timeout: 10_000 });
});

test("export stays usable after a successful download", async ({ page, api }) => {
  api.scan.status = "completed";
  api.findings = [finding];
  await page.goto(`/scans/${sid}`);

  const trigger = page.getByRole("button", { name: /export/i });
  const exportCalls = () => api.requests.filter((row) => row.path.endsWith("/export")).length;
  const before = exportCalls();

  await trigger.click();
  await page.getByRole("menuitem", { name: "JSON", exact: true }).click();
  await expect.poll(exportCalls).toBe(before + 1);
  await expect(trigger).toBeEnabled();

  await trigger.click();
  await page.getByRole("menuitem", { name: "JSON", exact: true }).click();
  await expect.poll(exportCalls).toBe(before + 2);
});

test("scan workspace visibility survives a refresh", async ({ page, api }) => {
  api.scan.status = "completed";
  api.findings = [
    finding,
    { ...finding, id: "finding-2", title: "Dismissed finding", verdict: "dismissed" },
  ];
  await page.route(url => new URL(url).pathname === "/scans/" + sid + "/runs",
    route => route.fulfill({ json: [] }));
  await page.goto("/scans/" + sid);

  const configuration = page.getByRole("region", { name: "Scan configuration", exact: true });
  await configuration.getByRole("button", { name: "Hide" }).click();
  await expect(configuration.getByRole("button", { name: "Show" })).toBeVisible();
  await expect(configuration.locator("#config-content")).toBeHidden();

  const workspace = page.getByRole("region", { name: "Scan results", exact: true });
  await expect(workspace.getByRole("button", { name: /all\s*1/ })).toBeVisible();
  await expect(workspace.locator(".sev-stat.dismissed")).toContainText("1");
  await expect(workspace.locator(".dismissed-toggle")).toContainText("1");
  const ask = workspace.getByText("Ask your scan", { exact: true });
  await ask.locator("..").getByText("Hide", { exact: true }).click();
  await expect(workspace.getByText("Show", { exact: true })).toBeVisible();

  await page.reload();

  await expect(configuration.getByRole("button", { name: "Show" })).toBeVisible();
  await expect(configuration.locator("#config-content")).toBeHidden();
  await expect(workspace.getByText("Show", { exact: true })).toBeVisible();
});
