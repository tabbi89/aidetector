import { test, expect, sid, finding } from "./api-fixture";
import type { MutationRow } from "../lib/api";

const call: MutationRow = {
  sequence: 1, method: "POST", route: "/v1/contacts", check: "write_authz",
  identity: "dana", pass: "engine", elapsed_ms: 52.9, error: null,
  request: {
    headers: { "content-type": "application/json", authorization: "<redacted>" },
    query_fields: [], content_bytes: 85,
    json_body: JSON.stringify({ contactType: "user", contactName: "Scanner canary", contactId: "aidx1234" }),
    json_shape: { contactType: { type: "string", length: 4 }, contactId: { type: "string", length: 8 } },
  },
  response: {
    status: 201, headers: { "content-type": "application/json", "x-request-id": "<redacted>" },
    content_type: "application/json", body_bytes: 265,
    body: JSON.stringify({ contactId: "aidx1234", contactPhone: "<redacted>" }),
    truncated: false, body_omitted: false, json_shape: null,
  },
};

test("findings lead with search and severity while secondary controls remain recoverable", async ({ page, api }, info) => {
  api.scan.status = "completed";
  api.findings = [finding, { ...finding, id: "second", fingerprint: "second", severity: "high", confidence: "heuristic", title: "Input reflected in response" }];
  await page.goto(`/scans/${sid}`);
  const workspace = page.getByRole("region", { name: "Scan results", exact: true });
  await expect(workspace.getByRole("searchbox", { name: "Search findings" })).toBeVisible();
  await expect(workspace.locator(".summary-bar")).toHaveCount(0);
  await expect(workspace.getByRole("combobox", { name: "Filter findings by check" })).toHaveCount(0);
  await expect(workspace.locator(".ask-head")).toHaveAttribute("aria-expanded", "false");
  await workspace.getByRole("button", { name: "More filters", exact: true }).click();
  await expect(workspace.getByRole("combobox", { name: "Filter findings by check" })).toBeVisible();
  await workspace.getByRole("combobox", { name: "Filter findings by verdict" }).selectOption("unreviewed");
  const toggle = workspace.getByRole("button", { name: "More filters · 1 active", exact: true });
  await expect(toggle).toBeVisible();
  await toggle.click();
  await expect(toggle).toHaveAttribute("aria-expanded", "false");
  await expect(page).toHaveURL(/verdict=unreviewed/);
  await page.reload();
  await expect(workspace.getByRole("combobox", { name: "Filter findings by verdict" })).toHaveValue("unreviewed");
  await workspace.locator(".findings-help > summary").press("Enter");
  await expect(workspace.getByText("Heuristic — a lead.", { exact: false })).toBeVisible();
  await workspace.locator(".findings-help > summary").press("Enter");
  const search = workspace.getByRole("searchbox", { name: "Search findings" });
  await search.fill("header");
  await workspace.getByRole("button", { name: "Clear search", exact: true }).click();
  await expect(search).toBeFocused();
  await expect(search).toHaveValue("");
  await workspace.getByRole("button", { name: /Export/ }).click();
  await expect(workspace.getByRole("menuitem", { name: "JSON", exact: true })).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(workspace.getByRole("button", { name: /Export/ })).toBeFocused();
  await page.goto(`/scans/${sid}`);
  await expect(workspace.locator(".finding")).toHaveCount(2);
  for (const theme of ["dark", "light"]) {
    await page.evaluate((value) => { document.documentElement.dataset.theme = value; }, theme);
    for (const width of [1440, 390]) {
      await page.setViewportSize({ width, height: 1000 });
      expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
      await workspace.screenshot({ path: info.outputPath(`findings-${theme}-${width}.png`) });
    }
  }
});

test("findings search waits for composition to finish before requesting or sharing a query", async ({ page, api }) => {
  api.scan.status = "completed";
  api.findings = [finding];
  const queries: string[] = [];
  await page.route((url) => url.pathname === `/scans/${sid}/findings`, (route) => {
    const query = new URL(route.request().url()).searchParams.get("q");
    if (query) queries.push(query);
    return route.fulfill({ json: [finding] });
  });
  await page.goto(`/scans/${sid}`);
  const search = page.getByRole("searchbox", { name: "Search findings" });
  await search.dispatchEvent("compositionstart");
  await search.fill("security");
  await page.waitForTimeout(350);
  expect(queries).toHaveLength(0);
  expect(new URL(page.url()).searchParams.has("q")).toBe(false);
  await search.dispatchEvent("compositionend");
  await expect.poll(() => queries).toEqual(["security"]);
  await expect(page).toHaveURL(/q=security/);
});

test("request detail shows bodies first and discloses headers and structure without losing evidence", async ({ page, api }, info) => {
  api.scan.status = "completed";
  const calls: MutationRow[] = [
    call,
    { ...call, sequence: 2, route: "/timeout", error: "ReadTimeout", response: { ...call.response, status: null, body_bytes: 0, body: "", body_omitted: true } },
    { ...call, sequence: 3, route: "/omitted", response: { ...call.response, status: 200, body: "", body_omitted: true } },
    { ...call, sequence: 4, route: "/truncated", response: { ...call.response, truncated: true } },
  ];
  await page.route((url) => url.pathname === `/scans/${sid}/runs`, (route) => route.fulfill({ json: [{
    id: "run-1", run_number: 1, status: "completed", started_at: "2026-01-01T00:00:00Z", finished_at: "2026-01-01T00:01:00Z",
    requests: 4, findings_count: 0, trace_count: 4, findings_snapshot: [], plan: [], coverage: [], options: {}, gaps: {}, resources: [],
  }] }));
  await page.route((url) => url.pathname === `/scans/${sid}/runs/1/trace`, (route) => route.fulfill({ json: { run_number: 1, total: 4, offset: 0, rows: calls } }));
  await page.goto(`/scans/${sid}?tab=mutations`);
  await page.getByRole("tab", { name: /Request log/ }).click();
  const entry = page.locator(".mutation-entry").first();
  await entry.locator(":scope > summary").click();
  const payload = entry.getByLabel("Request payload", { exact: true });
  await expect(payload).toContainText("Scanner canary");
  await expect(entry.getByLabel("Response body", { exact: true })).toContainText('"contactPhone": "<redacted>"');
  await expect(entry.locator(".mutation-headers").first()).toBeHidden();
  await expect(entry.getByLabel("Request structure", { exact: true })).toBeHidden();
  await entry.locator("summary", { hasText: "Request headers" }).click();
  await expect(entry.getByText("authorization", { exact: true })).toBeVisible();
  await entry.locator("summary", { hasText: "Payload structure" }).press("Enter");
  await expect(entry.getByLabel("Request structure", { exact: true })).toContainText("<string, 8 chars>");
  await payload.focus();
  await expect(payload).toBeFocused();
  // Return to the body-first view for the visual evidence.
  await entry.locator("summary", { hasText: "Request headers" }).click();
  await entry.locator("summary", { hasText: "Payload structure" }).click();
  for (const theme of ["dark", "light"]) {
    await page.evaluate((value) => { document.documentElement.dataset.theme = value; }, theme);
    for (const width of [1440, 390]) {
      await page.setViewportSize({ width, height: 1000 });
      expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
      await entry.screenshot({ path: info.outputPath(`request-${theme}-${width}.png`) });
    }
  }
  for (const [index, text] of [[1, "No response received (ReadTimeout)."], [2, "body not retained"], [3, "truncated"]] as const) {
    const row = page.locator(".mutation-entry").nth(index);
    await row.locator(":scope > summary").click();
    await expect(row.getByLabel("Response body", { exact: true })).toContainText(text);
  }
  expect(api.requests.filter((request) => request.method !== "GET")).toHaveLength(0);
});
