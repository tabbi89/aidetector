import type { Route } from "@playwright/test";
import { test, expect, sid, finding } from "./api-fixture";

// The filtered findings list is server-owned: these pin that its pages, its
// refreshes, its endpoint filter, its triage and the attention summary above it
// stay true to the server while requests race.

const findingsPath = `/scans/${sid}/findings`;
const isFindings = (url: URL) => url.pathname === findingsPath;
const item = (id: string, title: string, extra: Record<string, unknown> = {}) => ({
  ...finding,
  id,
  fingerprint: id,
  title,
  ...extra,
});

test("a filtered page still in flight never lands under a newer query", async ({ page, api }) => {
  api.scan.status = "completed";
  api.findings = [finding];
  let pending: Route | undefined;
  await page.route(isFindings, async (route) => {
    const url = new URL(route.request().url());
    const q = url.searchParams.get("q");
    if (q === "old" && url.searchParams.get("offset") === "500") {
      pending = route;
      return;
    }
    const rows =
      q === "old"
        ? Array.from({ length: 500 }, (_, i) => item(`old-${i}`, `old-${i}`))
        : q === "new"
          ? [item("new", "New query result")]
          : api.findings;
    await route.fulfill({ json: rows });
  });
  await page.goto(`/scans/${sid}`);
  const search = page.getByRole("searchbox", { name: "Search findings" });
  await search.fill("old");
  const more = page.getByRole("button", { name: /Load more filtered findings/ });
  await expect(more).toBeVisible();
  await more.click();
  await expect.poll(() => !!pending).toBe(true);
  await search.fill("new");
  await expect(page.locator(".finding").getByText("New query result", { exact: true })).toBeVisible();
  await pending!.fulfill({ json: [item("stale", "OUTDATED OLD QUERY")] });
  await page.evaluate(() => new Promise<void>((r) => requestAnimationFrame(() => requestAnimationFrame(() => r()))));
  await expect(page.locator(".finding").getByText("OUTDATED OLD QUERY", { exact: true })).toHaveCount(0);
});

test("a filtered list re-reads its query when the scan completes", async ({ page, api }) => {
  api.scan.status = "running";
  api.scan.progress = 40;
  api.findings = [item("start", "needle initial")];
  await page.route(isFindings, (route) => route.fulfill({ json: api.findings }));
  await page.goto(`/scans/${sid}`);
  await page.getByRole("searchbox", { name: "Search findings" }).fill("needle");
  await expect(page.locator(".finding").getByText("needle initial", { exact: true })).toBeVisible();
  api.findings = [...api.findings, item("finish", "needle arrived on completion")];
  api.scan.status = "completed";
  api.scan.progress = 100;
  await expect(
    page.locator(".finding").getByText("needle arrived on completion", { exact: true }),
  ).toBeVisible();
});

test("selecting an endpoint filters on its label, loaded or not", async ({ page, api }) => {
  api.scan.status = "completed";
  api.findings = [finding];
  api.scan.operations.push({ ...api.scan.operations[0], id: "op-2", path: "/other" });
  const rows = [
    item("off-page", "Needle off-page", { operation_id: "op-2" }),
    item("other-row", "Needle unrelated", { operation_id: "op-1" }),
  ];
  const endpoints: (string | null)[] = [];
  await page.route(isFindings, async (route) => {
    const url = new URL(route.request().url());
    if (!url.searchParams.get("q")) return route.fulfill({ json: api.findings });
    const endpoint = url.searchParams.get("endpoint");
    endpoints.push(endpoint);
    await route.fulfill({ json: endpoint === "GET /other" ? [rows[0]] : rows });
  });
  await page.goto(`/scans/${sid}`);
  await page.getByRole("searchbox", { name: "Search findings" }).fill("Needle");
  await expect(page.locator(".finding").getByText("Needle off-page", { exact: true })).toBeVisible();
  await page.getByRole("combobox", { name: "Filter findings by endpoint" }).selectOption("GET /other");
  await expect.poll(() => endpoints.at(-1)).toBe("GET /other");
  await expect(page.locator(".finding").getByText("Needle unrelated", { exact: true })).toHaveCount(0);
  await expect(page.locator(".finding").getByText("Needle off-page", { exact: true })).toBeVisible();
});

test("an unavailable summary never yields a clean statement from a partial page", async ({ page, api }) => {
  api.scan.status = "completed";
  api.findings = [
    ...Array.from({ length: 500 }, (_, i) =>
      item(`h-${i}`, `Heuristic critical ${i}`, { severity: "critical", confidence: "heuristic" }),
    ),
    item("actual-high", "Verified high outside page", { severity: "high", confidence: "verified" }),
  ];
  await page.route(isFindings, (route) => route.fulfill({ json: api.findings.slice(0, 500) }));
  await page.route(
    (url) => url.pathname === `${findingsPath}/summary`,
    (route) => route.fulfill({ status: 503, json: { detail: "Summary unavailable" } }),
  );
  await page.goto(`/scans/${sid}`);
  await expect(page.locator(".finding").first()).toBeVisible();
  await expect(page.getByText(/Counts over every finding are unavailable/)).toBeVisible();
  await expect(page.getByText("No verified high or critical findings", { exact: false })).toHaveCount(0);
});

test("a rejected triage change leaves the filtered card as it was", async ({ page, api }) => {
  api.scan.status = "completed";
  api.findings = [item("triage-fixture", "needle triage")];
  await page.route(isFindings, (route) => route.fulfill({ json: api.findings }));
  await page.route(
    (url) => url.pathname === `${findingsPath}/triage-fixture`,
    (route) => route.fulfill({ status: 503, json: { detail: "Synthetic patch rejection" } }),
  );
  await page.goto(`/scans/${sid}`);
  await page.getByRole("searchbox", { name: "Search findings" }).fill("needle");
  const card = page.locator(".finding");
  await expect(card.getByText("needle triage", { exact: true })).toBeVisible();
  await card.getByRole("button", { name: "Confirm", exact: true }).click();
  await expect(page.getByText("Synthetic patch rejection", { exact: true })).toBeVisible();
  await expect(card.getByRole("button", { name: "Confirm", exact: true })).toHaveAttribute("aria-pressed", "false");
});

test("a dismissed finding leaves a filtered list that hides dismissed", async ({ page, api }) => {
  api.scan.status = "completed";
  api.findings = [item("dismiss-fixture", "needle dismiss"), item("keep", "needle keep")];
  await page.route(isFindings, (route) =>
    route.fulfill({ json: api.findings.filter((f) => f.verdict !== "dismissed") }),
  );
  await page.route(
    (url) => url.pathname === `${findingsPath}/dismiss-fixture`,
    async (route) => {
      api.findings[0] = { ...api.findings[0], verdict: "dismissed" };
      await route.fulfill({ json: api.findings[0] });
    },
  );
  await page.goto(`/scans/${sid}`);
  await page.getByRole("searchbox", { name: "Search findings" }).fill("needle");
  const dismissed = page.locator(".finding").filter({ hasText: "needle dismiss" });
  await expect(dismissed).toBeVisible();
  await dismissed.getByRole("button", { name: "False positive", exact: true }).click();
  await expect(dismissed).toHaveCount(0);
  await expect(page.locator(".finding").getByText("needle keep", { exact: true })).toBeVisible();
});

test("a findings list that never loaded is not reported clean", async ({ page, api }) => {
  api.scan.status = "completed";
  api.findings = [item("hidden-high", "Verified high", { severity: "high", confidence: "verified" })];
  await page.route(isFindings, (route) => route.fulfill({ status: 503, json: { detail: "Findings unavailable" } }));
  await page.route(
    (url) => url.pathname === `${findingsPath}/summary`,
    (route) => route.fulfill({ status: 503, json: { detail: "Summary unavailable" } }),
  );
  await page.goto(`/scans/${sid}`);
  await expect(page.getByText(/Counts over every finding are unavailable/)).toBeVisible();
  await expect(page.getByText("No verified high or critical findings", { exact: false })).toHaveCount(0);
});
