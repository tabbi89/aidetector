import type { Page, Route } from "@playwright/test";
import { test, expect, sid } from "./api-fixture";

const resourcePath = new RegExp(`/scans/${sid}/(runs|diff|cost)(\\?.*)?$`);

/** The trailing resource segment, ignoring any paging query string. */
function resourceOf(url: string): string {
  return new URL(url).pathname.split("/").pop()!;
}

function payload(resource: string, run: number) {
  if (resource === "runs") return [{
    id: `run-${run}`, run_number: run, status: "completed",
    started_at: "2026-01-01T00:00:00Z", finished_at: "2026-01-01T00:01:00Z",
    requests: 12, findings_count: 0, findings_snapshot: [], plan: [],
    coverage: [{ operation_id: "op-1", method: "GET", path: `/run-${run}-coverage`,
      enabled: true, requests: 12, findings: 0, checks: ["security_headers"] }],
  }];
  if (resource === "diff") return {
    from_run: run - 1, to_run: run, added: [], resolved: [], not_retested: [],
    unchanged: [], unmatchable: 0, options_changed: false,
    executor_changed: false, config_changed: false,
  };
  return {
    scan_id: sid, total_usd: run,
    // The step name marks which run's usage is on screen (models are not shown).
    entries: [{ phase: `run_${run}_step`, model: "m", tokens_in: 10, tokens_out: 10,
      cost_micros: run * 1_000_000 }],
    models: [{ model: "m", calls: 1, tokens_in: 10,
      tokens_out: 10, cost_usd: run, phases: [`run_${run}_step`] }],
  };
}

async function releaseOld(page: Page, routes: Route[], error: boolean) {
  // Wait for browser receipt and rendering, not just Node's fulfill calls,
  // before asserting that the delayed responses left the visible data alone.
  const responses: Promise<unknown>[] = [];
  const observe = (response: import("@playwright/test").Response) => {
    if (routes.some(route => route.request() === response.request())) {
      responses.push(response.finished());
    }
  };
  page.on("response", observe);
  await Promise.all(routes.map(route => route.fulfill(error
    ? { status: 503, json: { detail: "Superseded resource request failed" } }
    : { json: payload(resourceOf(route.request().url()), 1) })));
  await expect.poll(() => responses.length).toBe(routes.length);
  await Promise.all(responses);
  page.off("response", observe);
  await page.evaluate(() => new Promise<void>(resolve => {
    requestAnimationFrame(() => requestAnimationFrame(() => resolve()));
  }));
}

for (const error of [false, true]) {
  test(`run completion ignores superseded resource ${error ? "errors" : "responses"}`, async ({ page, api }) => {
    api.scan.status = "running";
    api.scan.progress = 40;
    const delayed: Route[] = [];
    const freshResources = new Set<string>();
    let finished = false;
    await page.route(resourcePath, async route => {
      if (!finished) {
        delayed.push(route);
        return;
      }
      const resource = resourceOf(route.request().url());
      freshResources.add(resource);
      if (error) {
        if (resource === "diff") return route.fulfill({ status: 409, json: { detail: "No runs" } });
        return route.fulfill({ json: resource === "runs" ? [] : { scan_id: sid, total_usd: 0, entries: [], models: [] } });
      }
      return route.fulfill({ json: payload(resource, 2) });
    });
    await page.goto(`/scans/${sid}?tab=coverage&ctab=ai`);
    await expect(page.getByText("Fixture scan progress").first()).toBeVisible();
    await expect.poll(() => new Set(delayed.map(route => resourceOf(route.request().url()))).size).toBe(3);

    // Finish while every pre-completion resource request is still pending.
    // The status-boundary refresh must replace all three cached requests.
    finished = true;
    api.scan.status = "completed";
    api.scan.progress = 100;
    const results = page.getByRole("region", { name: "Scan results", exact: true });
    const configuration = page.getByRole("region", { name: "Scan configuration", exact: true });
    if (error) {
      await expect.poll(() => freshResources.size).toBe(3);
      await expect(results.getByRole("heading", { name: "No endpoint coverage yet" })).toBeVisible();
    } else {
      await expect(results.getByRole("cell", { name: "GET /run-2-coverage", exact: true })).toBeVisible();
      await expect(configuration.locator(".ai-steps")).toHaveText("Run 2 step");
    }
    await releaseOld(page, delayed, error);

    if (error) {
      await expect(results.getByRole("heading", { name: "No endpoint coverage yet" })).toBeVisible();
      await results.getByRole("tab", { name: /Changes/ }).click();
      await expect(results.getByRole("heading", { name: "No comparison available" })).toBeVisible();
      await expect(configuration.getByText("No AI usage has been recorded for this scan yet.")).toBeVisible();
    } else {
      await expect(results.getByRole("cell", { name: "GET /run-2-coverage", exact: true })).toBeVisible();
      await expect(results.getByRole("cell", { name: "GET /run-1-coverage", exact: true })).toHaveCount(0);
      await results.getByRole("tab", { name: /Changes/ }).click();
      await expect(results.getByRole("heading", { name: "Since run 1", exact: true })).toBeVisible();
      await expect(configuration.locator(".ai-steps")).toHaveText("Run 2 step");
    }
  });
}

test("discovering the latest run supersedes pending comparison and AI usage reads", async ({ page, api }) => {
  api.scan.status = "completed";
  const delayed: Route[] = [];
  let latestRun: Route | undefined;
  const counts = { diff: 0, cost: 0 };
  await page.route(resourcePath, async route => {
    const resource = resourceOf(route.request().url());
    if (resource === "runs") {
      latestRun = route;
      return;
    }
    if (++counts[resource as "diff" | "cost"] === 1) {
      delayed.push(route);
      return;
    }
    return route.fulfill({ json: payload(resource, 2) });
  });
  await page.goto(`/scans/${sid}?tab=changes&ctab=ai`);
  await expect.poll(() => delayed.length).toBe(2);
  await expect.poll(() => Boolean(latestRun)).toBe(true);
  await latestRun!.fulfill({ json: payload("runs", 2) });
  const results = page.getByRole("region", { name: "Scan results", exact: true });
  const configuration = page.getByRole("region", { name: "Scan configuration", exact: true });
  await expect(results.getByRole("heading", { name: "Since run 1", exact: true })).toBeVisible();
  await expect(configuration.locator(".ai-steps")).toHaveText("Run 2 step");
  await releaseOld(page, delayed, false);
  await expect(results.getByRole("heading", { name: "Since run 1", exact: true })).toBeVisible();
  await expect(configuration.locator(".ai-steps")).toHaveText("Run 2 step");
});
