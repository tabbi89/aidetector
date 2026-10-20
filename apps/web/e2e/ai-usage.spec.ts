import { expect, sid, test } from "./api-fixture";

const entry = (phase: string, tokens_in: number, tokens_out: number, cost_micros: number) =>
  ({ phase, model: "deepseek-chat", tokens_in, tokens_out, cost_micros });

test("AI usage names the steps, never the model, and fits every viewport", async ({ page, api }, info) => {
  api.scan.status = "completed";
  api.cost = {
    scan_id: sid, total_usd: 0.0027,
    entries: [
      entry("plan", 586, 203, 100), entry("security_review", 3940, 1704, 1000),
      entry("qa", 1852, 203, 300), entry("plan", 586, 251, 200),
      entry("security_review", 3940, 1699, 1000),
    ],
    models: [{ model: "deepseek-chat", calls: 5, tokens_in: 10904, tokens_out: 4060,
      cost_usd: 0.0027, phases: ["plan", "security_review", "qa"] }],
  };
  await page.goto(`/scans/${sid}?ctab=ai`);
  const configuration = page.getByRole("region", { name: "Scan configuration", exact: true });
  const summary = configuration.locator(".ai-summary");
  await expect(summary.locator(".ai-steps")).toHaveText("Planning · Security design review · Questions");
  await expect(summary.locator(".ai-calls")).toHaveText("5 calls");
  await expect(summary.locator(".ai-total")).toHaveText("$0.0027");
  await summary.click();

  // One row per step, repeat calls folded in.
  const table = configuration.getByRole("table", { name: "AI usage by step" });
  await expect(table.getByRole("row")).toHaveCount(4);
  const review = table.getByRole("row").filter({ hasText: "Security design review" });
  await expect(review).toContainText("× 2");
  await expect(review).toContainText("7,880");
  await expect(review).toContainText("$0.0020");
  await expect(configuration.getByText(/deepseek/i)).toHaveCount(0);

  const panel = configuration.locator(".ai-panel");
  for (const width of [1280, 390]) {
    await page.setViewportSize({ width, height: 900 });
    await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
    await panel.screenshot({ path: info.outputPath(`ai-usage-${width}.png`) });
  }
  await page.evaluate(() => document.documentElement.dataset.theme = "dark");
  await panel.screenshot({ path: info.outputPath("ai-usage-dark.png") });
});
