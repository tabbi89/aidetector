import { test, expect, sid } from "./api-fixture";
import type { SecurityReview } from "../lib/api";

const suggestion = {
  title: "Separate public user responses", priority: "high" as const,
  observation: "The public user response declares password_hash.",
  risk: "A serializer using this schema could expose credential material.",
  recommendation: "Use a public response DTO that excludes password_hash.",
  validation: "Read the user endpoint with each identity and verify password_hash is absent.",
  assumptions: ["Check which serializer implements the response."],
  references: ["openapi#/components/schemas/User/properties/password_hash"],
};

test("AI security improvements remain visible without findings and fit mobile and dark mode", async ({ page, api }, info) => {
  api.scan.status = "completed";
  await page.route(url => new URL(url).pathname === "/scans/" + sid + "/runs", route => route.fulfill({ json: [{
    id: "review-run", run_number: 1, status: "completed", started_at: api.scan.created_at,
    findings_snapshot: [], coverage: [], plan: [], resources: [], options: { security_review: true },
    security_review: { status: "completed", schema_status: "available", model: "deepseek-chat",
      suggestions: [suggestion] } satisfies SecurityReview,
  }] }));
  await page.goto(`/scans/${sid}`);
  const workspace = page.getByRole("region", { name: "Scan results", exact: true });
  await workspace.getByRole("tab", { name: /Security improvements/ }).click();
  await expect(workspace.getByRole("heading", { name: suggestion.title })).toBeVisible();
  await expect(workspace.getByText(/Compared OpenAPI with the configured database/)).toBeVisible();
  await expect(workspace.getByText(suggestion.validation)).toBeVisible();
  await workspace.getByText("Schema references (1)").click();
  await expect(workspace.getByText(suggestion.references[0], { exact: true })).toBeVisible();
  await expect(workspace.getByRole("button", { name: "Confirm", exact: true })).toHaveCount(0);
  for (const width of [1440, 390]) {
    await page.setViewportSize({ width, height: 1000 });
    await workspace.screenshot({ path: info.outputPath(`security-review-${width}.png`) });
    await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
  }
  await page.evaluate(() => document.documentElement.dataset.theme = "dark");
  await workspace.screenshot({ path: info.outputPath("security-review-dark.png") });
});

for (const state of ["not_requested", "unavailable", "completed"] as const) {
  test(`AI security review explains ${state} state`, async ({ page, api }) => {
    api.scan.status = "completed";
    await page.route(url => new URL(url).pathname === "/scans/" + sid + "/runs", route => route.fulfill({ json: [{
      id: "review-run", run_number: 1, status: "completed", started_at: api.scan.created_at,
      findings_snapshot: [], coverage: [], plan: [], resources: [], options: {},
      security_review: { status: state, schema_status: "unavailable", model: "deepseek-chat",
        suggestions: [] } satisfies SecurityReview,
    }] }));
    await page.goto(`/scans/${sid}`);
    await page.getByRole("tab", { name: /Security improvements/ }).click();
    const message = state === "not_requested" ? "heavy-lane pass"
      : state === "unavailable" ? "The review could not finish"
        : "OpenAPI only: the configured database metadata was unavailable";
    await expect(page.getByText(message, { exact: state === "not_requested" })).toBeVisible();
  });
}
