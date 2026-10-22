import { test, expect, sid, finding } from "./api-fixture";

const freeCapabilities = {
  passes: Object.fromEntries(
    ["plan", "adjudicate", "security_review", "genai_payloads"].map((key) => [
      key, { available: true, reason: null },
    ]),
  ),
  premium: { available: false, plan: "free", reason: "Requires a Premium workspace plan." },
};

test("plan labels distinguish access from availability and do not preselect paid work", async ({ page, api }, info) => {
  void api;
  await page.goto(`/scans/${sid}`);
  const access = page.getByRole("region", { name: "Plan access", exact: true });
  await expect(access.getByRole("status")).toHaveText("Premium access enabled");
  await expect(access.getByText("On every plan", { exact: true })).toBeVisible();
  await expect(page.getByRole("tab", { name: /Schema context/ }).getByText("Premium", { exact: true })).toBeVisible();
  // AI design review is included, even though some other AI passes are paid.
  await expect(page.getByRole("tab", { name: /Security improvements/ }).getByText("Premium", { exact: true })).toHaveCount(0);
  await page.getByRole("button", { name: /Run now/ }).click();
  const panel = page.locator("#run-panel");
  await expect(panel.getByRole("checkbox", { name: /^Include premium detections/ })).not.toBeChecked();
  for (const name of [/Test writes/, /Use AI/]) {
    await expect(panel.getByRole("checkbox", { name })).not.toBeChecked();
  }
  await panel.locator("summary", { hasText: "Choose AI passes" }).click();
  for (const [title, badge] of [["Risk plan", "Included"], ["Security design review", "Included"], ["Adaptive validation", "Premium"]]) {
    const option = panel.locator("label.opt").filter({ has: page.getByRole("checkbox", { name: title, exact: true }) });
    await expect(option.getByText(badge, { exact: true })).toBeVisible();
  }
  for (const theme of ["dark", "light"]) {
    await page.evaluate((value) => { document.documentElement.dataset.theme = value; }, theme);
    for (const width of [1440, 390]) {
      await page.setViewportSize({ width, height: 1000 });
      await expect(access).toBeVisible();
      expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
      await access.screenshot({ path: info.outputPath(`access-${theme}-${width}.png`) });
      await panel.screenshot({ path: info.outputPath(`options-${theme}-${width}.png`) });
    }
  }
});

test("Free can review results but web runs and schedules explain the Premium requirement", async ({ page, api }, info) => {
  api.scan.status = "completed";
  api.findings = [finding];
  await page.route("http://api.test/capabilities", (route) => route.fulfill({ json: freeCapabilities }));
  await page.goto(`/scans/${sid}`);
  await expect(page.getByRole("region", { name: "Plan access", exact: true }).getByRole("status")).toHaveText("Free workspace");
  await page.getByRole("button", { name: /Ask your scan/ }).click();
  await expect(page.getByText("Premium workspace required", { exact: true })).toBeVisible();
  await expect(page.getByRole("textbox", { name: "Question about the scan" })).toBeDisabled();
  await expect(page.getByRole("button", { name: "Ask", exact: true })).toBeDisabled();
  await expect(page.getByText(finding.title, { exact: true })).toBeVisible();
  await page.getByRole("button", { name: /Run now/ }).click();
  const panel = page.locator("#run-panel");
  await expect(panel.getByRole("heading", { name: "Web scans require Premium" })).toBeVisible();
  await expect(panel.getByRole("link", { name: "Run with the CLI" })).toHaveAttribute("href", "/cli");
  await expect(panel.getByRole("button", { name: "Run scan", exact: true })).toHaveCount(0);
  await page.getByRole("tab", { name: /Schedule/ }).click();
  await expect(page.locator("#config-panel-schedule").getByRole("heading", { name: "Web scans require Premium" })).toBeVisible();
  await panel.screenshot({ path: info.outputPath("free-web-run.png") });
  expect(api.requests.filter((request) => request.path.endsWith("/ask") || request.path.endsWith("/run"))).toHaveLength(0);
});

test("a failed plan check stays unconfirmed and can recover without losing run choices", async ({ page, api }) => {
  void api;
  let recovered = false;
  await page.route("http://api.test/capabilities", (route) => {
    return !recovered
      ? route.fulfill({ status: 503, json: { detail: "Plan service unavailable" } })
      : route.fulfill({ json: { ...freeCapabilities, premium: { available: true, plan: "premium", reason: null } } });
  });
  await page.goto(`/scans/${sid}`);
  const access = page.getByRole("region", { name: "Plan access", exact: true });
  await expect(access.getByRole("status")).toHaveText("Plan not confirmed");
  await page.getByRole("button", { name: /Run now/ }).click();
  await page.getByRole("radiogroup", { name: "Scan level" }).getByText("Deep", { exact: true }).click();
  recovered = true;
  await access.getByRole("button", { name: "Retry plan check" }).click();
  await expect(access.getByRole("status")).toHaveText("Premium access enabled");
  await expect(page.getByRole("radio", { name: "Deep", exact: true })).toBeChecked();
  await expect(access.getByRole("button", { name: "Retry plan check" })).toHaveCount(0);
});

test("missing entitlement and unchecked tools never claim Premium or runtime availability", async ({ page, api }) => {
  void api;
  await page.route("http://api.test/capabilities", (route) => route.fulfill({ json: { passes: {} } }));
  await page.goto(`/scans/${sid}`);
  await expect(page.getByRole("region", { name: "Plan access", exact: true }).getByRole("status")).toHaveText("Plan not confirmed");
  await page.getByRole("button", { name: /Run now/ }).click();
  await page.locator("summary", { hasText: "Feature availability" }).click();
  await expect(page.locator(".feat-chip.unknown")).toHaveText("Not checked");
});

test("retrying plan access updates mounted run and question controls together", async ({ page, api }) => {
  api.scan.status = "completed";
  api.findings = [finding];
  let attempts = 0;
  let recovered = false;
  await page.route("http://api.test/capabilities", (route) => {
    attempts += 1;
    return !recovered
      ? route.fulfill({ status: 503, json: { detail: "Temporary plan failure" } })
      : route.fulfill({ json: freeCapabilities });
  });
  await page.goto(`/scans/${sid}`);
  const access = page.getByRole("region", { name: "Plan access", exact: true });
  await expect(access.getByRole("status")).toHaveText("Plan not confirmed");
  await page.getByRole("button", { name: /Ask your scan/ }).click();
  await page.getByRole("button", { name: /Run now/ }).click();
  await expect(page.getByRole("radiogroup", { name: "Scan level" })).toBeVisible();
  await expect(access.getByRole("status")).toHaveText("Plan not confirmed");
  const attemptsBeforeRetry = attempts;
  recovered = true;
  await access.getByRole("button", { name: "Retry plan check" }).click();
  await expect(access.getByRole("status")).toHaveText("Free workspace");
  await expect(page.locator("#run-panel").getByRole("heading", { name: "Web scans require Premium" })).toBeVisible();
  await expect(page.getByRole("textbox", { name: "Question about the scan" })).toBeDisabled();
  expect(attempts).toBe(attemptsBeforeRetry + 1);
});

test("plan loading is explicit and keyboard navigation reaches the paid configuration section", async ({ page, api }) => {
  void api;
  let release!: () => void;
  const pending = new Promise<void>((resolve) => { release = resolve; });
  await page.route("http://api.test/capabilities", async (route) => {
    await pending;
    await route.fulfill({ json: freeCapabilities });
  });
  await page.goto(`/scans/${sid}`);
  const access = page.getByRole("region", { name: "Plan access", exact: true });
  await expect(access.getByRole("status")).toHaveText("Checking plan…");
  release();
  await expect(access.getByRole("status")).toHaveText("Free workspace");
  const specTab = page.getByRole("tab", { name: /API spec/ });
  await specTab.focus();
  for (let i = 0; i < 3; i += 1) await page.keyboard.press("ArrowDown");
  await expect(page.getByRole("tab", { name: /Schema context.*Premium/ })).toBeFocused();
  await expect(page.getByRole("heading", { name: "Schema context", exact: true })).toBeVisible();
});
