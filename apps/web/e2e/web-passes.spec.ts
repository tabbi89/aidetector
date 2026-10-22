import { test, expect, sid } from "./api-fixture";

test("premium detections can be requested on Quick and survive a scope change", async ({
  page,
  api,
}) => {
  await page.goto(`/scans/${sid}`);
  await page.getByRole("button", { name: /Run now/ }).click();
  const premium = page.getByRole("checkbox", {
    name: /^Include premium detections/,
  });
  await expect(premium).not.toBeChecked();
  await premium.check();
  await page.locator("summary", { hasText: "Customise checks" }).click();
  await page
    .getByRole("radiogroup", { name: "Scan scope" })
    .getByText("Headers & exposure", { exact: true })
    .click();
  await expect(premium).toBeChecked();
  await expect(
    page.getByRole("checkbox", { name: /Use AI/ }),
  ).not.toBeChecked();
  await expect(
    page.getByRole("checkbox", { name: /Test writes/ }),
  ).not.toBeChecked();
  await page
    .getByRole("checkbox", { name: /I own, or am explicitly authorized/ })
    .check();
  await page.getByRole("button", { name: "Run scan", exact: true }).click();
  expect(
    api.requests.find((request) => request.path.endsWith("/run"))?.body,
  ).toMatchObject({ level: "quick", premium: true, ai: false, mutate: false });
});

test("Deep and its AI bundle run from the web while writes stay off", async ({
  page,
  api,
}, info) => {
  await page.goto(`/scans/${sid}`);
  await page.getByRole("button", { name: /Run now/ }).click();
  await page
    .getByRole("radiogroup", { name: "Scan level" })
    .getByText("Deep", { exact: true })
    .click();
  await expect(
    page.getByText(/These can add traffic beyond the core/),
  ).toBeVisible();
  await page.getByRole("checkbox", { name: /Use AI/ }).check();
  for (const name of [
    /^Risk plan/,
    /^Review findings/,
    /^Security design review/,
    /^Generate payloads/,
    /^Adaptive validation/,
  ]) {
    await expect(page.getByRole("checkbox", { name })).toBeChecked();
  }
  await expect(
    page.getByRole("checkbox", { name: /^Refine test resources/ }),
  ).toBeDisabled();
  await expect(
    page.getByRole("checkbox", { name: /Test writes/ }),
  ).not.toBeChecked();
  await page
    .locator(".specbox")
    .filter({ has: page.getByRole("radiogroup", { name: "Scan level" }) })
    .last()
    .screenshot({ path: info.outputPath("deep-web-passes.png") });
  await page
    .getByRole("checkbox", { name: /I own, or am explicitly authorized/ })
    .check();
  await page.getByRole("button", { name: "Run scan", exact: true }).click();
  expect(
    api.requests.find((request) => request.path.endsWith("/run"))?.body,
  ).toMatchObject({
    level: "deep",
    ai: true,
    mutate: false,
    resource_refine: false,
    agent: false,
  });
});

test("individual AI passes send only the requested work and enforce refinement prerequisites", async ({
  page,
  api,
}) => {
  await page.goto(`/scans/${sid}`);
  await page.getByRole("button", { name: /Run now/ }).click();
  await page.locator("summary", { hasText: "Choose AI passes" }).click();
  await page.getByRole("checkbox", { name: /^Security design review/ }).check();
  await page.getByRole("checkbox", { name: /^Adaptive validation/ }).check();
  const refinement = page.getByRole("checkbox", {
    name: /^Refine test resources/,
  });
  await expect(refinement).toBeDisabled();
  await page.getByRole("checkbox", { name: /Test writes/ }).check();
  await refinement.check();
  await page
    .getByRole("combobox", { name: /Validation attempts per test/ })
    .selectOption("2");
  await page
    .getByRole("combobox", { name: /Create attempts per resource/ })
    .selectOption("2");
  await page
    .getByRole("checkbox", { name: /I own, or am explicitly authorized/ })
    .check();
  api.failNext = `/scans/${sid}/run`;
  await page.getByRole("button", { name: "Run scan", exact: true }).click();
  await expect(page.getByText("Temporary fixture failure")).toBeVisible();
  await expect(refinement).toBeChecked();
  await page.getByRole("button", { name: "Run scan", exact: true }).click();
  expect(
    api.requests.filter((request) => request.path.endsWith("/run")).at(-1)
      ?.body,
  ).toMatchObject({
    level: "quick",
    ai: false,
    security_review: true,
    plan: false,
    adjudicate: false,
    genai_payloads: false,
    adaptive: true,
    adaptive_attempts: 2,
    resource_refine: true,
    resource_attempts: 2,
    premium: true,
    mutate: true,
  });
});

test("customizing an AI bundle allows an opt-out and turning AI off clears every pass", async ({
  page,
  api,
}) => {
  void api;
  await page.goto(`/scans/${sid}`);
  await page.getByRole("button", { name: /Run now/ }).click();
  const ai = page.getByRole("checkbox", { name: /Use AI/ });
  await ai.check();
  await page.getByRole("checkbox", { name: /^Review findings/ }).uncheck();
  await expect(
    page.getByRole("checkbox", { name: /^Risk plan/ }),
  ).toBeChecked();
  await expect(
    page.getByRole("checkbox", { name: /^Security design review/ }),
  ).toBeChecked();
  await ai.uncheck();
  await page.locator("summary", { hasText: "Choose AI passes" }).click();
  for (const name of [
    /^Risk plan/,
    /^Review findings/,
    /^Security design review/,
    /^Generate payloads/,
    /^Adaptive validation/,
    /^Refine test resources/,
  ]) {
    await expect(page.getByRole("checkbox", { name })).not.toBeChecked();
  }
});

test("a free plan offers local CLI execution instead of a web run", async ({
  page,
  api,
}) => {
  void api;
  await page.route("http://api.test/capabilities", (route) =>
    route.fulfill({
      json: {
        passes: Object.fromEntries(
          ["plan", "adjudicate", "security_review", "genai_payloads"].map(
            (key) => [key, { available: true, reason: null }],
          ),
        ),
        premium: {
          available: false,
          plan: "free",
          reason: "Premium requires this workspace to have a paid plan.",
        },
      },
    }),
  );
  await page.goto(`/scans/${sid}`);
  await page.getByRole("button", { name: /Run now/ }).click();
  await expect(page.getByRole("heading", { name: "Web scans require Premium" })).toBeVisible();
  await expect(page.getByRole("link", { name: "Run with the CLI" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Run scan", exact: true })).toHaveCount(0);
});

test("unavailable AI is explained and cannot be newly enabled", async ({
  page,
  api,
}) => {
  void api;
  await page.route("http://api.test/capabilities", (route) =>
    route.fulfill({
      json: {
        passes: Object.fromEntries(
          ["plan", "adjudicate", "security_review", "genai_payloads"].map(
            (key) => [
              key,
              { available: false, reason: "AI runtime is not configured." },
            ],
          ),
        ),
        premium: { available: true, plan: "premium", reason: null },
      },
    }),
  );
  await page.goto(`/scans/${sid}`);
  await page.getByRole("button", { name: /Run now/ }).click();
  await expect(page.getByRole("checkbox", { name: /Use AI/ })).toBeDisabled();
  await page.locator("summary", { hasText: "Choose AI passes" }).click();
  await expect(
    page.getByRole("checkbox", { name: /^Risk plan/ }),
  ).toBeDisabled();
  await expect(
    page.getByText("AI runtime is not configured.", { exact: true }).first(),
  ).toBeVisible();
});
