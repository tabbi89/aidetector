import { test, expect } from "./api-fixture";

test("CLI section highlighting follows deep links, clicks and scrolling without rewriting history", async ({
  page,
  api,
}) => {
  void api;
  await page.emulateMedia({ reducedMotion: "reduce" });
  await page.goto("/cli#ci");
  const nav = page.getByRole("navigation", { name: "CLI guide sections" });
  const ci = nav.getByRole("link", { name: "Gate a pipeline" });
  await expect(ci).toHaveAttribute("aria-current", "location");
  await nav.getByRole("link", { name: "Local runs", exact: true }).click();
  await expect(page).toHaveURL(/#local$/);
  await expect(
    nav.getByRole("link", { name: "Local runs", exact: true }),
  ).toHaveAttribute("aria-current", "location");
  await page.locator("#ci").evaluate((element) => element.scrollIntoView());
  await expect(ci).toHaveAttribute("aria-current", "location");
  await expect(nav.locator('[aria-current="location"]')).toHaveCount(1);
  await expect(page).toHaveURL(/#local$/);
  const target = await page.locator("#ci").boundingBox(),
    bar = await nav.boundingBox();
  expect(target!.y).toBeGreaterThanOrEqual(bar!.y + bar!.height);
  await page.goBack();
  await expect(page).toHaveURL(/#ci$/);
  await expect(ci).toHaveAttribute("aria-current", "location");
});

test("Coverage uses the same current-section state and narrow layout", async ({
  page,
  api,
}) => {
  void api;
  await page.setViewportSize({ width: 390, height: 900 });
  await page.goto("/coverage#check-details");
  const nav = page.getByRole("navigation", { name: "Coverage sections" });
  await expect(
    nav.getByRole("link", { name: "Explore checks" }),
  ).toHaveAttribute("aria-current", "location");
  await page
    .locator("#evidence-guide")
    .evaluate((element) => element.scrollIntoView());
  await expect(
    nav.getByRole("link", { name: "Read the evidence" }),
  ).toHaveAttribute("aria-current", "location");
  await expect(page).toHaveURL(/#check-details$/);
  const intro = await page.locator("#evidence-guide > p").boundingBox();
  const example = await page
    .locator('#evidence-guide [aria-label="Evidence examples"]')
    .locator("../..")
    .boundingBox();
  expect(example!.y - intro!.y - intro!.height).toBeGreaterThanOrEqual(28);
  expect(
    await page.evaluate(() => document.documentElement.scrollWidth),
  ).toBeLessThanOrEqual(390);
});

test("dark default survives blocked storage and no JavaScript; brand fits the narrow header", async ({
  browser,
  api,
  page,
}) => {
  void api;
  await page.addInitScript(() => {
    Object.defineProperty(window, "localStorage", {
      get() {
        throw new Error("Storage blocked");
      },
    });
  });
  await page.goto("/coverage");
  await expect(page.locator("html")).toHaveAttribute("data-theme", "dark");
  for (const width of [320, 390, 1280]) {
    await page.setViewportSize({ width, height: 900 });
    await expect(
      page.getByRole("banner").getByRole("link", { name: "runpentests." }),
    ).toBeVisible();
    expect(
      await page.evaluate(() => document.documentElement.scrollWidth),
    ).toBeLessThanOrEqual(width);
  }
  const context = await browser.newContext({ javaScriptEnabled: false });
  const staticPage = await context.newPage();
  await staticPage.goto("http://127.0.0.1:3107/coverage");
  await expect(staticPage.locator("html")).toHaveAttribute(
    "data-theme",
    "dark",
  );
  await context.close();
});
