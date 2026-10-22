import { test, expect } from "./api-fixture";

test("catalogue select supports keyboard selection, typeahead, Escape and URL restore", async ({
  page,
  api,
}) => {
  void api;
  await page.goto("/coverage#check-details");
  const evidence = page.getByRole("combobox", {
    name: "Evidence",
    exact: true,
  });
  await evidence.focus();
  await page.keyboard.press("Space");
  await expect(page.getByRole("listbox", { name: "Evidence" })).toBeVisible();
  await page.keyboard.press("End");
  await page.keyboard.press("Enter");
  await expect(evidence).toHaveAttribute("data-value", "planned");
  await expect(evidence).toBeFocused();
  await expect(page).toHaveURL(/evidence=planned/);
  await evidence.click();
  await expect(
    page.getByRole("option", { name: "Planned", exact: true }),
  ).toBeFocused();
  await page.keyboard.press("v");
  await expect(
    page.getByRole("option", { name: "Verified", exact: true }),
  ).toBeFocused();
  await page.keyboard.press("Enter");
  await expect(evidence).toHaveAttribute("data-value", "verified");
  await evidence.click();
  await page.keyboard.press("ArrowDown");
  await page.keyboard.press("Escape");
  await expect(evidence).toHaveAttribute("data-value", "verified");
  await expect(evidence).toBeFocused();
  await page.reload();
  await expect(evidence).toContainText("Verified");
});

for (const width of [390, 1280]) {
  test(`filter menus fit and preserve full risk names at ${width}px in both themes`, async ({
    page,
    api,
  }, info) => {
    void api;
    await page.setViewportSize({ width, height: 740 });
    for (const theme of ["light", "dark"]) {
      await page.goto("/coverage?risk=API3%3A2023#check-details");
      await page.evaluate(
        (value) => (document.documentElement.dataset.theme = value),
        theme,
      );
      const risk = page.getByRole("combobox", {
        name: "Risk area",
        exact: true,
      });
      await expect(risk).toContainText("API3 · Private fields");
      await risk.click();
      const menu = page.getByRole("listbox", {
        name: "Risk area",
        exact: true,
      });
      const selected = menu.getByRole("option", {
        name: /API3 · Private fields/,
      });
      await expect(selected).toHaveAttribute("aria-selected", "true");
      await expect(selected).toContainText(
        "Broken Object Property Level Authorization",
      );
      const triggerBox = await page
          .getByRole("combobox", {
            name: "Risk area",
            exact: true,
            includeHidden: true,
          })
          .boundingBox(),
        menuBox = await menu.boundingBox();
      expect(triggerBox).not.toBeNull();
      expect(menuBox).not.toBeNull();
      expect(Math.abs(triggerBox!.width - menuBox!.width)).toBeLessThanOrEqual(
        1,
      );
      expect(Math.abs(triggerBox!.x - menuBox!.x)).toBeLessThanOrEqual(1);
      expect(menuBox!.x).toBeGreaterThanOrEqual(0);
      expect(menuBox!.x + menuBox!.width).toBeLessThanOrEqual(width);
      expect(menuBox!.y).toBeGreaterThanOrEqual(0);
      expect(menuBox!.y + menuBox!.height).toBeLessThanOrEqual(740);
      await page.screenshot({
        path: info.outputPath(`risk-menu-${theme}-${width}.png`),
      });
      await page.keyboard.press("Escape");
      await expect(risk).toBeFocused();
      expect(
        await page.evaluate(() => document.documentElement.scrollWidth),
      ).toBeLessThanOrEqual(width);
    }
  });
}

test("homepage evidence intro has breathing room and the stack strip identifies all three services", async ({
  page,
  api,
}) => {
  void api;
  await page.addInitScript(() =>
    sessionStorage.removeItem("aidetector.api-key"),
  );
  await page.route("http://api.test/auth/status", (route) =>
    route.fulfill({ status: 401, json: { detail: "Not authenticated" } }),
  );
  await page.goto("/");
  for (const width of [320, 390, 1280]) {
    await page.setViewportSize({ width, height: 900 });
    const intro = await page.locator("#decide .evidence-intro").boundingBox();
    const example = await page
      .locator("#decide [aria-label='Evidence examples']")
      .locator("../..")
      .boundingBox();
    expect(example!.y - (intro!.y + intro!.height)).toBeGreaterThanOrEqual(
      width <= 640 ? 28 : 36,
    );
    expect(
      await page.evaluate(() => document.documentElement.scrollWidth),
    ).toBeLessThanOrEqual(width);
  }
  const strip = page.getByRole("region", { name: "Built with" });
  for (const name of ["Cloudflare", "Stripe", "OpenAI"])
    await expect(
      strip.getByRole("heading", { name, exact: true }),
    ).toBeVisible();
});
