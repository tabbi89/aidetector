import { test, expect } from "./api-fixture";

test("configuration precedence fits every column without hidden horizontal content", async ({
  page,
  api,
}) => {
  void api;
  await page.goto("/cli");
  const table = page.getByRole("table", {
    name: "Which configuration value wins for this run",
  });
  for (const width of [320, 390, 460, 961, 1440]) {
    await page.setViewportSize({ width, height: 900 });
    const dimensions = await page.locator(".prec-wrap").evaluate((element) => ({
      width: element.clientWidth,
      scroll: element.scrollWidth,
    }));
    expect(
      dimensions.scroll,
      `all columns visible at ${width}px`,
    ).toBeLessThanOrEqual(dimensions.width + 1);
    await expect(table.locator("tfoot")).toHaveText(
      /This run uses\s*critical\s*5\s*uploaded spec/,
    );
    for (const text of [
      "runpentests.yml",
      "Flags",
      "Web settings",
      "Defaults",
    ]) {
      await expect(
        table
          .getByRole("rowheader", {
            name: new RegExp(text.replace(".", "\\.")),
          })
          .first(),
      ).toBeVisible();
    }
  }
});

test("coverage and CLI use matching illustrated headers in both themes", async ({
  page,
  api,
}, info) => {
  void api;
  await page.emulateMedia({ reducedMotion: "reduce" });
  for (const route of ["coverage", "cli"]) {
    await page.goto(`/${route}`);
    for (const width of [390, 1280]) {
      await page.setViewportSize({ width, height: 900 });
      for (const theme of ["light", "dark"]) {
        await page.evaluate((value) => {
          document.documentElement.dataset.theme = value;
        }, theme);
        await expect(page.getByRole("heading", { level: 1 })).toBeVisible();
        await expect(page.getByRole("figure").first()).toBeVisible();
        await page
          .locator("main > section")
          .first()
          .screenshot({
            path: info.outputPath(`${route}-${theme}-${width}.png`),
          });
        expect(
          await page.evaluate(() => document.documentElement.scrollWidth),
        ).toBeLessThanOrEqual(width);
      }
    }
  }
});
