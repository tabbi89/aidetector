import { test, expect, sid } from "./api-fixture";

test("evidence examples explain proof, leads and gaps without sending a scan", async ({
  page,
  api,
}) => {
  await page.goto("/coverage");
  const choices = page.getByRole("group", { name: "Evidence examples" });
  await expect(
    choices.getByRole("button", { name: "Wrong account" }),
  ).toHaveAttribute("aria-pressed", "true");
  await expect(
    page.getByText("Bob receives Alice’s order", { exact: true }),
  ).toBeVisible();
  await choices.getByRole("button", { name: "Risky input" }).focus();
  await page.keyboard.press("Enter");
  await expect(
    page.getByText("Reflection observed", { exact: true }),
  ).toBeVisible();
  await expect(
    page.getByText(/It does not prove that a database/),
  ).toBeVisible();
  await choices.getByRole("button", { name: "Skipped check" }).click();
  await expect(
    page.getByText("Cross-account proof unavailable", { exact: true }),
  ).toBeVisible();
  await expect(page.getByText(/A skipped check is untested/)).toBeVisible();
  expect(api.requests.filter((request) => request.method !== "GET")).toEqual(
    [],
  );
});

test("coverage search, filters, URL restore and no-results recovery work together", async ({
  page,
  api,
}) => {
  void api;
  await page.goto("/coverage");
  const search = page.getByRole("searchbox", { name: "Search checks" });
  await expect(
    page.getByText("What we observe", { exact: true }).first(),
  ).not.toBeVisible();
  await search.fill("BOLA");
  await expect(page).toHaveURL(/q=BOLA/);
  await page.getByRole("combobox", { name: "Evidence", exact: true }).click();
  await page.getByRole("option", { name: "Verified", exact: true }).click();
  await page.getByRole("combobox", { name: "Plan", exact: true }).click();
  await page.getByRole("option", { name: "Free", exact: true }).click();
  await expect(page).toHaveURL(/evidence=verified/);
  await page.reload();
  await expect(search).toHaveValue("BOLA");
  await expect(page.getByLabel("Evidence", { exact: true })).toHaveAttribute(
    "data-value",
    "verified",
  );
  const check = page
    .locator("summary")
    .filter({ hasText: "Broken Object Level Authorization (BOLA)" });
  await check.click();
  await expect(
    page.getByText("What we observe", { exact: true }).first(),
  ).toBeVisible();
  await search.fill("no-such-signal-12345");
  await expect(
    page.getByRole("heading", { name: "No matching checks" }),
  ).toBeVisible();
  await page.getByRole("button", { name: "Clear search", exact: true }).click();
  await expect(search).toBeFocused();
  await expect(search).toHaveValue("");
  await expect(page.getByLabel("Evidence", { exact: true })).toHaveAttribute(
    "data-value",
    "verified",
  );
  await page.getByRole("button", { name: "Clear filters" }).click();
  await expect(page.getByLabel("Evidence", { exact: true })).toHaveAttribute(
    "data-value",
    "",
  );
  await expect(page.getByLabel("Plan", { exact: true })).toHaveAttribute(
    "data-value",
    "",
  );
  await expect(page).toHaveURL("/coverage");
});

test("coverage input commits after IME composition and area links select the risk", async ({
  page,
  api,
}) => {
  void api;
  await page.goto("/coverage");
  const search = page.getByRole("searchbox", { name: "Search checks" });
  await search.dispatchEvent("compositionstart");
  await search.fill("token");
  await expect(search).toHaveValue("token");
  await expect(page).toHaveURL("/coverage");
  await search.dispatchEvent("compositionend");
  await expect(page).toHaveURL(/q=token/);
  await page.getByRole("link", { name: /Other people’s data/ }).click();
  await expect(page.getByLabel("Risk area", { exact: true })).toHaveAttribute(
    "data-value",
    "API1:2023",
  );
  await expect(search).toHaveValue("");
  await expect(page).toHaveURL(/#check-details$/);
  const filters = page.getByRole("search", { name: "Test catalogue" });
  await filters.getByLabel("Evidence", { exact: true }).focus();
  await page.keyboard.press("Space");
  await page.keyboard.press("Escape");
  await expect(filters.getByLabel("Evidence", { exact: true })).toBeFocused();
});

test("shared validation focuses errors, preserves values and clears between auth modes", async ({
  page,
  api,
}) => {
  await page.addInitScript(() =>
    sessionStorage.removeItem("aidetector.api-key"),
  );
  await page.goto("/login");
  const signIn = page.getByRole("button", { name: "Sign in", exact: true });
  await signIn.click();
  const email = page.getByLabel("Email", { exact: true });
  await expect(email).toBeFocused();
  await expect(email).toHaveAttribute("aria-invalid", "true");
  await expect(
    page.getByRole("alert").filter({ hasText: "Check the highlighted fields" }),
  ).toBeVisible();
  expect(api.requests.some((request) => request.path === "/auth/login")).toBe(
    false,
  );
  await email.fill("person@example.test");
  await expect(email).not.toHaveAttribute("aria-invalid");
  await expect(email).toHaveValue("person@example.test");
  await page
    .getByRole("button", { name: "Request access", exact: true })
    .click();
  await expect(
    page.getByText("Check the highlighted fields.", { exact: true }),
  ).toHaveCount(0);
  await expect(email).toHaveValue("person@example.test");
});

test("text editors grow without manual resizing and existing run gates stay explicit", async ({
  page,
  api,
}) => {
  void api;
  await page.goto(`/scans/${sid}`);
  await page.getByRole("button", { name: /Run now/ }).click();
  const run = page.getByRole("button", { name: "Run scan", exact: true });
  await expect(run).toBeDisabled();
  await expect(
    page.getByRole("checkbox", { name: /Test writes/ }),
  ).not.toBeChecked();
  await expect(
    page.getByRole("checkbox", { name: /Use AI/ }),
  ).not.toBeChecked();
  await page
    .getByRole("radiogroup", { name: "Scan level" })
    .getByText("Standard", { exact: true })
    .click();
  await expect(
    page.getByRole("checkbox", { name: /Test writes/ }),
  ).not.toBeChecked();
  await expect(
    page.getByRole("checkbox", { name: /Use AI/ }),
  ).not.toBeChecked();
  await expect(page.getByRole("radio", { name: /Deep/ })).toBeEnabled();
  await expect(run).toBeDisabled();
  await page.goto("/scans/new");
  await page
    .getByLabel("Base URL", { exact: true })
    .fill("https://target.test");
  await page.getByRole("button", { name: "Create & continue" }).click();
  const editor = page.getByLabel(/Spec contents/);
  const height = await editor.evaluate(
    (element) => element.getBoundingClientRect().height,
  );
  await editor.fill(
    Array.from({ length: 100 }, (_, index) => `line ${index}`).join("\n"),
  );
  await expect
    .poll(() =>
      editor.evaluate((element) => element.getBoundingClientRect().height),
    )
    .toBeGreaterThan(height);
  expect(
    await editor.evaluate((element) => getComputedStyle(element).resize),
  ).toBe("none");
  expect(
    await editor.evaluate((element) => element.getBoundingClientRect().height),
  ).toBeLessThanOrEqual(520);
});

test("destructive confirmation is keyboard safe, preserves failed actions and prevents duplicate dispatch", async ({
  page,
  api,
}) => {
  await page.goto(`/scans/${sid}`);
  const remove = page.getByRole("button", { name: "Delete scan", exact: true });
  await remove.click();
  const dialog = page.getByRole("dialog", { name: "Delete scan permanently?" });
  const cancel = dialog.getByRole("button", { name: "Cancel", exact: true });
  await expect(cancel).toBeFocused();
  await page.keyboard.press("Shift+Tab");
  await expect(
    dialog.getByRole("button", { name: "Delete scan", exact: true }),
  ).toBeFocused();
  await page.keyboard.press("Escape");
  await expect(dialog).not.toBeVisible();
  await expect(remove).toBeFocused();
  expect(api.requests.some((request) => request.method === "DELETE")).toBe(
    false,
  );
  await remove.click();
  api.failNext = `/scans/${sid}`;
  await dialog
    .getByRole("button", { name: "Delete scan", exact: true })
    .click();
  await expect(dialog.getByRole("alert")).toContainText(
    "Temporary fixture failure",
  );
  await expect(dialog).toBeVisible();
  let calls = 0;
  let release: () => void = () => undefined;
  const gate = new Promise<void>((resolve) => {
    release = resolve;
  });
  await page.route(`http://api.test/scans/${sid}`, async (route) => {
    if (route.request().method() !== "DELETE") return route.fallback();
    calls += 1;
    await gate;
    await route.fulfill({ json: { status: "deleted" } });
  });
  const confirm = dialog.getByRole("button", {
    name: "Delete scan",
    exact: true,
  });
  await confirm.click();
  await expect(confirm).toBeDisabled();
  await expect(cancel).toBeDisabled();
  await page.keyboard.press("Escape");
  await expect(dialog).toBeVisible();
  release();
  await expect(page).toHaveURL("/scans");
  expect(calls).toBe(1);
});

for (const width of [390, 1280]) {
  test(`guides remain usable in both themes at ${width}px`, async ({
    page,
    api,
  }, testInfo) => {
    void api;
    await page.emulateMedia({ reducedMotion: "reduce" });
    await page.setViewportSize({ width, height: 900 });
    for (const theme of ["light", "dark"]) {
      await page.goto("/coverage");
      await page.evaluate((value) => {
        document.documentElement.dataset.theme = value;
      }, theme);
      await page
        .getByRole("button", { name: "Risky input", exact: true })
        .click();
      await expect(
        page.getByText("Reflection observed", { exact: true }),
      ).toBeVisible();
      const contrast = await page
        .locator("#evidence-guide .conf.heuristic")
        .evaluate((element) => {
          const style = getComputedStyle(element);
          const luminance = (color: string) => {
            const parts = (color.match(/[\d.]+/g) ?? [])
              .slice(0, 3)
              .map((value) => {
                const channel = Number(value) / 255;
                return channel <= 0.04045
                  ? channel / 12.92
                  : ((channel + 0.055) / 1.055) ** 2.4;
              });
            return parts[0] * 0.2126 + parts[1] * 0.7152 + parts[2] * 0.0722;
          };
          const foreground = luminance(style.color),
            background = luminance(style.backgroundColor);
          return (
            (Math.max(foreground, background) + 0.05) /
            (Math.min(foreground, background) + 0.05)
          );
        });
      expect(contrast).toBeGreaterThanOrEqual(4.5);
      const dimensions = await page.evaluate(() => ({
        client: document.documentElement.clientWidth,
        scroll: document.documentElement.scrollWidth,
      }));
      expect(dimensions.scroll).toBeLessThanOrEqual(dimensions.client);
      expect(
        await page
          .locator("html")
          .evaluate((element) => getComputedStyle(element).scrollbarColor),
      ).not.toBe("auto");
      await page.locator("#evidence-guide").screenshot({
        path: testInfo.outputPath(`evidence-${theme}-${width}.png`),
      });
      await page
        .getByRole("searchbox", { name: "Search checks" })
        .fill("header");
      await page.locator("#check-details").screenshot({
        path: testInfo.outputPath(`catalogue-${theme}-${width}.png`),
      });
    }
  });
}
