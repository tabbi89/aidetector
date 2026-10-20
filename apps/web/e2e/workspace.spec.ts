import { test, expect } from "./api-fixture";

// Workspace settings: one section at a time from a labelled side navigation,
// deep-linkable, keyboard-reachable, with empty states that name the next step.

// Every test takes `api`: the fixture is lazy, and without it nothing is mocked.
test("workspace sections deep-link, announce themselves and keep one main landmark", async ({ page, api }) => {
  void api;
  await page.goto("/workspace?section=limits");
  const nav = page.getByRole("navigation", { name: "Workspace settings" });
  await expect(page.getByRole("heading", { level: 1, name: "Spending & run limits" })).toBeVisible();
  await expect(nav.getByRole("link", { name: "Spending & limits" })).toHaveAttribute("aria-current", "page");
  // Every limit field is labelled and described.
  await expect(page.getByLabel("Monthly budget (USD)")).toHaveAttribute("aria-describedby", "limit-monthly-help");
  await expect(page.locator("main")).toHaveCount(1);

  await nav.getByRole("link", { name: "Notifications" }).click();
  await expect(page).toHaveURL(/section=notifications/);
  const heading = page.getByRole("heading", { level: 1, name: "Notifications" });
  await expect(heading).toBeFocused();
  await expect(page.getByText("No endpoints yet")).toBeVisible();
});

test("a token needs a member, and the page says so instead of a dead button", async ({ page, api }) => {
  void api;
  await page.goto("/workspace?section=tokens");
  await expect(page.getByText("A token belongs to a member, and this workspace has none yet.")).toBeVisible();
  await expect(page.getByRole("button", { name: "Create token" })).toHaveCount(0);
  await page.getByRole("link", { name: "Go to Members" }).click();
  await expect(page.getByRole("heading", { level: 1, name: "Members" })).toBeVisible();
});

test("adding a member focuses the form and sends what was typed", async ({ page, api }) => {
  await page.goto("/workspace?section=members");
  await page.getByRole("button", { name: "Add member" }).first().click();
  await expect(page.getByLabel("Email")).toBeFocused();
  await page.getByLabel("Email").fill("dana@example.test");
  await page.getByLabel("Display name").fill("Dana");
  await page.getByRole("combobox", { name: "Role", exact: true }).selectOption("viewer");
  await page.getByRole("button", { name: "Add member" }).last().click();
  await expect(page.getByRole("status").filter({ hasText: "Member added." })).toBeVisible();
  expect(api.requests.find((r) => r.method === "POST" && r.path === "/workspace/members")?.body).toEqual({
    email: "dana@example.test",
    display_name: "Dana",
    role: "viewer",
  });
});

test("on a phone the primary links fold into a menu and mark the current section", async ({ page, api }) => {
  void api;
  await page.setViewportSize({ width: 375, height: 812 });
  await page.goto("/monitoring");
  const primary = page.getByRole("navigation", { name: "Primary" });
  await expect(primary.getByRole("link", { name: "Scans" })).toBeHidden();
  const menu = primary.getByRole("button", { name: "Menu" });
  await menu.click();
  await expect(menu).toHaveAttribute("aria-expanded", "true");
  await expect(primary.getByRole("link", { name: "Monitoring" })).toHaveAttribute("aria-current", "page");
  await page.keyboard.press("Escape");
  await expect(menu).toHaveAttribute("aria-expanded", "false");
  await expect(menu).toBeFocused();
  expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(375);
});
