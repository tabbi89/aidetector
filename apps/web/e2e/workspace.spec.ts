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

test("member removal keeps API failures in the confirmation and refreshes after retry", async ({ page, api }) => {
  void api;
  const member = { user_id: "member-1", email: "dana@example.test", display_name: "Dana", role: "viewer", created_at: "2026-01-01T00:00:00Z" };
  let removed = false, attempts = 0;
  await page.route("http://api.test/workspace/members", (route) => route.fulfill({ json: removed ? [] : [member] }));
  await page.route("http://api.test/workspace/members/member-1", (route) => {
    attempts += 1;
    if (attempts === 1) return route.fulfill({ status: 503, json: { detail: "Try removing this member again." } });
    removed = true;
    return route.fulfill({ json: { status: "removed" } });
  });
  await page.goto("/workspace?section=members");
  await page.getByRole("button", { name: "Remove Dana", exact: true }).click();
  const dialog = page.getByRole("dialog", { name: "Remove workspace member?" });
  await expect(dialog).toContainText("Dana");
  await dialog.getByRole("button", { name: "Remove member", exact: true }).click();
  await expect(dialog.getByRole("alert")).toContainText("Try removing this member again.");
  await dialog.getByRole("button", { name: "Remove member", exact: true }).click();
  await expect(dialog).not.toBeVisible();
  await expect(page.getByRole("button", { name: "Remove Dana", exact: true })).toHaveCount(0);
  await expect(page.getByRole("status").filter({ hasText: "Dana removed." })).toBeVisible();
  expect(attempts).toBe(2);
});
