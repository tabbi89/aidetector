import { test, expect } from "./api-fixture";

// The app pages sit behind a session; the overview, CLI guide and coverage do
// not. The gate renders sign-in in a closed page's place, so nothing of that
// page (and none of its reads) appears first.

test("the overview, CLI guide and coverage stay public", async ({ page, api }) => {
  void api;
  await page.addInitScript(() => sessionStorage.removeItem("aidetector.api-key"));
  for (const path of ["/", "/cli", "/coverage"]) {
    await page.goto(path);
    await expect(page.getByRole("heading", { level: 1 })).toBeVisible();
    await expect(page.getByRole("heading", { name: "Sign in" })).toHaveCount(0);
  }
  const nav = page.getByRole("navigation", { name: "Primary" });
  await expect(nav.getByRole("link", { name: "Coverage" })).toBeVisible();
  await expect(nav.getByRole("link", { name: "Scans" })).toHaveCount(0);
  await expect(nav.getByRole("link", { name: "Monitoring" })).toHaveCount(0);
  await expect(page.getByRole("banner").getByRole("link", { name: "Sign in" })).toBeVisible();
  await expect(page.getByRole("banner").getByRole("link", { name: "runpentests." })).toHaveAttribute("href", "/");
});

test("a signed-out tab sees only sign-in, and signing in shows the page it asked for", async ({ page, api }) => {
  await page.addInitScript(() => sessionStorage.removeItem("aidetector.api-key"));
  await page.goto("/workspace");

  await expect(page.getByRole("heading", { name: "Sign in" })).toBeVisible();
  const nav = page.getByRole("navigation", { name: "Primary" });
  await expect(nav.getByRole("link", { name: "Scans" })).toHaveCount(0);

  await page.getByLabel("Email").fill("admin@example.test");
  await page.getByLabel("Password").fill("not it at all");
  await page.getByRole("button", { name: "Sign in", exact: true }).click();
  // Next's route announcer is an empty role=alert too; match ours by its text.
  await expect(
    page.getByRole("alert").filter({ hasText: "invalid email or password" }),
  ).toBeVisible();
  // A wrong password is an answer on the form; the form stays.
  await expect(page.getByRole("heading", { name: "Sign in" })).toBeVisible();

  await page.getByLabel("Password").fill("correct horse battery");
  await page.getByRole("button", { name: "Sign in", exact: true }).click();
  await expect(page).toHaveURL(/\/workspace$/);
  // Signed in, the header is the app: Scans, New scan, Monitoring — nothing else.
  await expect(nav.getByRole("link")).toHaveText(["Scans", "New scan", "Monitoring"]);
  await expect(page.getByRole("heading", { name: "Sign in" })).toHaveCount(0);
  expect(api.requests.some((r) => r.path === "/auth/login")).toBe(true);
});

test("an open server keeps pages closed and says how to create the admin", async ({ page, api }) => {
  api.openServer = true;
  await page.addInitScript(() => sessionStorage.removeItem("aidetector.api-key"));
  await page.goto("/scans");

  await expect(page.getByText("This server has no admin yet")).toBeVisible();
  await expect(page.getByText("make admin email=you@example.com")).toBeVisible();
  expect(api.requests.filter((r) => r.path === "/scans")).toHaveLength(0);
});

test("/login sends a signed-in tab on, but never off-site", async ({ page, api }) => {
  void api;
  await page.goto("/login?next=//evil.test/x");
  await expect(page).toHaveURL(/127\.0\.0\.1:3107\/scans$/);

  await page.goto("/login?next=/workspace");
  await expect(page).toHaveURL(/\/workspace$/);
});

test("a signed-in tab starts at the scans list, and the logo leads there", async ({ page, api }) => {
  void api;
  await page.goto("/");
  await expect(page).toHaveURL(/\/scans$/);
  await page.goto("/coverage");
  await page.getByRole("banner").getByRole("link", { name: "runpentests." }).click();
  await expect(page).toHaveURL(/\/scans$/);
});

test("signing out returns the tab to the sign-in form", async ({ page, api }) => {
  await page.goto("/scans");
  await page.getByRole("button", { name: /^Account: / }).click();
  await expect(page.getByText("admin@example.test")).toBeVisible();
  await page.getByRole("button", { name: "Sign out" }).click();

  await expect(page.getByRole("heading", { name: "Sign in" })).toBeVisible();
  expect(api.requests.some((r) => r.path === "/auth/logout")).toBe(true);
});

test("requesting access checks the password as it is typed and confirms the request", async ({ page, api }) => {
  await page.addInitScript(() => sessionStorage.removeItem("aidetector.api-key"));
  await page.goto("/login");

  await page.getByRole("button", { name: "Request access" }).click();
  await expect(page.getByRole("heading", { name: "Request access" })).toBeVisible();
  await expect(page.getByLabel("Full name")).toBeFocused();
  await page.getByLabel("Full name").fill("Dana Example");
  await page.getByLabel("Email").fill("dana@example.test");
  const password = page.getByLabel("Password");
  await password.fill("tiny5");
  await expect(page.locator(".auth-rule")).not.toHaveClass(/met/);
  await password.fill("long enough password");
  await expect(page.locator(".auth-rule")).toHaveClass(/met/);

  // The toggle shows what was typed, and hides it again.
  await page.getByRole("button", { name: "Show" }).click();
  await expect(password).toHaveAttribute("type", "text");
  await page.getByRole("button", { name: "Hide" }).click();
  await expect(password).toHaveAttribute("type", "password");

  await page.getByRole("button", { name: "Request access", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Request sent" })).toBeVisible();
  await expect(page.getByText("dana@example.test")).toBeVisible();
  expect(api.requests.find((r) => r.path === "/auth/signup")?.body).toEqual({
    email: "dana@example.test", display_name: "Dana Example", password: "long enough password",
  });

  await page.getByRole("button", { name: "Back to sign in" }).click();
  await expect(page.getByRole("heading", { name: "Sign in" })).toBeVisible();
  await expect(page.getByLabel("Email")).toHaveValue("dana@example.test");
});
