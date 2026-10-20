import { expect, spec, test } from "./api-fixture";

/** Walk the wizard to its credentials step. */
async function toCredentials(page: import("@playwright/test").Page) {
  await page.goto("/scans/new");
  await page.getByLabel("Base URL", { exact: true }).fill("http://target.test");
  await page.getByRole("button", { name: "Create & continue" }).click();
  await page.getByLabel(/Spec contents/).fill(spec);
  await page.getByRole("button", { name: "Parse spec" }).click();
  await page.getByRole("button", { name: /Continue to credentials/ }).click();
}

const keyHints = {
  suggested: "single" as const,
  reason: "One key is enough.",
  operations: 1,
  protected_operations: 1,
  schemes: [{
    name: "key", kind: "apiKey" as const, auth_type: "api_key" as const,
    header_name: "X-Api-Token", grant_type: "static" as const, token_url: null,
    scopes: [], description: null,
  }],
  roles: [],
};

test("a single-key spec leads with one key, sent the way the spec says", async ({ page, api }) => {
  api.authHints = keyHints;
  await toCredentials(page);
  await expect(page.getByRole("tab", { name: "One API key" })).toHaveAttribute("aria-selected", "true");
  await expect(page.getByLabel("How is it sent?")).toHaveValue("api_key");
  await expect(page.getByLabel("Header name")).toHaveValue("X-Api-Token");
  await page.getByLabel("Token", { exact: true }).fill("fixture-key");
  await page.getByRole("button", { name: "Add credential", exact: true }).click();
  // One key is enough to scan; a second account is offered, not required.
  await expect(page.getByRole("button", { name: "Add a second account" })).toBeVisible();
  const body = api.requests.find(r => r.path.endsWith("/credentials"))?.body;
  expect(body).toMatchObject({
    name: "default", role: "user", auth_type: "api_key", header_name: "X-Api-Token",
    secret: "fixture-key",
  });
  // No refresh flow: the key is left out, since the API rejects an empty string.
  expect(body).not.toHaveProperty("refresh_secret");
});

test("a query-string key needs its parameter name", async ({ page, api }) => {
  api.authHints = keyHints;
  await toCredentials(page);
  await page.getByLabel("How is it sent?").selectOption("query");
  await page.getByLabel("Query parameter").fill("");
  await page.getByLabel("Token", { exact: true }).fill("fixture-key");
  await page.getByRole("button", { name: "Add credential", exact: true }).click();
  await expect(page.getByText("Query parameter is required.")).toBeVisible();
  expect(api.requests.some(r => r.path.endsWith("/credentials"))).toBe(false);
});

test("a public API needs no credentials", async ({ page, api }) => {
  api.authHints = { ...keyHints, suggested: "public", schemes: [], protected_operations: 0 };
  await toCredentials(page);
  await expect(page.getByRole("tab", { name: "Public" })).toHaveAttribute("aria-selected", "true");
  await expect(page.getByText(/the scan runs without signing in/)).toBeVisible();
  await expect(page.getByLabel("Token", { exact: true })).toHaveCount(0);
});

test("roles from the spec set the role and its privilege", async ({ page, api }) => {
  api.authHints = {
    ...keyHints, suggested: "roles",
    schemes: [{ ...keyHints.schemes[0], auth_type: "bearer", header_name: null }],
    roles: [{ name: "user", privilege: 1 }, { name: "admin", privilege: 3 }],
  };
  await toCredentials(page);
  await expect(page.getByRole("tab", { name: "Several roles" })).toHaveAttribute("aria-selected", "true");
  await page.getByLabel("Name", { exact: true }).fill("ops");
  await page.getByRole("button", { name: "admin (privilege 3)" }).click();
  await expect(page.getByLabel("Role", { exact: true })).toHaveValue("admin");
  await expect(page.getByLabel("Privilege")).toHaveValue("3");
  await page.getByLabel("Token", { exact: true }).fill("ops-token");
  await page.getByRole("button", { name: "Add credential", exact: true }).click();
  await expect(page.getByText("ops", { exact: true })).toBeVisible();
  expect(api.requests.find(r => r.path.endsWith("/credentials"))?.body).toMatchObject({
    name: "ops", role: "admin", privilege: 3, auth_type: "bearer",
  });
});

test("a tenant says which workspace an identity belongs to", async ({ page, api }) => {
  api.authHints = {
    ...keyHints, suggested: "roles",
    schemes: [{ ...keyHints.schemes[0], auth_type: "bearer", header_name: null }],
    roles: [],
  };
  await toCredentials(page);
  await page.getByLabel("Name", { exact: true }).fill("b-write");
  await page.getByLabel("Role", { exact: true }).fill("editor");
  await page.getByLabel(/^Tenant/).fill("workspace-b");
  await page.getByLabel("Token", { exact: true }).fill("b-token");
  await page.getByRole("button", { name: "Add credential", exact: true }).click();
  expect(api.requests.find(r => r.path.endsWith("/credentials"))?.body).toMatchObject({
    name: "b-write", role: "editor", tenant: "workspace-b",
  });
});
