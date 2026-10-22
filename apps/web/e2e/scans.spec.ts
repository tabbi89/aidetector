import { readFile } from "node:fs/promises";
import { test, expect, sid, spec, finding } from "./api-fixture";
import { SCOPE_GROUPS } from "../app/components/checkScope";

const payloadKeys = SCOPE_GROUPS.find((g) => g.id === "payloads")!.checks.map((c) => c.key);
// The default run is a Quick scan. The web names the level and the server
// expands it, so the panel never ticks schema fuzzing or premium itself;
// writes and AI stay explicit switches.
const flags = { mutate: /Test writes/, ai: /Use AI/ };

/**
 * Every run flag the client sends at its default — the mirror of
 * `NO_RUN_OPTIONS` in `apps/web/lib/api.ts`, which mirrors the API's RunRequest.
 * These assertions compare the whole body, so a flag added to the API belongs
 * here too; the API side is guarded by tests/test_coverage_mirror.py.
 */
const NO_PASSES = {
  level: "quick", ai: false,
  adjudicate: false, security_review: false, zap: false, kali: false,
  confirm: false, testssl: false, plan: false, genai_payloads: false, agent: false,
  adaptive: false, resource_refine: false, premium: false, fuzz: false, mutate: false,
};

test("wizard retains input after failure, forwards credentials and every opt-in", async ({ page, api }) => {
  api.failNext = "/scans";
  await page.goto("/scans/new");
  // `exact` keeps any other "… base URL" label out of the match.
  await page.getByLabel("Base URL", { exact: true }).fill("http://target.test");
  await page.getByRole("button", { name: "Create & continue" }).click();
  await expect(page.getByText("Temporary fixture failure")).toBeVisible();
  await expect(page.getByLabel("Base URL", { exact: true })).toHaveValue("http://target.test");
  await page.getByRole("button", { name: "Create & continue" }).click();
  await page.getByLabel(/Spec contents/).fill(spec);
  await page.getByRole("button", { name: "Parse spec" }).click();
  await page.getByRole("button", { name: /Continue to credentials/ }).click();
  await page.getByLabel("Name", { exact: true }).fill("alice");
  await page.getByLabel("Role", { exact: true }).fill("user");
  await page.getByLabel("Token", { exact: true }).fill("fixture-secret");
  await page.getByRole("button", { name: "Add credential", exact: true }).click();
  await expect(page.getByText("alice", { exact: true })).toBeVisible();
  await page.getByRole("button", { name: /Continue to run/ }).click();
  // The project-form handoff must name the deployment it was configured
  // against; a punned scan id is meaningless on another server.
  await page.getByRole("tab", { name: "Project file" }).click();
  await expect(
    page.getByText(/RUNPENTESTS_SERVER=http:\/\/api\.test RUNPENTESTS_API_KEY=<your-api-key>/),
  ).toBeVisible();
  const run = page.getByRole("button", { name: "Run scan", exact: true });
  await expect(run).toBeDisabled();
  await page.locator("summary", { hasText: "Advanced" }).click();
  await page.getByLabel("Requests per second").selectOption("2");
  await expect(page.getByRole("radio", { name: /Quick/ })).toBeChecked();
  await expect(page.getByRole("radio", { name: /Deep/ })).toBeEnabled();
  // Neither switch is pre-ticked.
  for (const label of Object.values(flags)) {
    await expect(page.getByRole("checkbox", { name: label })).not.toBeChecked();
  }
  await page.locator("summary", { hasText: "Customise checks" }).click();
  await expect(page.getByRole("radio", { name: /Full scan/ })).toBeChecked();
  // The scope radios are visually hidden inside their labels.
  await page
    .getByRole("radiogroup", { name: "Scan scope" })
    .getByText("Payload injection", { exact: true })
    .click();
  await expect(page.getByRole("radio", { name: /Payload injection/ })).toBeChecked();
  await page
    .getByRole("radiogroup", { name: "Scan level" })
    .getByText("Standard", { exact: true })
    .click();
  await expect(page.getByRole("radio", { name: /Standard/ })).toBeChecked();
  for (const label of Object.values(flags)) {
    await page.getByRole("checkbox", { name: label }).check();
  }
  await expect(run).toBeDisabled();
  await page.getByRole("checkbox", { name: /I own, or am explicitly authorized/ }).check();
  api.failNext = `/scans/${sid}/run`;
  await run.click();
  await expect(page.getByText("Temporary fixture failure")).toBeVisible();
  await expect(run).toBeEnabled();
  await run.click();
  await expect(page).toHaveURL(`/scans/${sid}`);
  expect(api.requests.filter(r => r.path.endsWith("/run")).at(-1)?.body).toEqual({
    authorized: true,
    ...NO_PASSES,
    level: "standard",
    mutate: true,
    ai: true,
    adaptive_attempts: 3,
    resource_attempts: 3,
    predefined_resource_ids: {},
    requests_per_second: 2,
    checks: payloadKeys,
  });
  expect(api.requests.find(r => r.path.endsWith("/credentials"))?.body).toMatchObject({
    name: "alice", role: "user", secret: "fixture-secret",
  });
});

test("detail run keeps authorization local and defaults to a quick scan", async ({ page, api }) => {
  await page.goto(`/scans/${sid}`);
  await page.getByRole("button", { name: /Run now/ }).click();
  const run = page.getByRole("button", { name: "Run scan", exact: true });
  await expect(run).toBeDisabled();
  await page.getByRole("checkbox", { name: /I own, or am explicitly authorized/ }).check();
  await page.getByRole("button", { name: "Close", exact: true }).click();
  await page.getByRole("button", { name: /Run now/ }).click();
  await expect(run).toBeDisabled();
  await page.getByRole("checkbox", { name: /I own, or am explicitly authorized/ }).check();
  await run.click();
  await expect(page.getByRole("button", { name: "Cancel scan" })).toBeVisible();
  expect(api.requests.find(r => r.path.endsWith("/run"))?.body).toEqual({
    authorized: true,
    ...NO_PASSES,
    adaptive_attempts: 3,
    resource_attempts: 3,
    predefined_resource_ids: {},
    requests_per_second: 10,
    checks: [],
  });
});

test("the run panel says a public target needs its domain verified first", async ({ page, api }) => {
  api.ownership = { host: "api.example.com", allowed: true, required: true, exempt: null,
    domain_id: null, verified_at: null, last_error: null, reason: null };
  await page.goto(`/scans/${sid}`);
  await page.getByRole("button", { name: /Run now/ }).click();
  const notice = page.getByRole("note").filter({ hasText: "Verify this domain before running" });
  await expect(notice).toContainText("api.example.com");
  await expect(notice.getByRole("link", { name: "Workspace → Domains" }))
    .toHaveAttribute("href", "/workspace?section=domains");

  api.ownership = { ...api.ownership, domain_id: "domain-1", verified_at: "2026-01-01T00:00:00Z" };
  // Verifying happens in another tab; returning to this one re-asks.
  await page.evaluate(() => window.dispatchEvent(new Event("focus")));
  await expect(page.getByRole("note").filter({ hasText: "Domain verified" })).toBeVisible();
  await expect(notice).toHaveCount(0);
});

test("a scope preset narrows the run and custom picks single checks", async ({ page, api }) => {
  await page.goto(`/scans/${sid}`);
  await page.getByRole("button", { name: /Run now/ }).click();
  // The default quick scan leaves the check customiser collapsed.
  await page.locator("summary", { hasText: "Customise checks" }).click();
  // The radio itself is visually hidden inside its label; clicking the label
  // is what a person does, and what the browser toggles.
  const scope = page.getByRole("radiogroup", { name: "Scan scope" });
  await scope.getByText("Headers & exposure", { exact: true }).click();
  await expect(page.getByRole("radio", { name: /Headers & exposure/ })).toBeChecked();
  await scope.getByText("Custom", { exact: true }).click();
  // Narrow the headers preset down to the header sweep alone.
  const picker = page.locator(".scope-picker");
  for (const name of [/Information disclosure/, /Sensitive fields/, /Secrets in responses/, /TLS certificate/, /Host-header/]) {
    await picker.getByRole("checkbox", { name }).uncheck();
  }
  await page.getByRole("checkbox", { name: /I own, or am explicitly authorized/ }).check();
  await page.getByRole("button", { name: "Run scan", exact: true }).click();
  await expect(page.getByRole("button", { name: "Cancel scan" })).toBeVisible();
  expect(api.requests.filter((r) => r.path.endsWith("/run")).at(-1)?.body).toMatchObject({
    checks: ["security_headers"],
    // Scope only narrows: the level and both switches stay at their defaults.
    level: "quick",
    mutate: false,
    ai: false,
  });
});

test("enabling a schedule asks for authorization and saves the selected passes", async ({ page, api }) => {
  await page.goto(`/scans/${sid}`);
  await page.getByRole("tab", { name: /Schedule/ }).click();
  const hourly = page.getByRole("button", { name: "hourly", exact: true });
  await expect(hourly).toBeDisabled();
  // The default is a Quick scan with writes and AI off.
  await expect(page.getByText(/engine scan/)).toBeVisible();
  await page.getByRole("checkbox", { name: /I own, or am explicitly authorized/ }).check();
  await hourly.click();
  await expect(page.getByRole("tab", { name: /Schedule/ })).toContainText("Hourly");
  expect(api.requests.filter((r) => r.path.endsWith("/schedule")).at(-1)?.body).toEqual({
    authorized: true,
    ...NO_PASSES,
    adaptive_attempts: 3,
    resource_attempts: 3,
    predefined_resource_ids: {},
    requests_per_second: 10,
    checks: [],
    minutes: 60,
  });

  // Stopping starts nothing, so it sends no authorization or options.
  await page.getByRole("button", { name: "Stop schedule" }).click();
  await expect(page.getByRole("tab", { name: /Schedule/ })).toContainText("Off");
  expect(api.requests.filter((r) => r.path.endsWith("/schedule")).at(-1)?.body).toEqual({
    minutes: null,
  });
  await expect(hourly).toBeDisabled();
});

test("an ended session shows sign-in in the page's place, and signing in shows the page", async ({ page, api }) => {
  api.requireKey = true;
  api.scan.status = "completed";
  const listCalls = () =>
    api.requests.filter((row) => row.method === "GET" && row.path === "/scans").length;

  await page.goto("/scans");
  // The tab's session is refused: the gate shows sign-in where the list would
  // be, and the list is never read with a session the server already refused.
  await expect(page.getByRole("heading", { name: "Sign in" })).toBeVisible();
  await expect(page.getByText("Your session ended")).toBeVisible();
  expect(listCalls()).toBe(0);

  await page.getByLabel("Email").fill("admin@example.test");
  await page.getByLabel("Password").fill("correct horse battery");
  await page.getByRole("button", { name: "Sign in", exact: true }).click();

  // Same URL, now the page itself.
  await expect(page).toHaveURL(/\/scans$/);
  await expect.poll(listCalls).toBeGreaterThan(0);
  await expect(page.getByText("http://target.test").first()).toBeVisible();
});

test("scan configuration saves the request rate", async ({ page, api }) => {
  await page.goto(`/scans/${sid}`);
  await page.getByRole("tab", { name: /Traffic/ }).click();
  await expect(page.getByRole("button", { name: "10 req/s" })).toHaveAttribute(
    "aria-pressed",
    "true",
  );
  await page.getByRole("button", { name: "2 req/s" }).click();
  await expect(page.getByRole("tab", { name: /Traffic/ })).toContainText("2 req/s");
  expect(api.requests.find((request) => request.path.endsWith("/request-rate"))?.body).toEqual({
    requests_per_second: 2,
  });
});

test("polling shows progress and cancellation recovers from API errors", async ({ page, api }) => {
  api.scan.status = "running";
  api.scan.progress = 10;
  await page.goto(`/scans/${sid}`);
  await expect(page.getByRole("progressbar")).toHaveAttribute("aria-valuenow", "10");
  api.scan.progress = 65;
  await expect(page.getByRole("progressbar")).toHaveAttribute("aria-valuenow", "65");
  api.failNext = `/scans/${sid}/cancel`;
  await page.getByRole("button", { name: "Cancel scan" }).click();
  const confirmation = page.getByRole("dialog", { name: "Cancel this scan?" });
  await expect(confirmation.getByRole("button", { name: "Keep scanning" })).toBeFocused();
  await confirmation.getByRole("button", { name: "Cancel scan" }).click();
  await expect(page.getByText("Temporary fixture failure")).toBeVisible();
  await expect(confirmation).toBeVisible();
  await confirmation.getByRole("button", { name: "Cancel scan" }).click();
  await expect(confirmation).not.toBeVisible();
  await expect(page.getByRole("button", { name: /Run now/ })).toBeVisible();
  await expect(page.getByRole("button", { name: "Cancel scan" })).toHaveCount(0);
});

test("pending cancellation survives polling and reload until the worker stops", async ({ page, api }) => {
  api.scan.status = "running";
  api.deferCancellation = true;
  // Other live regions (the findings summary's "Counting every finding…")
  // can be up at the same moment, so match the cancellation note by its text.
  const pending = page.getByRole("status").filter({ hasText: "Cancellation requested" });
  await page.goto(`/scans/${sid}`);
  await page.getByRole("button", { name: "Cancel scan" }).click();
  await page.getByRole("dialog").getByRole("button", { name: "Cancel scan" }).click();
  await expect(page.getByRole("button", { name: "Cancelling…" })).toBeDisabled();
  await expect(pending).toBeVisible();
  await page.reload();
  await expect(page.getByRole("button", { name: "Cancelling…" })).toBeDisabled();
  await expect(pending).toBeVisible();
  api.scan.status = "cancelled";
  await expect(page.getByRole("button", { name: /Run now/ })).toBeVisible();
  await expect(pending).toHaveCount(0);
});

test("completed findings export downloads readable JSON", async ({ page, api }) => {
  api.scan.status = "completed";
  api.scan.progress = 100;
  api.findings = [finding];
  await page.goto(`/scans/${sid}`);
  await expect(page.getByText(finding.title, { exact: true })).toBeVisible();
  const downloaded = page.waitForEvent("download");
  await page.locator(".statline").getByRole("button", { name: /Export/ }).click();
  await page.getByRole("menuitem", { name: "JSON", exact: true }).click();
  const download = await downloaded;
  expect(download.suggestedFilename()).toBe("scan.json");
  expect(JSON.parse(await readFile((await download.path())!, "utf8"))).toEqual({ findings: [finding] });
});

test("a verified domain asks for authorization on the Run button itself", async ({ page, api }) => {
  api.ownership = { host: "target.test", allowed: true, required: true, exempt: null,
    domain_id: "domain-1", verified_at: "2026-01-01T00:00:00Z", last_error: null, reason: null };
  await page.goto(`/scans/${sid}`);
  await page.getByRole("button", { name: /Run now/ }).click();
  await expect(page.getByRole("checkbox", { name: /I own, or am explicitly authorized/ })).toHaveCount(0);
  await page.getByRole("button", { name: "I'm authorized — run scan on target.test", exact: true }).click();
  await expect(page.getByRole("button", { name: "Cancel scan" })).toBeVisible();
  expect(api.requests.filter((r) => r.path.endsWith("/run")).at(-1)?.body).toMatchObject({ authorized: true });
});

test("each bare {id} resource gets its own predefined-ID box", async ({ page, api }) => {
  const item = (id: string, path: string) => ({
    id, method: "GET", path, auth_scope: null, enabled: true,
    params: [{ name: "id", in: "path", required: true }],
  });
  api.scan.operations = [
    item("op-monitor", "/monitors/{id}"),
    item("op-incident", "/incidents/{id}/acknowledge"),
  ];
  await page.goto(`/scans/${sid}`);
  await page.getByRole("button", { name: "Add IDs for 2 path parameters" }).click();
  const editor = page.getByLabel("Predefined resource IDs for spec path parameters");
  expect(JSON.parse(await editor.inputValue())).toEqual({ incident_id: "", monitor_id: "" });
  await editor.fill(JSON.stringify({ incident_id: "inc-9", monitor_id: "mon-1" }));
  await expect(page.locator(".field-error")).toHaveCount(0);
  // The pre-per-resource bare key is still accepted.
  await editor.fill(JSON.stringify({ id: "legacy" }));
  await expect(page.locator(".field-error")).toHaveCount(0);
  await editor.fill(JSON.stringify({ incident_id: "inc-9", monitor_id: "mon-1" }));
  await page.getByRole("button", { name: /Run now/ }).click();
  await page.getByRole("checkbox", { name: /I own, or am explicitly authorized/ }).check();
  await page.getByRole("button", { name: "Run scan", exact: true }).click();
  await expect(page.getByRole("button", { name: "Cancel scan" })).toBeVisible();
  expect(api.requests.find((r) => r.path.endsWith("/run"))?.body).toMatchObject({
    predefined_resource_ids: { incident_id: "inc-9", monitor_id: "mon-1" },
  });
});
