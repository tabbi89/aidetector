import { test, expect, sid, spec } from "./api-fixture";

test("CLI handoffs copy the configured server without embedding secrets", async ({ page, api }) => {
  void api;
  const server = "http://api.test";
  // The tab's own session token: a hand-off names a placeholder, never this.
  const sessionSecret = "fixture-session";
  const targetSecret = "target-secret-never-export";

  // Capture clipboard writes in the browser without OS clipboard permissions.
  await page.addInitScript(() => {
    Object.defineProperty(navigator, "clipboard", {
      configurable: true,
      value: {
        writeText: async (value: string) => {
          document.documentElement.dataset.copied = value;
        },
      },
    });
  });
  await page.goto("/scans/new");
  await page.getByLabel("Base URL", { exact: true }).fill("http://target.test");
  await page.getByRole("button", { name: "Create & continue" }).click();
  await page.getByLabel(/Spec contents/).fill(spec);
  await page.getByRole("button", { name: "Parse spec" }).click();
  await page.getByRole("button", { name: /Continue to credentials/ }).click();
  await page.getByLabel("Name", { exact: true }).fill("alice");
  await page.getByLabel("Role", { exact: true }).fill("user");
  await page.getByLabel("Token", { exact: true }).fill(targetSecret);
  await page.getByRole("button", { name: "Add credential", exact: true }).click();
  await expect(page.getByText("alice", { exact: true })).toBeVisible();
  await page.getByRole("button", { name: /Continue to run/ }).click();

  const handoff = page.locator(".cli-handoff");
  const prefix = `AIDETECTOR_SERVER=${server} AIDETECTOR_API_KEY=<your-api-key> `;
  const runCommand = `${prefix}aidetector run ${sid} --authorized --fail-on high --verified-only`;
  await expect(handoff.locator("pre")).toHaveText(runCommand);
  await handoff.getByRole("button", { name: /^Copy run command/ }).click();
  await expect(page.locator("html")).toHaveAttribute("data-copied", runCommand);

  await handoff.getByRole("tab", { name: "Project file" }).click();
  const projectCommand = `${prefix}aidetector http://target.test --config ./aidetector.yml --authorized`;
  await expect(handoff.locator("pre").last()).toHaveText(projectCommand);
  await handoff.getByRole("button", { name: /^Copy project command/ }).click();
  await expect(page.locator("html")).toHaveAttribute("data-copied", projectCommand);
  await handoff.getByRole("button", { name: /^Copy project file/ }).click();
  const projectFile = await handoff.locator("pre").first().innerText();
  await expect(page.locator("html")).toHaveAttribute("data-copied", projectFile);
  expect(projectFile).toContain(`scan: ${sid}`);
  expect(projectFile).toContain("secret_env: USER_SECRET");

  for (const value of [runCommand, projectCommand, projectFile, await handoff.innerText()]) {
    expect(value).not.toContain(sessionSecret);
    expect(value).not.toContain(targetSecret);
  }
});
