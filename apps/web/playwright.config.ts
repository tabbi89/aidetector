import { defineConfig, devices } from "@playwright/test";

export default defineConfig({
  testDir: "./e2e",
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: 0,
  timeout: 30_000,
  use: {
    baseURL: "http://127.0.0.1:3107",
    trace: "retain-on-failure",
    serviceWorkers: "block",
    // Playwright's bundled browsers are not installed on every machine; the
    // installed Google Chrome can be used instead by naming it here.
    launchOptions: process.env.PLAYWRIGHT_CHROME
      ? { executablePath: process.env.PLAYWRIGHT_CHROME }
      : {},
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
  webServer: {
    // `exec` matters: without it Playwright kills the shell and leaves the
    // next-server child holding port 3107, so the next run cannot start.
    command:
      "npm run build && exec npx next start --hostname 127.0.0.1 --port 3107",
    url: "http://127.0.0.1:3107",
    reuseExistingServer: false,
    timeout: 120_000,
    // A Next server that ignores SIGTERM would otherwise hold the port and
    // leave the run hanging after the last test.
    gracefulShutdown: { signal: "SIGTERM", timeout: 5000 },
    env: { NEXT_PUBLIC_API_URL: "http://api.test", NEXT_DIST_DIR: ".next-e2e" },
  },
});
