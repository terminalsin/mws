import { defineConfig, devices } from "@playwright/test";

// End-to-end tests of the whole console: the shell and every zone, built for
// production and served by scripts/zones.mjs, against a running MWS (start it
// with `cargo run -p mws`, or point MWS_ENDPOINT elsewhere).
const baseURL = process.env.MWS_DASHBOARD_URL ?? "http://127.0.0.1:3000";

export default defineConfig({
  testDir: "e2e",
  timeout: 60_000,
  expect: { timeout: 15_000 },
  fullyParallel: false,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? [["list"], ["html", { open: "never" }]] : "list",
  use: {
    baseURL,
    trace: "off",
    ...(process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE ? { launchOptions: { executablePath: process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE } } : {}),
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
  webServer: process.env.MWS_DASHBOARD_URL
    ? undefined
    : {
        command: "node scripts/zones.mjs start",
        url: `${baseURL}/control`,
        reuseExistingServer: !process.env.CI,
        timeout: 120_000,
        stdout: "pipe",
      },
});
