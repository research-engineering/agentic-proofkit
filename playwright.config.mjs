import {defineConfig, devices} from "@playwright/test";

const baseURL = process.env.PROOFKIT_BROWSER_TEST_URL;
if (!baseURL) throw new Error("PROOFKIT_BROWSER_TEST_URL is required");
const outputDir = process.env.PROOFKIT_BROWSER_TEST_OUTPUT_DIR;
if (!outputDir) throw new Error("PROOFKIT_BROWSER_TEST_OUTPUT_DIR is required");
const reportPath = process.env.PROOFKIT_BROWSER_TEST_REPORT_PATH;
if (!reportPath) throw new Error("PROOFKIT_BROWSER_TEST_REPORT_PATH is required");

export default defineConfig({
  outputDir,
  testDir: "tests/browser",
  fullyParallel: false,
  forbidOnly: true,
  retries: 0,
  reporter: [["line"], ["json", {outputFile: reportPath}]],
  timeout: 30_000,
  workers: 1,
  use: {
    baseURL,
    trace: "retain-on-failure",
  },
  projects: [
    {name: "chromium", use: {...devices["Desktop Chrome"]}},
    {name: "firefox", use: {...devices["Desktop Firefox"]}},
    {name: "webkit", use: {...devices["Desktop Safari"]}},
  ],
});
