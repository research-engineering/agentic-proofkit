import {relative, resolve, sep} from "node:path";
import {defineConfig, devices} from "@playwright/test";

const baseURL = process.env.PROOFKIT_BROWSER_TEST_URL;
if (!baseURL) throw new Error("PROOFKIT_BROWSER_TEST_URL is required");
const outputDir = process.env.PROOFKIT_BROWSER_TEST_OUTPUT_DIR;
if (!outputDir) throw new Error("PROOFKIT_BROWSER_TEST_OUTPUT_DIR is required");
const reportPath = process.env.PROOFKIT_BROWSER_TEST_REPORT_PATH;
if (!reportPath) throw new Error("PROOFKIT_BROWSER_TEST_REPORT_PATH is required");
// The two matrix families run as separate witness commands; each names its
// own test directory.
const family = process.env.PROOFKIT_BROWSER_MATRIX_FAMILY;
if (family !== "static" && family !== "workspace") throw new Error("PROOFKIT_BROWSER_MATRIX_FAMILY must be static or workspace");
const testDir = `tests/matrix/${family}`;
if (!relative(resolve(testDir), resolve(outputDir)).startsWith(`..${sep}`)) {
  throw new Error("matrix output directory must be outside the matrix test directory");
}

// The site-icon control is a Firefox-only test.
const firefoxOnly = ["firefox-site-icons.spec.mjs"];

export default defineConfig({
  outputDir,
  testDir,
  fullyParallel: true,
  forbidOnly: true,
  retries: 0,
  reporter: [["line"], ["json", {outputFile: reportPath}]],
  timeout: 60_000,
  workers: 2,
  use: {
    baseURL,
    screenshot: "off",
    trace: "retain-on-failure",
  },
  projects: [
    {name: "chromium", testIgnore: firefoxOnly, use: {...devices["Desktop Chrome"]}},
    {name: "firefox", use: {
      ...devices["Desktop Firefox"],
      launchOptions: {firefoxUserPrefs: {"browser.chrome.site_icons": false, "fission.webContentIsolationStrategy": 1}},
    }},
    {name: "webkit", testIgnore: firefoxOnly, use: {...devices["Desktop Safari"]}},
  ],
});
