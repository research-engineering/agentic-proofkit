import {relative, resolve, sep} from "node:path";
import {defineConfig, devices} from "@playwright/test";

const baseURL = process.env.PROOFKIT_BROWSER_TEST_URL;
if (!baseURL) throw new Error("PROOFKIT_BROWSER_TEST_URL is required");
const outputDir = process.env.PROOFKIT_BROWSER_TEST_OUTPUT_DIR;
if (!outputDir) throw new Error("PROOFKIT_BROWSER_TEST_OUTPUT_DIR is required");
const reportPath = process.env.PROOFKIT_BROWSER_TEST_REPORT_PATH;
if (!reportPath) throw new Error("PROOFKIT_BROWSER_TEST_REPORT_PATH is required");
const testDir = "tests/visual";
// Actual captures go only to the run output directory, never into the tests.
if (!relative(resolve(testDir), resolve(outputDir)).startsWith(`..${sep}`)) {
  throw new Error("visual output directory must be outside the visual test directory");
}

// The README scene is a Chromium-only reference.
const chromiumOnly = ["readme-scene.spec.mjs"];

export default defineConfig({
  outputDir,
  testDir,
  fullyParallel: false,
  forbidOnly: true,
  retries: 0,
  reporter: [["line"], ["json", {outputFile: reportPath}]],
  timeout: 60_000,
  updateSnapshots: "none",
  workers: 1,
  use: {
    baseURL,
    screenshot: "off",
    trace: "off",
  },
  projects: [
    // Full tile raster makes repeated Chromium launches byte-identical.
    {name: "chromium", use: {...devices["Desktop Chrome"], launchOptions: {args: ["--disable-partial-raster"]}}},
    {name: "firefox", testIgnore: chromiumOnly, use: {
      ...devices["Desktop Firefox"],
      launchOptions: {firefoxUserPrefs: {"browser.chrome.site_icons": false, "fission.webContentIsolationStrategy": 1}},
    }},
    {name: "webkit", testIgnore: chromiumOnly, use: {...devices["Desktop Safari"]}},
  ],
});
