import {
  cellTitle, closeDialogByEscape, judgeSecurityNow, modes, narrowModes, openWorkspaceDialog, openWorkspaceView, runOracles, schemes, test,
  workspaceDialogs, workspaceViews,
} from "../harness/matrix-harness.mjs";
import {unicodeSelectionOracle} from "../harness/unicode-selection.mjs";
import {expect} from "@playwright/test";
import {contentOracle} from "../harness/oracles.mjs";

// One cell per workspace tab, color scheme and mode in every engine, and one
// per open panel dialog and color scheme in each narrow mode.
for (const mode of modes) {
  test.describe(mode.id, () => {
    test.use({viewport: mode.viewport, deviceScaleFactor: mode.deviceScaleFactor});
    for (const view of workspaceViews) {
      for (const scheme of schemes) {
        test(cellTitle(view, scheme), async ({page, matrixServers, security}, testInfo) => {
          const records = await openWorkspaceView(page, matrixServers, view, scheme, mode);
          await runOracles(page, security, records, testInfo);
          // Oracle 5 runs last: it creates a handoff packet.
          if (view === "workspace-specifications") await unicodeSelectionOracle(page, mode, security);
        });
      }
    }
    if (!mode.narrow) return;
    for (const dialog of Object.keys(workspaceDialogs)) {
      for (const scheme of schemes) {
        test(cellTitle(dialog, scheme), async ({page, matrixServers, security}, testInfo) => {
          await openWorkspaceView(page, matrixServers, "workspace-specifications", scheme, mode);
          const records = await openWorkspaceDialog(page, dialog);
          await runOracles(page, security, records, testInfo);
          const heading = page.locator(`${workspaceDialogs[dialog].panel} h2`).first();
          try {
            await heading.evaluate(element => {element.style.height = "1px"; element.style.overflow = "hidden";});
            await expect(runOracles(page, security, records, testInfo)).rejects.toThrow("content: record text is lost");
          } finally {
            await heading.evaluate(element => {element.style.removeProperty("height"); element.style.removeProperty("overflow");});
          }
          await contentOracle(page, records.records, records.expectedRecords);
          try {
            await page.evaluate(() => {
              const overlay = document.createElement("div");
              overlay.id = "dialog-paint-control";
              Object.assign(overlay.style, {position: "fixed", inset: "0", background: "black", pointerEvents: "none"});
              document.body.append(overlay);
            });
            await contentOracle(page, records.records, records.expectedRecords);
            await page.locator(workspaceDialogs[dialog].panel).evaluate(element => element.append(document.querySelector("#dialog-paint-control")));
            await expect(contentOracle(page, records.records, records.expectedRecords)).rejects.toThrow("content: record text is lost");
          } finally {
            await page.locator("#dialog-paint-control").evaluate(element => element.remove());
          }
          await contentOracle(page, records.records, records.expectedRecords);
          await closeDialogByEscape(page, dialog);
          await judgeSecurityNow(page, security);
        });
      }
    }
  });
}

if (narrowModes.length !== 3) throw new Error("the dialog states run in exactly three narrow modes");
