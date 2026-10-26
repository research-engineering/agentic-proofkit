import {
  cellTitle, closeDialogByEscape, judgeSecurityNow, modes, narrowModes, openWorkspaceDialog, openWorkspaceView, runOracles, schemes, test,
  workspaceDialogs, workspaceViews,
} from "../harness/matrix-harness.mjs";
import {unicodeSelectionOracle} from "../harness/unicode-selection.mjs";

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
          await openWorkspaceDialog(page, dialog);
          await runOracles(page, security, {records: null}, testInfo);
          await closeDialogByEscape(page, dialog);
          await judgeSecurityNow(page, security);
        });
      }
    }
  });
}

if (narrowModes.length !== 3) throw new Error("the dialog states run in exactly three narrow modes");
