import {cellTitle, modes, openStaticView, runOracles, schemes, staticViews, test} from "../harness/matrix-harness.mjs";

// One cell per static view, color scheme and mode in every engine.
for (const mode of modes) {
  test.describe(mode.id, () => {
    test.use({viewport: mode.viewport, deviceScaleFactor: mode.deviceScaleFactor});
    for (const view of staticViews) {
      for (const scheme of schemes) {
        test(cellTitle(view, scheme), async ({page, matrixServers, security}, testInfo) => {
          const records = await openStaticView(page, matrixServers, view, scheme, mode);
          await runOracles(page, security, records, testInfo);
        });
      }
    }
  });
}
