import {assertMatchesReference, captureTwice, openView, referenceId, schemes, test, viewNames, widths} from "./visual-harness.mjs";

// One exact digest comparison per view, color scheme and width in every engine.
for (const view of viewNames) {
  for (const scheme of schemes) {
    for (const width of widths) {
      test(`${view} ${scheme} ${width}`, async ({page, browserName, visualServers}, testInfo) => {
        await openView(page, visualServers, view, scheme, width);
        const captures = await captureTwice(page, {fullPage: true});
        assertMatchesReference(testInfo, referenceId(browserName, view, scheme, width), captures);
      });
    }
  }
}
