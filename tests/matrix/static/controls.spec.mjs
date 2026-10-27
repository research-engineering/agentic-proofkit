import {modes, openStaticView, test} from "../harness/matrix-harness.mjs";
import {oracleControls} from "../harness/controls.mjs";

// The oracle controls on the static source view in Cards mode, light, 1440.
const mode = modes.find((candidate) => candidate.id === "1440");
test.use({viewport: mode.viewport, deviceScaleFactor: mode.deviceScaleFactor});

const controls = oracleControls({
  open: (page, servers) => openStaticView(page, servers, "static-source-cards", "light", mode),
  container: "main",
  // The static CSP has no img-src, so a page-initiated /favicon.ico load is
  // refused; in Firefox this is the load that site icons would otherwise make.
  blockedLoad: {source: "/favicon.ico", matches: (uri) => new URL(uri).pathname === "/favicon.ico"},
});
for (const [title, body] of controls) test(title, body);
