import {modes, openWorkspaceView, test} from "../harness/matrix-harness.mjs";
import {oracleControls} from "../harness/controls.mjs";

// The oracle controls on the workspace Specifications tab, light, 1440.
const mode = modes.find((candidate) => candidate.id === "1440");
test.use({viewport: mode.viewport, deviceScaleFactor: mode.deviceScaleFactor});

const controls = oracleControls({
  open: (page, servers) => openWorkspaceView(page, servers, "workspace-specifications", "light", mode),
  container: "#workspace-content",
  // The workspace CSP admits only same-origin images, so a data: image is refused.
  blockedLoad: {source: "data:image/gif;base64,R0lGODlhAQABAAAAACw=", matches: (uri) => uri === "data"},
});
for (const [title, body] of controls) test(title, body);
