import {stdout} from "node:process";

import {captureInventory} from "../tests/visual/capture-inventory.mjs";
import {runDiagnosticEntrypoint} from "./diagnostic.mjs";
import {stableJSONStringify} from "./stable-json.mjs";

// Prints the canonical digest and dimensions of every capture below one
// capture directory, recomputed from the PNG files. Reference admission calls
// it; the visual gate never does.
await runDiagnosticEntrypoint(async () => {
  const [directory] = process.argv.slice(2);
  if (typeof directory !== "string" || directory === "" || process.argv.length !== 3) {
    throw new Error("usage: browser-visual-capture-digests.mjs CAPTURE_DIRECTORY");
  }
  stdout.write(`${stableJSONStringify(captureInventory(directory))}\n`);
});
