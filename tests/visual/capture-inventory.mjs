import {lstatSync, readdirSync} from "node:fs";
import {join} from "node:path";

import {canonicalRGBADigest, decodePNG} from "./exact-png.mjs";
import {readBrowserProofFile} from "../../scripts/browser-proof-inputs.mjs";

// captureInventory decodes every PNG capture below a capture directory and
// returns its entries sorted by ID (<engine>/<view>.<scheme>.<width>). Any
// file that is not a regular PNG capture is refused.
export function captureInventory(directory) {
  const entries = [];
  const walk = (relative) => {
    for (const entry of readdirSync(join(directory, relative), {withFileTypes: true})) {
      const path = relative === "" ? entry.name : `${relative}/${entry.name}`;
      const metadata = lstatSync(join(directory, path));
      if (metadata.isSymbolicLink()) throw new Error("capture directory must not contain symlinks");
      if (metadata.isDirectory()) {
        walk(path);
        continue;
      }
      if (!metadata.isFile() || !path.endsWith(".png")) throw new Error("capture directory may contain only PNG captures");
      const image = decodePNG(readBrowserProofFile(join(directory, path)).content);
      entries.push({height: image.height, id: path.slice(0, -".png".length), rgbaSHA256: canonicalRGBADigest(image), width: image.width});
    }
  };
  walk("");
  return entries.sort((left, right) => (left.id < right.id ? -1 : left.id > right.id ? 1 : 0));
}
