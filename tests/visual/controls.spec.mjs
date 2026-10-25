import {expect} from "@playwright/test";

import {captureTwice, controlDigest, openView, referenceId, test} from "./visual-harness.mjs";

// Controls over a copied workspace stylesheet served in place of the original.
// The routed unchanged copy must keep the admitted digest, so routing alone
// cannot change the pixels; each mutated copy must then yield a canonical
// digest that differs from the admitted digest of the unmutated view. A
// mutation control fails when its mutation is not visible in the captured
// pixels, which also checks that the recorded font environment renders
// weight, family and monospace differences.
const view = "workspace-specifications";
const scheme = "light";
const width = 1440;

async function routeCopiedStylesheet(page, mutate) {
  await page.route("**/assets/workspace.css", async (route) => {
    const response = await route.fetch();
    const original = await response.text();
    const copy = mutate(original);
    if (copy === original) throw new Error("control copy did not change the copied stylesheet");
    await route.fulfill({response, body: copy});
  });
}

function replaceOnce(stylesheet, from, to) {
  const occurrences = stylesheet.split(from).length - 1;
  if (occurrences !== 1) throw new Error(`copied stylesheet must contain exactly one ${JSON.stringify(from)}`);
  return stylesheet.replace(from, to);
}

// Raises the blue channel of the light text color token by one unit.
function shiftTextColorByOneUnit(stylesheet) {
  const declarations = [...stylesheet.matchAll(/--text: #([0-9a-f]{6});/g)];
  if (declarations.length === 0) throw new Error("copied stylesheet has no text color token");
  const [declaration, hex] = declarations[0];
  const blue = Number.parseInt(hex.slice(4), 16);
  const shifted = hex.slice(0, 4) + (blue === 255 ? blue - 1 : blue + 1).toString(16).padStart(2, "0");
  return stylesheet.replace(declaration, `--text: #${shifted};`);
}

async function captureControl(page, visualServers, testInfo, browserName, name, copy) {
  await routeCopiedStylesheet(page, copy);
  await openView(page, visualServers, view, scheme, width);
  return controlDigest(testInfo, referenceId(browserName, view, scheme, width), name, await captureTwice(page, {fullPage: true}));
}

// The copy differs from the original only by a trailing comment.
test("a routed unchanged stylesheet keeps its reference", async ({page, browserName, visualServers}, testInfo) => {
  const {actual, admitted} = await captureControl(page, visualServers, testInfo, browserName, "routed-unchanged", (stylesheet) => `${stylesheet}\n/* routed unchanged copy */\n`);
  expect(actual, "routing an unchanged stylesheet copy must keep the admitted digest and dimensions").toEqual({height: admitted.height, rgbaSHA256: admitted.rgbaSHA256, width: admitted.width});
});

const controls = [
  ["a one-unit text color change differs from its reference", "text-color-one-unit", shiftTextColorByOneUnit],
  ["a one-pixel shift differs from its reference", "one-pixel-shift", (stylesheet) => `${stylesheet}\nhtml { padding-inline-start: 1px; }\n`],
  // Every element renders at weight 700, so the text at weight 400 becomes 700
  // and no relative weight such as bolder reaches a heavier synthesized face.
  ["a font-weight change from 400 to 700 differs from its reference", "font-weight-700", (stylesheet) => `${stylesheet}\n* { font-weight: 700 !important; }\n`],
  // The root family stack ends in sans-serif; the copy makes it serif.
  ["a change of the sans-serif family to serif differs from its reference", "serif-family", (stylesheet) => replaceOnce(stylesheet, "font-family: ui-sans-serif, system-ui, sans-serif;", "font-family: serif;")],
  // The requirement IDs use the monospace stack; the copy makes them sans-serif.
  ["a change of the monospace family to sans-serif differs from its reference", "monospace-family", (stylesheet) => replaceOnce(stylesheet, "font-family: ui-monospace, monospace;", "font-family: sans-serif;")],
];

for (const [title, name, mutate] of controls) {
  test(title, async ({page, browserName, visualServers}, testInfo) => {
    const {actual, admitted} = await captureControl(page, visualServers, testInfo, browserName, name, mutate);
    expect(actual.rgbaSHA256, `${name} control capture must differ from the admitted digest`).not.toBe(admitted.rgbaSHA256);
  });
}
