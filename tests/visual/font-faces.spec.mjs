import {expect} from "@playwright/test";

import {openView, test} from "./visual-harness.mjs";

// Every product font stack must draw its intended face in every engine. The
// stacks are read from the rendered workspace and static views, so a stack
// change in either style owner is checked. Each stack is then drawn in a probe
// page beside the named Liberation faces, in regular and bold, and identified
// by exact pixel equality. A monospace stack must also advance i and M
// equally, and a sans-serif stack must not.
const stacks = Object.freeze([
  {name: "workspace root", view: "workspace-specifications", selector: ":root", face: "Liberation Sans", monospaced: false},
  {name: "workspace requirement ID", view: "workspace-specifications", selector: "article h3", face: "Liberation Mono", monospaced: true},
  {name: "static root", view: "static-source-cards", selector: ":root", face: "Liberation Sans", monospaced: false},
  {name: "static code", view: "static-source-cards", selector: "code", face: "Liberation Mono", monospaced: true},
  {name: "static record ID", view: "static-source-cards", selector: ".proofkit-id", face: "Liberation Mono", monospaced: true},
]);
const faces = Object.freeze(["Liberation Sans", "Liberation Serif", "Liberation Mono"]);
const weights = Object.freeze([400, 700]);
const text = "REQ-BROWSER-001 iiii MMMM Wq";

// readStacks returns each stack's computed font-family in its rendered view.
async function readStacks(page, visualServers) {
  const rendered = [];
  for (const view of [...new Set(stacks.map((stack) => stack.view))]) {
    await openView(page, visualServers, view, "light", 1440);
    for (const stack of stacks.filter((candidate) => candidate.view === view)) {
      const family = await page.evaluate((selector) => {
        const element = document.querySelector(selector);
        return element === null ? null : getComputedStyle(element).fontFamily;
      }, stack.selector);
      expect(family, `${stack.name} (${stack.selector}) must be rendered in ${view}`).not.toBeNull();
      rendered.push({...stack, family});
    }
  }
  return rendered;
}

test("each product font stack draws its intended face", async ({page, visualServers}) => {
  const rendered = await readStacks(page, visualServers);
  const samples = [
    ...faces.map((face) => ({label: face, family: JSON.stringify(face)})),
    ...rendered.map((stack) => ({label: `${stack.name} (${stack.family})`, family: stack.family})),
  ];
  const probe = await page.context().newPage();
  try {
    await probe.setViewportSize({width: 1000, height: 1200});
    await probe.setContent("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"></head><body style=\"margin:0;background:#fff;color:#000\"></body></html>");
    await probe.evaluate(({samples, weights, text}) => {
      samples.forEach(({family}, index) => {
        for (const weight of weights) {
          const box = document.createElement("div");
          box.dataset.sample = `${index}-${weight}`;
          Object.assign(box.style, {width: "900px", height: "40px", overflow: "hidden", fontSize: "24px", lineHeight: "40px", whiteSpace: "pre", fontFamily: family, fontWeight: String(weight)});
          box.textContent = text;
          document.body.append(box);
        }
        for (const glyphs of ["iiiiiiiiii", "MMMMMMMMMM"]) {
          const span = document.createElement("span");
          span.dataset.advance = `${index}-${glyphs[0]}`;
          Object.assign(span.style, {fontSize: "40px", whiteSpace: "pre", fontFamily: family});
          span.textContent = glyphs;
          document.body.append(span);
        }
      });
    }, {samples, weights, text});
    const advances = await probe.evaluate(async () => {
      await document.fonts.ready;
      await new Promise((resolveFrame) => requestAnimationFrame(() => requestAnimationFrame(resolveFrame)));
      return Object.fromEntries([...document.querySelectorAll("[data-advance]")].map((span) => [span.dataset.advance, span.getBoundingClientRect().width]));
    });
    const capture = (index, weight) => probe.locator(`[data-sample="${index}-${weight}"]`).screenshot({animations: "disabled", caret: "hide", scale: "css"});
    const findings = [];
    // The named faces must be installed and distinguishable, regular and bold.
    const faceCaptures = new Map();
    for (const weight of weights) {
      for (const [index, face] of faces.entries()) faceCaptures.set(`${face} ${weight}`, await capture(index, weight));
    }
    const captures = [...faceCaptures.entries()];
    for (const [left, leftBytes] of captures) {
      for (const [right, rightBytes] of captures) {
        if (left < right && leftBytes.equals(rightBytes)) findings.push(`${left} and ${right} draw identically`);
      }
    }
    for (const [offset, stack] of rendered.entries()) {
      const index = faces.length + offset;
      for (const weight of weights) {
        const bytes = await capture(index, weight);
        const drawn = faces.filter((face) => faceCaptures.get(`${face} ${weight}`).equals(bytes));
        if (drawn.length !== 1 || drawn[0] !== stack.face) {
          findings.push(`${samples[index].label} at weight ${weight} draws ${drawn.length === 0 ? "no named face" : drawn.join(" and ")}, not ${stack.face}`);
        }
      }
      const monospaced = advances[`${index}-i`] === advances[`${index}-M`];
      if (monospaced !== stack.monospaced) {
        findings.push(`${samples[index].label} is ${monospaced ? "monospaced" : "proportional"}, not ${stack.monospaced ? "monospaced" : "proportional"}`);
      }
    }
    expect(findings, "every product font stack must draw its intended face").toEqual([]);
  } finally {
    await probe.close();
  }
});
