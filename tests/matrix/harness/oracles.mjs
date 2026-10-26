import axeMin from "axe-core/axe.min.js";
import {expect} from "@playwright/test";

// The oracles of one accessibility-matrix cell. Each oracle observes the page
// and hands its observation to a pure judgement; the negative controls feed
// those judgements, or the oracles themselves, a page or an observation that
// must be refused, so every judgement has a control that fails it.

export const axeSource = axeMin.source;
export const axeVersion = axeMin.version;
const axeConfigureOptions = Object.freeze({allowedOrigins: ["<same_origin>"], branding: {application: "playwright"}});
const axeRunOptions = Object.freeze({rules: {"target-size": {enabled: true}}});

export class OracleFailure extends Error {
  constructor(oracle, message, evidence) {
    super(`${oracle}: ${message}${evidence === undefined ? "" : `\n${JSON.stringify(evidence, null, 2)}`}`);
    this.oracle = oracle;
  }
}

// ---------------------------------------------------------------------------
// Shared in-page helpers. Each is installed by source text into the page,
// because evaluated functions cannot close over module scope.

const pageHelpers = String.raw`
const proofkitMatrix = (() => {
  const parse = (value) => {
    if (value === "transparent") return [0, 0, 0, 0];
    // Pinned Firefox serializes some UA colors, such as its default
    // placeholder color, in the color(srgb ...) form.
    const srgb = value.match(/^color\(srgb\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)(?:\s*\/\s*([\d.]+%?))?\s*\)$/);
    if (srgb) {
      const alpha = srgb[4] === undefined ? 1 : srgb[4].endsWith("%") ? Number(srgb[4].slice(0, -1)) / 100 : Number(srgb[4]);
      return [Number(srgb[1]) * 255, Number(srgb[2]) * 255, Number(srgb[3]) * 255, alpha];
    }
    const match = value.match(/^rgba?\(\s*([\d.]+)[,\s]+([\d.]+)[,\s]+([\d.]+)(?:\s*[,/]\s*([\d.]+%?))?\s*\)$/);
    if (!match) throw new Error("unsupported computed color " + value);
    let alpha = match[4] === undefined ? 1 : match[4].endsWith("%") ? Number(match[4].slice(0, -1)) / 100 : Number(match[4]);
    return [Number(match[1]), Number(match[2]), Number(match[3]), alpha];
  };
  const composite = (top, bottom) => {
    const alpha = top[3] + bottom[3] * (1 - top[3]);
    if (alpha === 0) return [0, 0, 0, 0];
    return [0, 1, 2].map((index) => (top[index] * top[3] + bottom[index] * bottom[3] * (1 - top[3])) / alpha).concat(alpha);
  };
  const luminance = (color) => {
    const channels = color.slice(0, 3).map((value) => {
      const normalized = value / 255;
      return normalized <= 0.04045 ? normalized / 12.92 : ((normalized + 0.055) / 1.055) ** 2.4;
    });
    return channels[0] * 0.2126 + channels[1] * 0.7152 + channels[2] * 0.0722;
  };
  const ratio = (left, right) => {
    const first = luminance(left);
    const second = luminance(right);
    return (Math.max(first, second) + 0.05) / (Math.min(first, second) + 0.05);
  };
  // The canvas behind the root is the root background, else white.
  const undecidable = (element) => {
    for (let current = element; current instanceof Element; current = current.parentElement) {
      const style = getComputedStyle(current);
      if (Number(style.opacity) !== 1) return "group opacity on " + current.tagName;
      if (style.backgroundImage !== "none") return "background image on " + current.tagName;
      if (style.filter !== "none" || style.mixBlendMode !== "normal" || (style.backdropFilter ?? "none") !== "none") return "filter or blend mode on " + current.tagName;
    }
    return null;
  };
  const backgroundOf = (element) => {
    const chain = [];
    for (let current = element; current instanceof Element; current = current.parentElement) chain.push(current);
    let color = [255, 255, 255, 1];
    for (const current of chain.reverse()) {
      const style = getComputedStyle(current);
      const layer = parse(style.backgroundColor);
      layer[3] *= Number(style.opacity);
      color = composite(layer, color);
    }
    return color;
  };
  const opacityOf = (element) => {
    let opacity = 1;
    for (let current = element; current instanceof Element; current = current.parentElement) opacity *= Number(getComputedStyle(current).opacity);
    return opacity;
  };
  const paints = (element) => {
    const style = getComputedStyle(element);
    return style.visibility === "visible" && opacityOf(element) > 0
      && (parse(style.backgroundColor)[3] > 0 || style.backgroundImage !== "none"
        || element.matches("img, canvas, video, iframe, object, embed"));
  };
  // An outline does not participate in hit-testing. Its side midpoints must
  // escape clipping and unrelated paint, not hit the focused element itself.
  const outlineVisible = (element, style) => {
    const width = Number.parseFloat(style.outlineWidth);
    const offset = Number.parseFloat(style.outlineOffset);
    if (!(width > 0) || !(offset >= 0)) return {visible: false, reason: "outline geometry"};
    const box = element.getBoundingClientRect();
    const bounds = {left: 0, top: 0, right: document.documentElement.clientWidth, bottom: document.documentElement.clientHeight};
    for (let ancestor = element.parentElement; ancestor instanceof Element; ancestor = ancestor.parentElement) {
      const outer = getComputedStyle(ancestor);
      if (outer.clipPath !== "none" || Number(outer.opacity) !== 1) return {visible: false, reason: "unsupported ancestor paint"};
      const clip = ancestor.getBoundingClientRect();
      const left = clip.left + ancestor.clientLeft;
      const top = clip.top + ancestor.clientTop;
      if (outer.overflowX !== "visible") {
        bounds.left = Math.max(bounds.left, left);
        bounds.right = Math.min(bounds.right, left + ancestor.clientWidth);
      }
      if (outer.overflowY !== "visible") {
        bounds.top = Math.max(bounds.top, top);
        bounds.bottom = Math.min(bounds.bottom, top + ancestor.clientHeight);
      }
    }
    const middle = offset + width / 2;
    const points = [[box.left - middle, box.top + box.height / 2], [box.right + middle, box.top + box.height / 2],
      [box.left + box.width / 2, box.top - middle], [box.left + box.width / 2, box.bottom + middle]];
    const unclipped = points.filter(([x, y]) => x >= bounds.left && x < bounds.right && y >= bounds.top && y < bounds.bottom);
    if (unclipped.length === 0) return {visible: false, reason: "outline is clipped", bounds, points};
    const unrelated = (candidate) => !candidate.contains(element) && !element.contains(candidate);
    const modal = element.closest("dialog:modal");
    const nonHitPaint = [...(modal ?? document.body).querySelectorAll("*")]
      .filter(candidate => unrelated(candidate) && getComputedStyle(candidate).pointerEvents === "none" && paints(candidate));
    const interior = document.elementsFromPoint(box.left + box.width / 2, box.top + box.height / 2);
    const interiorLayer = interior.indexOf(element);
    const behindInterior = new Set(interiorLayer < 0 ? [] : interior.slice(interiorLayer + 1));
    const containsPoint = (candidate, x, y) => {
      const paint = candidate.getBoundingClientRect();
      let {left, top, right, bottom} = paint;
      for (let parent = candidate.parentElement; parent instanceof Element; parent = parent.parentElement) {
        const style = getComputedStyle(parent);
        const clip = parent.getBoundingClientRect();
        if (style.overflowX !== "visible") { left = Math.max(left, clip.left + parent.clientLeft); right = Math.min(right, clip.left + parent.clientLeft + parent.clientWidth); }
        if (style.overflowY !== "visible") { top = Math.max(top, clip.top + parent.clientTop); bottom = Math.min(bottom, clip.top + parent.clientTop + parent.clientHeight); }
      }
      return x >= left && x < right && y >= top && y < bottom;
    };
    const visible = unclipped.some(([x, y]) => {
      const stack = document.elementsFromPoint(x, y);
      const ownLayer = stack.findIndex(candidate => candidate.contains(element) || element.contains(candidate));
      return ownLayer >= 0 && !stack.slice(0, ownLayer).some(candidate => unrelated(candidate) && !behindInterior.has(candidate) && paints(candidate))
        && !nonHitPaint.some(candidate => containsPoint(candidate, x, y));
    });
    return {visible, reason: visible ? null : "outline is covered or its visibility is undecidable", bounds, points};
  };
  // tabStops lists the enabled interactive elements in DOM order: inside an
  // open modal dialog only its own, outside closed details only summaries.
  const tabStops = () => {
    const modal = document.querySelector("dialog:modal");
    const scope = modal ?? document.body;
    const nativelyInteractive = (element) => element.matches("a[href], area[href], button, input:not([type=hidden]), select, textarea, iframe, [contenteditable=''], [contenteditable=true]") ||
      (element.tagName === "SUMMARY" && element.parentElement?.tagName === "DETAILS" && element.parentElement.querySelector(":scope > summary") === element);
    const closedDetailsContent = (element) => {
      for (let details = element.parentElement?.closest("details"); details; details = details.parentElement?.closest("details")) {
        if (!details.open && details.querySelector(":scope > summary") !== element) return true;
      }
      return false;
    };
    const rendered = (element) => !element.closest("[inert]") && getComputedStyle(element).visibility === "visible" && element.getClientRects().length > 0;
    return [...scope.querySelectorAll("*")].filter((element) => {
      if (!rendered(element) || closedDetailsContent(element)) return false;
      if (nativelyInteractive(element)) return !element.matches(":disabled");
      return element.hasAttribute("tabindex") && element.tabIndex >= 0;
    });
  };
  return Object.freeze({parse, composite, luminance, ratio, undecidable, backgroundOf, opacityOf, paints, outlineVisible, tabStops});
})();
Object.defineProperty(globalThis, "proofkitMatrix", {value: proofkitMatrix});
`;

// matrixInitScript is installed into every document before its scripts run:
// the pinned axe distribution and the in-page helpers. Init scripts are not
// subject to the page's CSP, so no oracle needs eval.
export const matrixInitScript = `${axeMin.source}\n${pageHelpers}`;


// ---------------------------------------------------------------------------
// Oracle 1: axe with default rules plus target-size, and the computed-contrast
// oracle for every color-contrast node that axe leaves incomplete.

export async function runAxe(page) {
  const result = await page.evaluate(async ({configure, run, version}) => {
    const axe = globalThis.axe;
    if (axe?.version !== version) throw new Error("the pinned axe distribution was not initialized");
    axe.configure(configure);
    return axe.run(document, run);
  }, {configure: axeConfigureOptions, run: axeRunOptions, version: axeVersion});
  if (result?.testEngine?.name !== "axe-core" || result.testEngine.version !== axeVersion) {
    throw new OracleFailure("axe", "axe returned an unexpected test engine");
  }
  return result;
}

// computedContrast decides one element's text contrast from computed styles:
// the text color over the composite of the ancestors' background colors.
// It refuses group opacity, which requires group compositing rather than
// independent background/text fading, and refuses to decide when a background
// image, filter or blend mode is in the chain, or when an
// element with a background other than its ancestors is painted above the
// text's first line.
export async function computedContrast(page, selectors) {
  return page.evaluate((targets) => targets.map((selector) => {
    const helpers = globalThis.proofkitMatrix;
    const element = document.querySelector(selector);
    if (!(element instanceof Element)) return {selector, decided: false, reason: "target not found"};
    const reason = helpers.undecidable(element);
    if (reason !== null) return {selector, decided: false, reason};
    const style = getComputedStyle(element);
    const fontSize = Number.parseFloat(style.fontSize);
    const bold = Number(style.fontWeight) >= 700;
    const large = fontSize >= 24 || (bold && fontSize >= 18.66);
    const background = helpers.backgroundOf(element);
    const text = helpers.parse(style.color);
    const ratio = helpers.ratio(helpers.composite(text, background), background);
    element.scrollIntoView({block: "center", inline: "center"});
    const range = document.createRange();
    range.selectNodeContents(element);
    const rect = [...range.getClientRects()].find((candidate) => candidate.width > 0 && candidate.height > 0);
    if (rect === undefined) return {selector, decided: false, reason: "no rendered text box"};
    const stack = document.elementsFromPoint(rect.left + Math.min(rect.width / 2, 4), rect.top + rect.height / 2);
    const index = stack.findIndex((candidate) => candidate === element || candidate.contains(element));
    if (index < 0) return {selector, decided: false, reason: "text is not hit-testable"};
    const covering = stack.slice(0, index).filter((candidate) => !candidate.contains(element) && helpers.parse(getComputedStyle(candidate).backgroundColor)[3] > 0);
    if (covering.length > 0) return {selector, decided: false, reason: "painted below " + covering[0].tagName};
    const nonHitPaint = [...document.querySelectorAll("body *")].find(candidate => {
      if (candidate.contains(element) || getComputedStyle(candidate).pointerEvents !== "none" || !helpers.paints(candidate)) return false;
      return [...candidate.getClientRects()].some(box =>
        Math.max(0, rect.left, box.left) < Math.min(document.documentElement.clientWidth, rect.right, box.right) &&
        Math.max(0, rect.top, box.top) < Math.min(document.documentElement.clientHeight, rect.bottom, box.bottom));
    });
    if (nonHitPaint !== undefined) return {selector, decided: false, reason: "potential paint excluded from hit-testing on " + nonHitPaint.tagName};
    return {selector, decided: true, ratio, large, required: large ? 3 : 4.5, fontSize, fontWeight: style.fontWeight};
  }), selectors);
}

export function axeRuleNodes(result, outcome, ruleId) {
  return result[outcome].filter((entry) => entry.id === ruleId).flatMap((entry) => entry.nodes);
}

export function axeTargetSelector(node) {
  if (!Array.isArray(node.target) || node.target.length !== 1 || typeof node.target[0] !== "string") {
    throw new OracleFailure("axe", "axe node target must be one selector in the main frame", node.target);
  }
  return node.target[0];
}

// judgeAxe: zero violations; color-contrast and target-size each apply to at
// least one node; target-size has no incomplete result; and each incomplete
// color-contrast node is decided by the computed-contrast oracle and meets
// 4.5:1, or 3:1 for large text.
export function judgeAxe(result, contrast) {
  if (result.violations.length > 0) {
    throw new OracleFailure("axe", "axe reported violations", result.violations.map((entry) => ({id: entry.id, targets: entry.nodes.map((node) => node.target)})));
  }
  for (const ruleId of ["color-contrast", "target-size"]) {
    const applied = ["passes", "violations", "incomplete"].reduce((count, outcome) => count + axeRuleNodes(result, outcome, ruleId).length, 0);
    if (applied === 0) throw new OracleFailure("axe", `${ruleId} applies to no node`);
  }
  const targetSize = axeRuleNodes(result, "incomplete", "target-size");
  if (targetSize.length > 0) throw new OracleFailure("axe", "target-size has incomplete results", targetSize.map((node) => node.target));
  const incomplete = axeRuleNodes(result, "incomplete", "color-contrast").map(axeTargetSelector);
  const decided = new Map(contrast.map((entry) => [entry.selector, entry]));
  for (const selector of incomplete) {
    const entry = decided.get(selector);
    if (entry === undefined) throw new OracleFailure("axe", "an incomplete color-contrast node has no computed-contrast decision", selector);
    if (!entry.decided) throw new OracleFailure("axe", "the computed-contrast oracle cannot decide an incomplete color-contrast node", entry);
    if (!(entry.ratio >= entry.required)) throw new OracleFailure("axe", "an incomplete color-contrast node fails the computed-contrast oracle", entry);
  }
}

export async function axeOracle(page, mutateResult = (result) => result) {
  const result = mutateResult(await runAxe(page));
  const incomplete = axeRuleNodes(result, "incomplete", "color-contrast").map(axeTargetSelector);
  const contrast = await computedContrast(page, incomplete);
  judgeAxe(result, contrast);
  return {incompleteContrast: contrast, contrastNodes: ["passes", "incomplete"].map((outcome) => axeRuleNodes(result, outcome, "color-contrast").length)};
}

// ---------------------------------------------------------------------------
// Oracle 1, continued: control contrast. Axe tests neither placeholder text
// nor the boundary of a checkbox, so the computed-contrast oracle decides
// both from computed styles: every rendered placeholder meets 4.5:1 against
// its field, and every rendered checkbox that is not in keyboard focus, where
// oracle 4 judges its focus ring instead, shows a solid outline at least as
// wide as the --border-width token with 3:1 contrast against the background
// behind it. The author outline is required in every engine, because the
// boundary that an engine paints itself is not a computed style.

export async function observeControlContrast(page) {
  return page.evaluate(() => {
    const helpers = globalThis.proofkitMatrix;
    const rendered = (element) => !element.closest("[hidden], [inert]") && getComputedStyle(element).visibility === "visible" && element.getClientRects().length > 0;
    const describe = (element) => element.id || element.getAttribute("aria-label") || element.closest("label")?.textContent?.trim() || element.tagName;
    const placeholders = [...document.querySelectorAll("input[placeholder], textarea[placeholder]")]
      .filter((element) => element.placeholder !== "" && rendered(element))
      .map((element) => {
        const style = getComputedStyle(element, "::placeholder");
        const background = helpers.backgroundOf(element);
        const text = helpers.parse(style.color);
        text[3] *= Number(style.opacity) * helpers.opacityOf(element);
        return {control: describe(element), color: style.color, opacity: style.opacity, decided: helpers.undecidable(element) === null,
          ratio: helpers.ratio(helpers.composite(text, background), background)};
      });
    const token = Number.parseFloat(getComputedStyle(document.documentElement).getPropertyValue("--border-width"));
    const checkboxes = [...document.querySelectorAll("input[type=checkbox]")]
      .filter((element) => rendered(element) && !element.matches(":focus-visible"))
      .map((element) => {
        const style = getComputedStyle(element);
        const background = helpers.backgroundOf(element.parentElement ?? document.documentElement);
        const outline = helpers.parse(style.outlineColor);
        outline[3] *= helpers.opacityOf(element);
        return {control: describe(element), decided: helpers.undecidable(element) === null, outlineStyle: style.outlineStyle, outlineWidth: Number.parseFloat(style.outlineWidth), token,
          ratio: helpers.ratio(helpers.composite(outline, background), background)};
      });
    return {placeholders, checkboxes};
  });
}

export function judgeControlContrast({placeholders, checkboxes}) {
  const faint = placeholders.filter((entry) => !entry.decided || !(entry.ratio >= 4.5));
  if (faint.length > 0) throw new OracleFailure("contrast", "a placeholder has less than 4.5:1 contrast with its field", faint);
  const unbounded = checkboxes.filter((entry) => !entry.decided || entry.outlineStyle !== "solid" || !(entry.outlineWidth >= entry.token) || !(entry.ratio >= 3));
  if (unbounded.length > 0) throw new OracleFailure("contrast", "a checkbox has no boundary of the border width with 3:1 contrast", unbounded);
}

export async function controlContrastOracle(page) {
  const observation = await observeControlContrast(page);
  judgeControlContrast(observation);
  return {placeholders: observation.placeholders.map((entry) => entry.ratio), checkboxes: observation.checkboxes.map((entry) => entry.ratio)};
}

// ---------------------------------------------------------------------------
// Oracle 2: reflow. The document does not scroll horizontally, and every
// element whose content overflows it horizontally is a labelled, keyboard-
// focusable graph or table region.

export async function observeReflow(page) {
  return page.evaluate(() => {
    const root = document.documentElement;
    const name = (element) => {
      const labelledBy = element.getAttribute("aria-labelledby");
      if (labelledBy) return labelledBy.split(/\s+/).map((id) => document.getElementById(id)?.textContent?.trim() ?? "").join(" ").trim();
      return (element.getAttribute("aria-label") ?? "").trim();
    };
    const overflowing = [...document.querySelectorAll("body *")]
      .filter((element) => element.clientWidth > 0 && element.scrollWidth - element.clientWidth > 1)
      .map((element) => ({
        tagName: element.tagName,
        id: element.id,
        className: typeof element.className === "string" ? element.className : "",
        role: element.getAttribute("role"),
        name: name(element),
        tabIndex: element.tabIndex,
        overflowX: getComputedStyle(element).overflowX,
        holdsGraphOrTable: element.querySelector("table, svg") !== null,
        scrollWidth: element.scrollWidth,
        clientWidth: element.clientWidth,
      }));
    return {documentOverflow: root.scrollWidth - root.clientWidth, overflowing};
  });
}

export function judgeReflow(observation) {
  if (observation.documentOverflow > 1) throw new OracleFailure("reflow", "the document scrolls horizontally", observation);
  const unlabelled = observation.overflowing.filter((element) => element.role !== "region" || element.name === "" || element.tabIndex < 0 ||
    !["auto", "scroll"].includes(element.overflowX) || !element.holdsGraphOrTable);
  if (unlabelled.length > 0) throw new OracleFailure("reflow", "content overflows an element that is not a labelled focusable graph or table region", unlabelled);
}

export async function reflowOracle(page) {
  const observation = await observeReflow(page);
  judgeReflow(observation);
  return observation;
}

// ---------------------------------------------------------------------------
// Oracle 3: lost content. Every text of the view's records is rendered, not
// clipped by an ancestor with overflow hidden or clip, and not painted over.
// Native closed disclosures require only their summaries, not their bodies.
// Other declared exceptions: a graph node label clamped inside the labelled graph
// region whose full text the visible record list holds, and the graph region
// hidden at 48rem or less while the record list is visible.

export async function observeContent(page, recordSelector) {
  return page.evaluate((selector) => {
    const records = [...document.querySelectorAll(selector)].filter((record) => !record.closest("[hidden]"));
    const findings = [];
    let texts = 0;
    // Background boxes can cover only part of a line or opt out of hit-testing.
    // Their geometry is an independent operand, not proof of pixel paint order.
    const paintedBoxes = [...document.querySelectorAll("body *")].filter(globalThis.proofkitMatrix.paints);
    const normalizeText = (text) => text.replace(/\s+/g, " ").trim();
    const listed = new Map([...document.querySelectorAll(".graph-records [data-graph-select]")]
      .filter((element) => element.getClientRects().length > 0)
      .map((element) => [element.dataset.graphSelect, element]));
    const graphAlternate = (graphNode) => {
      const alternate = listed.get(graphNode?.dataset.graphSelect);
      return alternate !== undefined && [".graph-node-label", ".graph-node-identity"].every(selector => {
        const original = graphNode.querySelector(selector);
        const replacement = alternate.querySelector(selector);
        return original !== null && replacement !== null && normalizeText(original.textContent) === normalizeText(replacement.textContent);
      });
    };
    const closedDetailsContent = (node) => {
      for (let details = node.parentElement?.closest("details"); details; details = details.parentElement?.closest("details")) {
        const summary = details.querySelector(":scope > summary");
        if (!details.open && !(summary && summary.contains(node))) return true;
      }
      return false;
    };
    for (const record of records) {
      const walker = document.createTreeWalker(record, NodeFilter.SHOW_TEXT);
      while (walker.nextNode()) {
        const node = walker.currentNode;
        if (node.textContent.trim() === "" || closedDetailsContent(node)) continue;
        const owner = node.parentElement;
        const ownerStyle = getComputedStyle(owner);
        if (owner.closest("script, style, template")) continue;
        texts += 1;
        const text = node.textContent.trim().slice(0, 80);
        if (ownerStyle.visibility !== "visible" || globalThis.proofkitMatrix.opacityOf(owner) === 0 || globalThis.proofkitMatrix.parse(ownerStyle.color)[3] === 0) {
          findings.push({text, problem: "not visible"});
          continue;
        }
        const graphNode = owner.closest(".graph-node");
        const graphRegion = owner.closest("[role=region]");
        const range = document.createRange();
        range.selectNodeContents(node);
        let rects = [...range.getClientRects()].filter((rect) => rect.width > 0 && rect.height > 0);
        if (rects.length === 0) {
          const hiddenGraph = graphNode !== null && graphRegion !== null && getComputedStyle(graphRegion).display === "none"
            && matchMedia("(max-width: 48rem)").matches && graphAlternate(graphNode);
          if (!hiddenGraph) findings.push({text, problem: "not rendered"});
          continue;
        }
        const lineRects = () => [...range.getClientRects()].filter((rect) => rect.width > 0 && rect.height > 0);
        const union = rects.reduce((box, rect) => ({left: Math.min(box.left, rect.left), top: Math.min(box.top, rect.top), right: Math.max(box.right, rect.right), bottom: Math.max(box.bottom, rect.bottom)}),
          {left: Infinity, top: Infinity, right: -Infinity, bottom: -Infinity});
        let clipped = null;
        for (let ancestor = owner; ancestor instanceof Element && ancestor !== document.documentElement; ancestor = ancestor.parentElement) {
          const style = getComputedStyle(ancestor);
          const clipsX = ["hidden", "clip"].includes(style.overflowX);
          const clipsY = ["hidden", "clip"].includes(style.overflowY);
          if (!clipsX && !clipsY) continue;
          const box = ancestor.getBoundingClientRect();
          const left = box.left + ancestor.clientLeft;
          const top = box.top + ancestor.clientTop;
          const right = left + ancestor.clientWidth;
          const bottom = top + ancestor.clientHeight;
          if ((clipsX && (union.left < left - 1 || union.right > right + 1)) || (clipsY && (union.top < top - 1 || union.bottom > bottom + 1))) {
            clipped = {tagName: ancestor.tagName, className: typeof ancestor.className === "string" ? ancestor.className : ""};
            break;
          }
        }
        if (clipped !== null) {
          const clamped = graphNode !== null && graphRegion !== null && graphRegion.contains(graphNode) && graphAlternate(graphNode);
          if (!clamped) findings.push({text, problem: "clipped", clipped});
          continue;
        }
        // Each line box of the text is scrolled to the center of every
        // scrolling ancestor and of the viewport, then hit-tested there.
        const reveal = (index) => {
          owner.scrollIntoView({block: "nearest", inline: "nearest"});
          for (let ancestor = owner.parentElement; ancestor instanceof Element && ancestor !== document.body && ancestor !== document.documentElement; ancestor = ancestor.parentElement) {
            const style = getComputedStyle(ancestor);
            const scrollsY = ["auto", "scroll"].includes(style.overflowY) && ancestor.scrollHeight > ancestor.clientHeight;
            const scrollsX = ["auto", "scroll"].includes(style.overflowX) && ancestor.scrollWidth > ancestor.clientWidth;
            if (!scrollsX && !scrollsY) continue;
            const rect = lineRects()[index];
            const box = ancestor.getBoundingClientRect();
            if (scrollsY) ancestor.scrollTop += rect.top + rect.height / 2 - (box.top + ancestor.clientTop + ancestor.clientHeight / 2);
            if (scrollsX) ancestor.scrollLeft += rect.left + rect.width / 2 - (box.left + ancestor.clientLeft + ancestor.clientWidth / 2);
          }
          const rect = lineRects()[index];
          window.scrollBy(0, rect.top + rect.height / 2 - document.documentElement.clientHeight / 2);
          return lineRects()[index];
        };
        let painted = true;
        let probe = null;
        for (let index = 0; index < rects.length; index += 1) {
          const rect = reveal(index);
          const x = rect.left + Math.min(rect.width / 2, 6);
          const y = rect.top + rect.height / 2;
          const hit = document.elementFromPoint(x, y);
          if (hit === null || !(hit === owner || owner.contains(hit) || hit.contains(owner))) {
            painted = false;
            probe = {line: index, by: hit === null ? null : hit.tagName, className: hit !== null && typeof hit.className === "string" ? hit.className : ""};
            break;
          }
          for (const element of paintedBoxes) {
            if (element.contains(owner)) continue;
            const style = getComputedStyle(element);
            for (const box of element.getClientRects()) {
              const left = Math.max(0, rect.left, box.left);
              const right = Math.min(document.documentElement.clientWidth, rect.right, box.right);
              const top = Math.max(0, rect.top, box.top);
              const bottom = Math.min(document.documentElement.clientHeight, rect.bottom, box.bottom);
              if (right <= left || bottom <= top) continue;
              if (style.pointerEvents === "none") {
                painted = false;
                probe = {line: index, by: element.tagName, problem: "overlapping paint excluded from hit-testing"};
                break;
              }
              const overlapHit = document.elementFromPoint((left + right) / 2, (top + bottom) / 2);
              if (overlapHit !== null && (overlapHit === element || element.contains(overlapHit))) {
                painted = false;
                probe = {line: index, by: element.tagName, problem: "intersecting painted box"};
                break;
              }
            }
            if (!painted) break;
          }
          if (!painted) break;
        }
        if (!painted) findings.push({text, problem: "visibility refused", probe});
      }
    }
    window.scrollTo(0, 0);
    return {records: records.length, texts, findings};
  }, recordSelector);
}

export function judgeContent(observation, expectedRecords) {
  if (observation.records !== expectedRecords || observation.texts === 0) {
    throw new OracleFailure("content", `the view must render exactly ${expectedRecords} records with text`, {records: observation.records, texts: observation.texts});
  }
  if (observation.findings.length > 0) throw new OracleFailure("content", "record text is lost or its visibility is undecidable", observation.findings);
}

export async function contentOracle(page, recordSelector, expectedRecords) {
  const observation = await observeContent(page, recordSelector);
  judgeContent(observation, expectedRecords);
  return {records: observation.records, texts: observation.texts};
}

// ---------------------------------------------------------------------------
// Oracle 4: keyboard. Tab reaches every enabled interactive element in DOM
// order, inside an open modal dialog only its own, and Shift+Tab walks back
// from the last one, so focus is held nowhere; each focused element shows an
// outline at least as wide as the focus token whose color has at least 3:1
// contrast with the background behind it. Pinned Firefox and WebKit also stop
// on an open dialog element, and an engine may stop on a scroll container;
// such a stop is not an interactive element, is admitted between them and
// must show the focus indicator too.

// tabKey is the key that moves focus to the next focusable element. Pinned
// WebKit, like Safari by default, skips links on Tab and reaches every
// focusable element on Option-Tab, which Playwright sends as Alt+Tab.
export function tabKey(browserName, backward = false) {
  return `${browserName === "webkit" ? "Alt+" : ""}${backward ? "Shift+" : ""}Tab`;
}

export async function observeKeyboard(page, browserName) {
  const expected = await page.evaluate(() => {
    const elements = globalThis.proofkitMatrix.tabStops();
    elements.forEach((element, index) => element.setAttribute("data-proofkit-matrix-stop", String(index)));
    const modal = document.querySelector("dialog:modal") !== null;
    if (!modal) {
      // Outside a modal dialog the walk starts at the document start: focusing
      // the body once moves the sequential focus navigation starting point
      // there, wherever earlier oracles scrolled.
      const body = document.body;
      body.tabIndex = -1;
      body.focus({preventScroll: true});
      body.removeAttribute("tabindex");
    }
    return {count: elements.length, modal, focused: document.activeElement?.getAttribute("data-proofkit-matrix-stop") ?? null};
  });
  const describeFocus = async () => {
    // WebKit can acknowledge a key before its focus-induced scroll commits.
    // Wait for that semantic readiness, never repeat the key or ignore clipping.
    let readiness;
    try {
      await expect.poll(async () => {
        readiness = await page.evaluate(() => {
          const element = document.activeElement;
          if (!document.hasFocus() || !(element instanceof Element) || element === document.body || element === document.documentElement) return {visible: true};
          const box = element.getBoundingClientRect();
          return {visible: box.bottom > 0 && box.top < document.documentElement.clientHeight && box.right > 0 && box.left < document.documentElement.clientWidth,
            tagName: element.tagName, id: element.id, top: box.top, left: box.left, bottom: box.bottom, right: box.right};
        });
        return readiness;
      }).toMatchObject({visible: true});
    } catch {
      throw new OracleFailure("keyboard", "the focused control did not reach the viewport", readiness);
    }
    const observation = await page.evaluate(() => {
      const helpers = globalThis.proofkitMatrix;
      const element = document.activeElement;
      // Focus that left the document for the browser leaves either the body
      // focused or the document unfocused.
      if (!document.hasFocus() || !(element instanceof Element) || element === document.body || element === document.documentElement) return {stop: null, outside: true, tagName: element?.tagName ?? null};
      const token = Number.parseFloat(getComputedStyle(document.documentElement).getPropertyValue("--focus-width"));
      const style = getComputedStyle(element);
      const paintDecidable = helpers.undecidable(element) === null;
      const outlineWidth = Number.parseFloat(style.outlineWidth);
      const visibility = helpers.outlineVisible(element, style);
      const background = helpers.backgroundOf(element.parentElement ?? document.documentElement);
      const outline = helpers.parse(style.outlineColor);
      outline[3] *= helpers.opacityOf(element);
      const scroller = ["auto", "scroll"].includes(style.overflowY) && element.scrollHeight > element.clientHeight ||
        ["auto", "scroll"].includes(style.overflowX) && element.scrollWidth > element.clientWidth;
      return {
        stop: element.getAttribute("data-proofkit-matrix-stop"),
        outside: false,
        container: element.tagName === "DIALOG" && element.open || scroller,
        tagName: element.tagName,
        label: (element.getAttribute("aria-label") ?? element.textContent ?? "").trim().slice(0, 60),
        outlineStyle: style.outlineStyle,
        outlineWidth,
        token,
        visible: paintDecidable && visibility.visible,
        visibilityProblem: visibility.reason,
        visibilityGeometry: visibility,
        contrast: helpers.ratio(helpers.composite(outline, background), background),
      };
    });
    return observation;
  };
  const visited = [];
  // walk presses the key until focus reaches the target stop, collecting
  // every step; it gives up after the stop count plus a margin.
  const walk = async (backward, target) => {
    const steps = [];
    for (let step = 0; step < expected.count + 12; step += 1) {
      await page.keyboard.press(tabKey(browserName, backward));
      const focus = await describeFocus();
      steps.push(focus);
      visited.push(focus);
      if (!focus.outside && !focus.visible) throw new OracleFailure("keyboard", "a focused element has no visible focus indicator of the focus token's width with 3:1 contrast", focus);
      if (focus.stop === target) break;
    }
    return steps;
  };
  const last = String(expected.count - 1);
  const forward = expected.count === 0 || expected.focused === last ? [] : await walk(false, last);
  const backward = expected.count < 2 ? [] : await walk(true, "0");
  await page.evaluate(() => { for (const element of document.querySelectorAll("[data-proofkit-matrix-stop]")) element.removeAttribute("data-proofkit-matrix-stop"); });
  return {expected, forward, backward, visited};
}

export function judgeKeyboard({expected, forward, backward, visited}) {
  if (expected.count === 0) throw new OracleFailure("keyboard", "the view has no interactive element");
  if (expected.modal && expected.focused === null) throw new OracleFailure("keyboard", "an open modal dialog holds no focused element", visited);
  const unlisted = visited.filter((focus) => focus.stop === null && !focus.outside && !focus.container);
  if (unlisted.length > 0) throw new OracleFailure("keyboard", "Tab stops on an element that is neither interactive nor an open dialog or scroll container", unlisted);
  if (visited.some((focus) => focus.outside)) throw new OracleFailure("keyboard", "focus left the document before every interactive element was reached", visited);
  const first = expected.modal ? Number(expected.focused) + 1 : 0;
  const forwardOrder = Array.from({length: expected.count - first}, (_, offset) => String(first + offset));
  const backwardOrder = Array.from({length: expected.count - 1}, (_, offset) => String(expected.count - 2 - offset));
  const stops = (steps) => steps.filter((focus) => focus.stop !== null).map((focus) => focus.stop);
  if (stops(forward).join(",") !== forwardOrder.join(",")) {
    throw new OracleFailure("keyboard", expected.modal ? "Tab does not reach every interactive element of the modal dialog in DOM order" : "Tab does not reach every enabled interactive element in DOM order",
      {count: expected.count, focused: expected.focused, forward});
  }
  if (stops(backward).join(",") !== backwardOrder.join(",")) {
    throw new OracleFailure("keyboard", "Shift+Tab does not walk back from the last interactive element through every one in reverse DOM order", {count: expected.count, backward});
  }
  const invisible = visited.filter((focus) => !focus.visible || ["none", "hidden"].includes(focus.outlineStyle) || !(focus.outlineWidth >= focus.token) || !(focus.contrast >= 3));
  if (invisible.length > 0) throw new OracleFailure("keyboard", "a focused element has no visible focus indicator of the focus token's width with 3:1 contrast", invisible);
}

export async function keyboardOracle(page, browserName) {
  const observation = await observeKeyboard(page, browserName);
  judgeKeyboard(observation);
  return {stops: observation.expected.count, modal: observation.expected.modal, steps: observation.visited.length};
}

// ---------------------------------------------------------------------------
// Oracle 6: security. The document response carries the exact CSP and
// document security headers, and the page raises no console error, no page
// error and no securitypolicyviolation event.

export function documentSecurityHeaders(csp) {
  return {
    "content-security-policy": csp,
    "cross-origin-opener-policy": "same-origin",
    "cross-origin-resource-policy": "same-origin",
    "permissions-policy": "accelerometer=(), camera=(), geolocation=(), gyroscope=(), microphone=(), payment=(), usb=()",
    "referrer-policy": "no-referrer",
    "x-content-type-options": "nosniff",
  };
}

export function judgeDocumentHeaders(headers, csp) {
  const expected = documentSecurityHeaders(csp);
  const actual = Object.fromEntries(Object.keys(expected).map((name) => [name, headers[name]]));
  if (JSON.stringify(actual) !== JSON.stringify(expected)) throw new OracleFailure("security", "the document security headers differ from the exact expected headers", {actual, expected});
}

// SecurityMonitor collects console errors, page errors and, through a page
// binding that an init script calls from a capture listener, every
// securitypolicyviolation event of every document of the page.
export class SecurityMonitor {
  static async attach(page) {
    const monitor = new SecurityMonitor();
    page.on("console", (message) => { if (message.type() === "error") monitor.consoleErrors.push(message.text()); });
    page.on("pageerror", (error) => { monitor.pageErrors.push(String(error?.message ?? error)); });
    await page.exposeBinding("proofkitMatrixReportViolation", (_source, violation) => { monitor.violations.push(violation); });
    await page.addInitScript(() => {
      document.addEventListener("securitypolicyviolation", (event) => {
        void globalThis.proofkitMatrixReportViolation({blockedURI: event.blockedURI, effectiveDirective: event.effectiveDirective, violatedDirective: event.violatedDirective});
      }, {capture: true});
    });
    return monitor;
  }

  constructor() {
    this.consoleErrors = [];
    this.pageErrors = [];
    this.violations = [];
  }

  observation() {
    return {consoleErrors: [...this.consoleErrors], pageErrors: [...this.pageErrors], violations: [...this.violations]};
  }
}

export function judgeSecurityEvents(observation) {
  if (observation.consoleErrors.length > 0 || observation.pageErrors.length > 0 || observation.violations.length > 0) {
    throw new OracleFailure("security", "the page raised a console error, a page error or a securitypolicyviolation event", observation);
  }
}

// settleSecurityEvents gives events that a just-finished action queued one
// round trip and two frames to arrive before the monitor is judged.
export async function settleSecurityEvents(page) {
  await page.evaluate(() => new Promise((resolve) => requestAnimationFrame(() => requestAnimationFrame(resolve))));
}
