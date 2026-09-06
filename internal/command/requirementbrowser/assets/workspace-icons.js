// @ts-check
// Static subset of lucide 1.41.0, package/dist/esm/icons/*.mjs.
// https://www.npmjs.com/package/lucide/v/1.41.0
// sha512-fIXP7JzC1vehdqOrMhwpbcXzX6CvUMuoDf16HY1FmC4sDBeuwrH2A0c6QmLn3wnSvaMchpEyM+JWijyTvOs3kw==
/*
ISC License

Copyright (c) 2026 Lucide Icons and Contributors

Permission to use, copy, modify, and/or distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

---

The following Lucide icons are derived from the Feather project:

airplay, alert-circle, alert-octagon, alert-triangle, aperture, arrow-down-circle, arrow-down-left, arrow-down-right, arrow-down, arrow-left-circle, arrow-left, arrow-right-circle, arrow-right, arrow-up-circle, arrow-up-left, arrow-up-right, arrow-up, at-sign, calendar, cast, check, chevron-down, chevron-left, chevron-right, chevron-up, chevrons-down, chevrons-left, chevrons-right, chevrons-up, circle, clipboard, clock, code, columns, command, compass, corner-down-left, corner-down-right, corner-left-down, corner-left-up, corner-right-down, corner-right-up, corner-up-left, corner-up-right, crosshair, database, divide-circle, divide-square, dollar-sign, download, external-link, feather, frown, hash, headphones, help-circle, info, italic, key, layout, life-buoy, link-2, link, loader, lock, log-in, log-out, maximize, meh, minimize, minimize-2, minus-circle, minus-square, minus, monitor, moon, more-horizontal, more-vertical, move, music, navigation-2, navigation, octagon, pause-circle, percent, plus-circle, plus-square, plus, power, radio, rss, search, server, share, shopping-bag, sidebar, smartphone, smile, square, table-2, tablet, target, terminal, trash-2, trash, triangle, tv, type, upload, x-circle, x-octagon, x-square, x, zoom-in, zoom-out

The MIT License (MIT) (for the icons listed above)

Copyright (c) 2013-present Cole Bemis

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

/** @type {Record<string, [string, Record<string, string>][]>} */
const nodes = {
  "panel-left": [["rect", {width: "18", height: "18", x: "3", y: "3", rx: "2"}], ["path", {d: "M9 3v18"}]],
  "panel-right": [["rect", {width: "18", height: "18", x: "3", y: "3", rx: "2"}], ["path", {d: "M15 3v18"}]],
  search: [["path", {d: "m21 21-4.34-4.34"}], ["circle", {cx: "11", cy: "11", r: "8"}]],
  x: [["path", {d: "M18 6 6 18"}], ["path", {d: "m6 6 12 12"}]],
  "chevron-right": [["path", {d: "m9 18 6-6-6-6"}]],
  "chevron-down": [["path", {d: "m6 9 6 6 6-6"}]],
  "arrow-left": [["path", {d: "m12 19-7-7 7-7"}], ["path", {d: "M19 12H5"}]],
  "arrow-right": [["path", {d: "M5 12h14"}], ["path", {d: "m12 5 7 7-7 7"}]],
  "refresh-cw": [["path", {d: "M3 12a9 9 0 0 1 9-9 9.75 9.75 0 0 1 6.74 2.74L21 8"}], ["path", {d: "M21 3v5h-5"}], ["path", {d: "M21 12a9 9 0 0 1-9 9 9.75 9.75 0 0 1-6.74-2.74L3 16"}], ["path", {d: "M8 16H3v5"}]],
  "file-text": [["path", {d: "M6 22a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h8a2.4 2.4 0 0 1 1.704.706l3.588 3.588A2.4 2.4 0 0 1 20 8v12a2 2 0 0 1-2 2z"}], ["path", {d: "M14 2v5a1 1 0 0 0 1 1h5"}], ["path", {d: "M10 9H8"}], ["path", {d: "M16 13H8"}], ["path", {d: "M16 17H8"}]],
  "git-compare-arrows": [["circle", {cx: "5", cy: "6", r: "3"}], ["path", {d: "M12 6h5a2 2 0 0 1 2 2v7"}], ["path", {d: "m15 9-3-3 3-3"}], ["circle", {cx: "19", cy: "18", r: "3"}], ["path", {d: "M12 18H7a2 2 0 0 1-2-2V9"}], ["path", {d: "m9 15 3 3-3 3"}]],
  network: [["rect", {x: "16", y: "16", width: "6", height: "6", rx: "1"}], ["rect", {x: "2", y: "16", width: "6", height: "6", rx: "1"}], ["rect", {x: "9", y: "2", width: "6", height: "6", rx: "1"}], ["path", {d: "M5 16v-3a1 1 0 0 1 1-1h12a1 1 0 0 1 1 1v3"}], ["path", {d: "M12 12V8"}]],
  "message-square": [["path", {d: "M22 17a2 2 0 0 1-2 2H6.828a2 2 0 0 0-1.414.586l-2.202 2.202A.71.71 0 0 1 2 21.286V5a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2z"}]],
  info: [["circle", {cx: "12", cy: "12", r: "10"}], ["path", {d: "M12 16v-4"}], ["path", {d: "M12 8h.01"}]],
  check: [["path", {d: "M20 6 9 17l-5-5"}]],
};

/** @param {string} name */
export function icon(name) {
  if (!Object.hasOwn(nodes, name)) throw new Error("Unknown workspace icon");
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  for (const [key, value] of Object.entries({width: "20", height: "20", viewBox: "0 0 24 24", fill: "none", stroke: "currentColor", "stroke-width": "2", "stroke-linecap": "round", "stroke-linejoin": "round", "aria-hidden": "true", focusable: "false", class: "workspace-icon"})) svg.setAttribute(key, value);
  for (const [tag, attributes] of nodes[name]) {
    const child = document.createElementNS(svg.namespaceURI, tag);
    for (const [key, value] of Object.entries(attributes)) child.setAttribute(key, value);
    svg.append(child);
  }
  return svg;
}

/** @param {ParentNode} root */
export function decorateIcons(root) {
  for (const element of root.querySelectorAll("[data-icon]")) {
    if (element instanceof HTMLElement && element.dataset.icon) {
      element.prepend(icon(element.dataset.icon));
      delete element.dataset.icon;
    }
  }
}
