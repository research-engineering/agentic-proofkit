import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import test from "node:test";
import {runInNewContext} from "node:vm";

const source = readFileSync(new URL("../internal/kernel/browserdoc/browser.js", import.meta.url), "utf8");

// This host adapter executes the unchanged production script without a browser.
// Expected IDs below are authored independently of its matching predicate.
function filterHost() {
  class Element {
    constructor(id, attributes = {}) {
      this.id = id;
      this.attributes = attributes;
      this.events = new Map();
      this.value = "";
      this.checked = false;
      this.hidden = false;
      this.textContent = "";
    }
    getAttribute(name) { return this.attributes[name] ?? null; }
    addEventListener(name, callback) { this.events.set(name, callback); }
  }
  const inputs = new Map(["search", "show-ids", "open-details", "view-mode", "visible-count"].map(name => ["proofkit-" + name, new Element(name)]));
  inputs.get("proofkit-view-mode").value = "cards";
  const filters = ["kind", "scope"].map(key => new Element(key, {"data-filter-key": key}));
  const fixtures = [
    {id: "exact", search: "Alpha", kind: ["a"], scope: ["red"]},
    {id: "long", search: "Alphanumeric", kind: ["aa"], scope: ["red"]},
    {id: "multi", search: "Beta", kind: ["z", "a"], scope: ["blue"]},
    {id: "empty", search: "Empty", kind: [], scope: []},
    {id: "absent", search: "Absent"},
  ];
  const records = () => fixtures.map(item => new Element(item.id, {
    "data-search": item.search,
    ...(item.kind === undefined ? {} : {"data-filter-kind": JSON.stringify(item.kind)}),
    ...(item.scope === undefined ? {} : {"data-filter-scope": JSON.stringify(item.scope)}),
  }));
  const cards = records(), rows = records();
  const cardSection = new Element("card-section"), tableSection = new Element("table-section");
  const lists = new Map([
    ["[data-proofkit-card]", cards], ["[data-proofkit-table-row]", rows],
    ["[data-proofkit-card-group]", []], ["[data-proofkit-filter]", filters],
    ["details", []], ["[data-proofkit-download]", []], ['.hierarchy a[href^="#"]', []],
  ]);
  const document = {
    documentElement: {dataset: {}},
    getElementById: id => inputs.get(id) ?? null,
    querySelector: selector => ({"[data-proofkit-card-section]": cardSection, "[data-proofkit-table-section]": tableSection})[selector] ?? null,
    querySelectorAll: selector => {
      assert(lists.has(selector), "unexpected production selector " + selector);
      return lists.get(selector);
    },
    addEventListener() {},
  };
  runInNewContext(source, {document}, {timeout: 1000});
  return (state, expected) => {
    filters[0].value = state.kind ?? "";
    filters[1].value = state.scope ?? "";
    inputs.get("proofkit-search").value = state.query ?? "";
    inputs.get("proofkit-view-mode").value = state.mode ?? "cards";
    inputs.get("proofkit-search").events.get("input")();
    assert.deepEqual(cards.filter(item => !item.hidden).map(item => item.id), expected, "cards " + JSON.stringify(state));
    assert.deepEqual(rows.filter(item => !item.hidden).map(item => item.id), expected, "rows " + JSON.stringify(state));
    assert.equal(inputs.get("proofkit-visible-count").textContent, String(expected.length));
    assert.equal(cardSection.hidden, state.mode === "table");
    assert.equal(tableSection.hidden, state.mode !== "table");
  };
}

test("static filters use exact membership, preserve non-first values and distinguish empty from wildcard", () => {
  const observe = filterHost();
  for (const [state, ids] of [
    [{}, ["exact", "long", "multi", "empty", "absent"]],
    [{kind: "a"}, ["exact", "multi"]],
    [{kind: "aa"}, ["long"]],
    [{kind: "z"}, ["multi"]],
    [{kind: "missing"}, []],
    [{}, ["exact", "long", "multi", "empty", "absent"]],
  ]) observe(state, ids);
});

test("static filter fields intersect with search and reset equally in cards and table", () => {
  for (const mode of ["cards", "table"]) {
    const observe = filterHost();
    for (const [state, ids] of [
      [{kind: "a", scope: "red"}, ["exact"]],
      [{kind: "a", scope: "blue"}, ["multi"]],
      [{kind: "a", scope: "missing"}, []],
      [{kind: "a", query: " ALPHA "}, ["exact"]],
      [{kind: "a", query: "Beta"}, ["multi"]],
      [{kind: "aa", query: "Beta"}, []],
      [{}, ["exact", "long", "multi", "empty", "absent"]],
    ]) observe({...state, mode}, ids);
  }
});
