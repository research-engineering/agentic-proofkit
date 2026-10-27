import assert from "node:assert/strict";
import test from "node:test";

import {
  axeTargetSelector, documentSecurityHeaders, judgeAxe, judgeContent, judgeControlContrast,
  judgeDocumentHeaders, judgeKeyboard, judgeReflow, judgeSecurityEvents, OracleFailure, SecurityMonitor,
  textContrastThreshold,
} from "./oracles.mjs";

function refuses(judge, observation, label) {
  assert.throws(() => judge(observation), OracleFailure, label);
}

test("text contrast classification separates regular size and both bold guards", () => {
  for (const [size, weight, required] of [
    [24, 400, 3], [23.99, 400, 4.5], [20, 700, 3], [20, 699, 4.5],
    [18.66, 700, 3], [18.65, 700, 4.5], [18, 900, 4.5], [24, 699, 3],
  ]) {
    assert.equal(textContrastThreshold(size, weight), required, `${size}px/${weight}`);
  }
});

test("axe decisions independently require every material rule operand", () => {
  const node = {target: ["#text"]};
  const fresh = () => ({violations: [], incomplete: [], passes: [
    {id: "color-contrast", nodes: [node]}, {id: "target-size", nodes: [node]},
  ]});
  assert.doesNotThrow(() => judgeAxe(fresh(), []));
  const violation = fresh();
  violation.violations.push({id: "other-rule", nodes: []});
  assert.throws(() => judgeAxe(violation, []), OracleFailure);
  for (const rule of ["color-contrast", "target-size"]) {
    const absent = fresh();
    absent.passes = absent.passes.filter(entry => entry.id !== rule);
    assert.throws(() => judgeAxe(absent, []), OracleFailure, rule);
  }
  const incompleteTarget = fresh();
  incompleteTarget.incomplete.push({id: "target-size", nodes: [node]});
  assert.throws(() => judgeAxe(incompleteTarget, []), OracleFailure);
  const incompleteColor = fresh();
  incompleteColor.incomplete.push({id: "color-contrast", nodes: [node]});
  const decision = {selector: "#text", decided: true, ratio: 4.5, required: 4.5};
  for (const decisions of [[], [{...decision, decided: false}], [{...decision, ratio: 4.49}], [{...decision, ratio: NaN}]]) {
    assert.throws(() => judgeAxe(incompleteColor, decisions), OracleFailure);
  }
  assert.doesNotThrow(() => judgeAxe(incompleteColor, [decision]));
  assert.doesNotThrow(() => judgeAxe(incompleteColor, [{...decision, ratio: 3, required: 3}]));
  for (const target of [null, [], ["#one", "#two"], [null]]) refuses(axeTargetSelector, {target}, "main-frame selector");
  assert.equal(axeTargetSelector(node), "#text");
});

test("control contrast decisions isolate every placeholder and checkbox operand", () => {
  const placeholder = {decided: true, ratio: 4.5};
  const checkbox = {decided: true, outlineStyle: "solid", outlineWidth: 2, token: 2, ratio: 3};
  const valid = {placeholders: [placeholder], checkboxes: [checkbox]};
  assert.doesNotThrow(() => judgeControlContrast(valid));
  for (const change of [{decided: false}, {ratio: 4.49}, {ratio: NaN}]) {
    refuses(judgeControlContrast, {...valid, placeholders: [placeholder, {...placeholder, ...change}]}, "placeholder");
  }
  for (const change of [{decided: false}, {outlineStyle: "none"}, {outlineWidth: 1.99}, {ratio: 2.99}, {ratio: NaN}]) {
    refuses(judgeControlContrast, {...valid, checkboxes: [checkbox, {...checkbox, ...change}]}, "checkbox");
  }
  assert.doesNotThrow(() => judgeControlContrast(valid));
});

test("reflow decision basis never masks one region operand behind another", () => {
  const region = {role: "region", name: "Data", tabIndex: 0, overflowX: "auto", holdsGraphOrTable: true};
  const valid = {documentOverflow: 1, overflowing: [region]};
  assert.doesNotThrow(() => judgeReflow(valid));
  assert.doesNotThrow(() => judgeReflow({...valid, overflowing: [{...region, overflowX: "scroll"}]}));
  refuses(judgeReflow, {...valid, documentOverflow: 2}, "document width");
  for (const change of [{role: null}, {name: ""}, {tabIndex: -1}, {overflowX: "hidden"}, {holdsGraphOrTable: false}]) {
    refuses(judgeReflow, {...valid, overflowing: [region, {...region, ...change}]}, JSON.stringify(change));
  }
  assert.doesNotThrow(() => judgeReflow(valid));
});

test("content decisions isolate record cardinality, text presence and findings", () => {
  const valid = {records: 1, texts: 1, findings: []};
  const judge = value => judgeContent(value, 1);
  assert.doesNotThrow(() => judge(valid));
  for (const change of [{records: 0}, {records: 2}, {texts: 0}, {findings: [{problem: "hidden"}]}]) {
    refuses(judge, {...valid, ...change}, JSON.stringify(change));
  }
  assert.doesNotThrow(() => judge(valid));
});

test("keyboard decisions isolate focus classification, both orders and every indicator operand", () => {
  const focus = stop => ({stop, outside: false, container: false, visible: true, outlineStyle: "solid", outlineWidth: 2, token: 2, contrast: 3});
  const valid = {expected: {count: 2, modal: false, focused: null}, forward: [focus("0"), focus("1")], backward: [focus("0")], visited: [focus("0"), focus("1")]};
  assert.doesNotThrow(() => judgeKeyboard(valid));
  refuses(judgeKeyboard, {expected: {count: 0, modal: false, focused: null}, forward: [], backward: [], visited: []}, "empty inventory");
  const modal = {...valid, expected: {count: 2, modal: true, focused: "0"}, forward: [focus("1")]};
  assert.doesNotThrow(() => judgeKeyboard(modal));
  refuses(judgeKeyboard, {...modal, expected: {...modal.expected, focused: null}}, "modal without focused element");
  for (const change of [{stop: null}, {outside: true}, {visible: false}, {outlineStyle: "none"}, {outlineStyle: "hidden"}, {outlineWidth: 1.99}, {contrast: 2.99}, {contrast: NaN}]) {
    refuses(judgeKeyboard, {...valid, visited: [focus("0"), {...focus("1"), ...change}]}, JSON.stringify(change));
  }
  refuses(judgeKeyboard, {...valid, forward: [focus("1"), focus("0")]}, "forward order");
  refuses(judgeKeyboard, {...valid, backward: [focus("1")]}, "reverse order");
  assert.doesNotThrow(() => judgeKeyboard({...valid, visited: [...valid.visited, {...focus(null), container: true}]}));
  assert.doesNotThrow(() => judgeKeyboard(valid));
});

test("document security decisions bind each required header independently", () => {
  const csp = "default-src 'none'";
  const expected = {
    "content-security-policy": csp,
    "cross-origin-opener-policy": "same-origin",
    "cross-origin-resource-policy": "same-origin",
    "permissions-policy": "accelerometer=(), camera=(), geolocation=(), gyroscope=(), microphone=(), payment=(), usb=()",
    "referrer-policy": "no-referrer",
    "x-content-type-options": "nosniff",
  };
  assert.deepEqual(documentSecurityHeaders(csp), expected);
  for (const key of Object.keys(expected)) {
    assert.throws(() => judgeDocumentHeaders({...expected, [key]: "wrong"}, csp), OracleFailure, key);
    const missing = {...expected};
    delete missing[key];
    assert.throws(() => judgeDocumentHeaders(missing, csp), OracleFailure, key);
  }
  assert.doesNotThrow(() => judgeDocumentHeaders({...expected, unrelated: "permitted"}, csp));
});

test("security event decisions implement the complete three-operand truth table", () => {
  for (let bits = 0; bits < 8; bits++) {
    const observation = {consoleErrors: bits & 1 ? ["console"] : [], pageErrors: bits & 2 ? ["page"] : [], violations: bits & 4 ? [{blockedURI: "blocked"}] : []};
    if (bits === 0) assert.doesNotThrow(() => judgeSecurityEvents(observation));
    else refuses(judgeSecurityEvents, observation, `security bits ${bits}`);
  }
});

test("security monitor wires and snapshots independent event channels", async () => {
  const handlers = new Map();
  let violation;
  let initialize;
  const monitor = await SecurityMonitor.attach({
    on: (event, handler) => handlers.set(event, handler),
    exposeBinding: async (name, handler) => { assert.equal(name, "proofkitMatrixReportViolation"); violation = handler; },
    addInitScript: async handler => { initialize = handler; },
  });
  assert.equal(typeof initialize, "function");
  assert.equal(typeof handlers.get("pageerror"), "function");
  handlers.get("console")({type: () => "log", text: () => "not an error"});
  assert.deepEqual(monitor.observation(), {consoleErrors: [], pageErrors: [], violations: []});
  handlers.get("pageerror")(new Error("uncaught"));
  assert.deepEqual(monitor.observation(), {consoleErrors: [], pageErrors: ["uncaught"], violations: []});
  handlers.get("console")({type: () => "error", text: () => "console"});
  violation({}, {blockedURI: "blocked"});
  const snapshot = monitor.observation();
  assert.deepEqual(snapshot, {consoleErrors: ["console"], pageErrors: ["uncaught"], violations: [{blockedURI: "blocked"}]});
  snapshot.consoleErrors.length = 0;
  snapshot.pageErrors.length = 0;
  snapshot.violations.length = 0;
  assert.equal(monitor.observation().consoleErrors.length, 1);
  assert.equal(monitor.observation().pageErrors.length, 1);
  assert.equal(monitor.observation().violations.length, 1);
});
