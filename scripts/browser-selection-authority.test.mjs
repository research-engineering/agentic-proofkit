import assert from "node:assert/strict";
import test from "node:test";

import {emptySelectionState, transitionSelection} from "../internal/command/requirementbrowser/assets/selection-authority.js";

const target = {
  anchorId: "requirement:REQ-PROOFKIT-SPEC-001:invariant",
  endCodePoint: 9,
  exactQuote: "Invariant",
  startCodePoint: 0,
};

test("collapsed text selection cannot retain hidden handoff authority", () => {
  const selected = transitionSelection(emptySelectionState(), {kind: "text", targets: [target]});
  assertEmptySelection(transitionSelection(selected, {kind: "collapse"}));
});

test("collapsed native selection does not revoke explicit button authority", () => {
  const selected = transitionSelection(emptySelectionState(), {kind: "button", targets: [target]});
  assert.deepEqual(transitionSelection(selected, {kind: "collapse"}), selected);
});

test("committed text remains visible authority until explicitly cleared", () => {
  const selected = transitionSelection(emptySelectionState(), {kind: "text", targets: [target]});
  const committed = transitionSelection(selected, {kind: "commit"});
  assert.equal(committed.mode, "committed_text");
  assert.deepEqual(transitionSelection(committed, {kind: "collapse"}), committed);
  assertEmptySelection(transitionSelection(committed, {kind: "clear"}));
});

test("empty text selection and explicit clear produce the empty state", () => {
  const selected = transitionSelection(emptySelectionState(), {kind: "text", targets: [target]});
  assertEmptySelection(transitionSelection(selected, {kind: "text", targets: []}));
  assertEmptySelection(transitionSelection(selected, {kind: "clear"}));
});

test("initial selection state has no handoff authority", () => {
  assertEmptySelection(emptySelectionState());
});

test("button authority requires exactly one target", () => {
  assert.throws(() => transitionSelection(emptySelectionState(), {kind: "button", targets: []}), /exactly one target/);
  assert.throws(() => transitionSelection(emptySelectionState(), {kind: "button", targets: [target, target]}), /exactly one target/);
});

test("selection state does not retain caller-owned target objects", () => {
  const callerTarget = {...target};
  const selected = transitionSelection(emptySelectionState(), {kind: "text", targets: [callerTarget]});
  callerTarget.exactQuote = "mutated";
  assert.equal(selected.targets[0]?.exactQuote, "Invariant");
});

function assertEmptySelection(state) {
  assert.equal(state.mode, "none");
  assert.deepEqual(state.targets, []);
}
