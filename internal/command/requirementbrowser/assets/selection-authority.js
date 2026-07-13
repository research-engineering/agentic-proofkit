// @ts-check

/** @typedef {{anchorId: string, exactQuote: string, startCodePoint: number, endCodePoint: number}} SelectionTarget */
/** @typedef {{mode: "none" | "button" | "text" | "committed_text", targets: SelectionTarget[]}} SelectionState */
/** @typedef {{kind: "button" | "text", targets: SelectionTarget[]} | {kind: "collapse" | "commit" | "clear"}} SelectionEvent */

/** @returns {SelectionState} */
export function emptySelectionState() {
  return {mode: "none", targets: []};
}

/** @param {SelectionState} state @param {SelectionEvent} event @returns {SelectionState} */
export function transitionSelection(state, event) {
  switch (event.kind) {
    case "button":
      if (event.targets.length !== 1) throw new Error("button selection requires exactly one target");
      return selectionState("button", event.targets);
    case "text":
      return event.targets.length === 0 ? emptySelectionState() : selectionState("text", event.targets);
    case "commit":
      return state.mode === "text" ? selectionState("committed_text", state.targets) : state;
    case "collapse":
      return state.mode === "text" ? emptySelectionState() : state;
    case "clear":
      return emptySelectionState();
  }
}

/** @param {"button" | "text" | "committed_text"} mode @param {SelectionTarget[]} targets @returns {SelectionState} */
function selectionState(mode, targets) {
  return {mode, targets: targets.map((target) => ({...target}))};
}
