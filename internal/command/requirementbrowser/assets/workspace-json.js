// @ts-check

/** @param {string} source @returns {any} */
export function parseWorkspaceJSON(source) {
  const rawJSON = Reflect.get(JSON, "rawJSON");
  const isRawJSON = Reflect.get(JSON, "isRawJSON");
  return JSON.parse(source, (_key, value, context = /** @type {{source?: string}} */ ({})) => {
    if (typeof value !== "number") return value;
    if (typeof context.source !== "string") throw new SyntaxError("Exact numeric observation is unavailable");
    if (Number.isSafeInteger(value) && String(value) === context.source) return value;
    if (typeof rawJSON !== "function" || typeof isRawJSON !== "function") throw new SyntaxError("Exact numeric observation is unavailable");
    return rawJSON(context.source);
  });
}

/** @param {any} value @returns {string} */
export function workspaceScalarText(value) {
  const isRawJSON = Reflect.get(JSON, "isRawJSON");
  return typeof isRawJSON === "function" && isRawJSON(value) ? value.rawJSON : String(value);
}
