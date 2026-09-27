// @ts-check

export class WorkspaceNumericCapabilityError extends Error {
  constructor() {
    super("Exact numeric observation is unavailable");
    this.name = "WorkspaceNumericCapabilityError";
  }
}

/** @param {string} source @returns {any} */
export function parseWorkspaceJSON(source) {
  const rawJSON = Reflect.get(JSON, "rawJSON");
  const isRawJSON = Reflect.get(JSON, "isRawJSON");
  return JSON.parse(source, (_key, value, context = /** @type {{source?: string}} */ ({})) => {
    if (typeof value !== "number") return value;
    if (typeof context.source !== "string") throw new WorkspaceNumericCapabilityError();
    if (Number.isSafeInteger(value) && String(value) === context.source) return value;
    if (typeof rawJSON !== "function" || typeof isRawJSON !== "function") throw new WorkspaceNumericCapabilityError();
    return rawJSON(context.source);
  });
}

/** @param {any} value @returns {string} */
export function workspaceScalarText(value) {
  const isRawJSON = Reflect.get(JSON, "isRawJSON");
  return typeof isRawJSON === "function" && isRawJSON(value) ? value.rawJSON : String(value);
}
