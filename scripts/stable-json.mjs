export function stableJSONStringify(value) {
  switch (typeof value) {
    case "string":
      return quote(value);
    case "boolean":
      return value ? "true" : "false";
    case "number":
      if (!Number.isFinite(value)) throw new Error("stable JSON numbers must be finite");
      return JSON.stringify(value);
    case "object":
      if (value === null) return "null";
      if (Array.isArray(value)) return `[${value.map(stableJSONStringify).join(",")}]`;
      return `{${Object.keys(value).sort().map((key) =>
        `${quote(key)}:${stableJSONStringify(value[key])}`).join(",")}}`;
    default:
      throw new Error(`unsupported stable JSON value type: ${typeof value}`);
  }
}

function quote(value) {
  return JSON.stringify(value)
    .replaceAll("\u2028", "\\u2028")
    .replaceAll("\u2029", "\\u2029");
}
