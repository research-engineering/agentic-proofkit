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
      return `{${Object.keys(value).map(assertScalarString).sort(compareScalarStrings).map((key) =>
        `${quote(key)}:${stableJSONStringify(value[key])}`).join(",")}}`;
    default:
      throw new Error(`unsupported stable JSON value type: ${typeof value}`);
  }
}

export function decodeUTF8Strict(bytes, fixedLabel = "input") {
  try {
    return new TextDecoder("utf-8", {fatal: true}).decode(bytes);
  } catch {
    throw new Error(`${fixedLabel} is not valid UTF-8`);
  }
}

export function createUTF8StrictStreamDecoder(fixedLabel = "input") {
  const decoder = new TextDecoder("utf-8", {fatal: true});
  let finished = false;
  const decode = (bytes, options) => {
    try {
      return decoder.decode(bytes, options);
    } catch {
      throw new Error(`${fixedLabel} is not valid UTF-8`);
    }
  };
  return {
    finish() {
      if (finished) return "";
      finished = true;
      return decode();
    },
    write(bytes) {
      if (finished) throw new Error(`${fixedLabel} UTF-8 decoder is already finished`);
      return decode(bytes, {stream: true});
    },
  };
}

export function redactDiagnosticValue(value) {
  if (!isScalarString(value) || containsUnsafeScalar(value) || containsSecretLikeValue(value)) {
    return "<redacted-diagnostic-value>";
  }
  const scalars = [...value];
  if (scalars.length <= 512) return value;
  return `${scalars.slice(0, 512).join("")}...<truncated-diagnostic>`;
}

const unsafeScalarRanges = [
  [0x000000, 0x00001f, 1],
  [0x00007f, 0x00009f, 1],
  [0x0000ad, 0x000600, 1363],
  [0x000601, 0x000605, 1],
  [0x00061c, 0x0006dd, 193],
  [0x00070f, 0x000890, 385],
  [0x000891, 0x0008e2, 81],
  [0x00180e, 0x00200b, 2045],
  [0x00200c, 0x00200f, 1],
  [0x002028, 0x002028, 1],
  [0x002029, 0x002029, 1],
  [0x00202a, 0x00202e, 1],
  [0x002060, 0x002064, 1],
  [0x002066, 0x00206f, 1],
  [0x00feff, 0x00fff9, 250],
  [0x00fffa, 0x00fffb, 1],
  [0x0110bd, 0x0110cd, 16],
  [0x013430, 0x01343f, 1],
  [0x01bca0, 0x01bca3, 1],
  [0x01d173, 0x01d17a, 1],
  [0x0e0001, 0x0e0020, 31],
  [0x0e0021, 0x0e007f, 1],
];

function quote(value) {
  assertScalarString(value);
  let output = '"';
  for (const character of value) {
    const scalar = character.codePointAt(0);
    switch (scalar) {
      case 0x22: output += '\\"'; break;
      case 0x5c: output += "\\\\"; break;
      case 0x08: output += "\\b"; break;
      case 0x09: output += "\\t"; break;
      case 0x0a: output += "\\n"; break;
      case 0x0c: output += "\\f"; break;
      case 0x0d: output += "\\r"; break;
      default:
        output += isUnsafeScalar(scalar) ? unicodeEscape(scalar) : character;
    }
  }
  return `${output}"`;
}

function assertScalarString(value) {
	if (!isScalarString(value)) {
		throw new Error("stable JSON strings must contain only Unicode scalar values");
	}
	return value;
}

function isScalarString(value) {
  for (let index = 0; index < value.length; index += 1) {
    const unit = value.charCodeAt(index);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const low = value.charCodeAt(index + 1);
      if (!(low >= 0xdc00 && low <= 0xdfff)) {
		return false;
      }
      index += 1;
    } else if (unit >= 0xdc00 && unit <= 0xdfff) {
		return false;
    }
  }
	return true;
}

function compareScalarStrings(left, right) {
  let leftIndex = 0;
  let rightIndex = 0;
  while (leftIndex < left.length && rightIndex < right.length) {
    const leftScalar = left.codePointAt(leftIndex);
    const rightScalar = right.codePointAt(rightIndex);
    if (leftScalar !== rightScalar) return leftScalar - rightScalar;
    leftIndex += leftScalar > 0xffff ? 2 : 1;
    rightIndex += rightScalar > 0xffff ? 2 : 1;
  }
  if (leftIndex === left.length && rightIndex === right.length) return 0;
  return leftIndex === left.length ? -1 : 1;
}

export function isUnsafeScalar(value) {
  let low = 0;
  let high = unsafeScalarRanges.length;
  while (low < high) {
    const middle = Math.floor((low + high) / 2);
    if (unsafeScalarRanges[middle][1] < value) low = middle + 1;
    else high = middle;
  }
  if (low === unsafeScalarRanges.length) return false;
  const [start, end, step] = unsafeScalarRanges[low];
  return value >= start && value <= end && (value - start) % step === 0;
}

function containsUnsafeScalar(value) {
	for (const character of value) {
		if (isUnsafeScalar(character.codePointAt(0))) return true;
	}
	return false;
}

const secretWhitespace = String.raw`(?:\s|\\+[ntrfv]|\\+u(?:000[9a-d]|0020|0085|00a0|202[89]))`;
const authorizationPattern = new RegExp(String.raw`authorization(?:\\*["'])?${secretWhitespace}*:${secretWhitespace}*[^\r\n]+`, "iu");
const bearerPattern = new RegExp(String.raw`bearer${secretWhitespace}+[A-Za-z0-9._~+/=-]{8,}`, "iu");
const namedSecretPattern = new RegExp(String.raw`(?:access[-_]?token|api[-_]?key|pass(?:word|wd)|secret|token)(?:\\*["'])?${secretWhitespace}*[=:]${secretWhitespace}*\S+`, "iu");
const escapedSecretControls = {n: "\n", t: "\t", r: "\r", f: "\f", v: "\v", b: "\b"};
const maxSecretDecodePasses = 16;

function decodeEscapedSecretText(value) {
  const parts = [];
  for (let index = 0; index < value.length;) {
    const start = value.indexOf("\\", index);
    if (start < 0) {
      parts.push(value.slice(index));
      break;
    }
    if (start > index) parts.push(value.slice(index, start));
    let cursor = start;
    while (cursor < value.length && value[cursor] === "\\") cursor++;
    if (cursor === value.length) {
      parts.push(value.slice(start));
      break;
    }
    if (hasSecretUnicodeUnit(value, cursor)) {
      const first = Number.parseInt(value.slice(cursor + 1, cursor + 5), 16);
      if (first >= 0xd800 && first <= 0xdbff) {
        let second = cursor + 5;
        const secondStart = second;
        while (second < value.length && value[second] === "\\") second++;
        if (second > secondStart && hasSecretUnicodeUnit(value, second)) {
          const low = Number.parseInt(value.slice(second + 1, second + 5), 16);
          if (low >= 0xdc00 && low <= 0xdfff) {
            parts.push(String.fromCodePoint(0x10000 + ((first - 0xd800) << 10) + low - 0xdc00));
            index = second + 5;
            continue;
          }
        }
      }
      parts.push(decodeSecretUnicodeScalar(first, value.slice(start, cursor + 5)));
      index = cursor + 5;
      continue;
    }
    const suffix = value[cursor];
    if (Object.hasOwn(escapedSecretControls, suffix)) parts.push(escapedSecretControls[suffix]);
    else if (suffix === "/" || suffix === '"') parts.push(suffix);
    else {
      parts.push(value.slice(start, cursor));
      index = cursor;
      continue;
    }
    index = cursor + 1;
  }
  return parts.join("");
}

function hasSecretUnicodeUnit(value, index) {
  if (value[index] !== "u" || index + 5 > value.length) return false;
  for (let offset = 1; offset <= 4; offset++) {
    const code = value.charCodeAt(index + offset);
    if (!((code >= 48 && code <= 57) || (code >= 65 && code <= 70) || (code >= 97 && code <= 102))) return false;
  }
  return true;
}

function decodeSecretUnicodeScalar(value, original) {
  return value >= 0xd800 && value <= 0xdfff ? original : String.fromCodePoint(value);
}

function containsSecretLikeValue(value) {
	const patterns = [
		authorizationPattern,
		bearerPattern,
		namedSecretPattern,
		/github_pat_[A-Za-z0-9_]+/iu,
		/gh[pousr]_[A-Za-z0-9_]+/iu,
		/sk-(?:proj-)?[A-Za-z0-9_-]{10,}/iu,
		/xox[abprs]-[A-Za-z0-9-]+/iu,
		/glpat-[A-Za-z0-9_-]+/iu,
		/[A-Za-z][A-Za-z0-9+.-]*:\/\/[^/\s:@]+:[^/\s@]+@/iu,
		/-----BEGIN [A-Z ]*PRIVATE KEY-----/iu,
		/eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/u,
	];
	let candidate = value;
	for (let depth = 0; depth <= maxSecretDecodePasses; depth++) {
		if (patterns.some((pattern) => pattern.test(candidate))) return true;
		const withoutUnsafe = [...candidate].filter((character) => !isUnsafeScalar(character.codePointAt(0))).join("");
		if (withoutUnsafe !== candidate && patterns.some((pattern) => pattern.test(withoutUnsafe))) return true;
		const decoded = decodeEscapedSecretText(candidate);
		if (decoded === candidate) return false;
		if (depth === maxSecretDecodePasses) return true;
		candidate = decoded;
	}
	return true;
}

function unicodeEscape(value) {
  if (value <= 0xffff) return `\\u${value.toString(16).padStart(4, "0")}`;
  const adjusted = value - 0x10000;
  const high = 0xd800 + (adjusted >> 10);
  const low = 0xdc00 + (adjusted & 0x3ff);
  return `\\u${high.toString(16)}\\u${low.toString(16)}`;
}
