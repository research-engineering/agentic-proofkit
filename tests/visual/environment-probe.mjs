import {execFileSync} from "node:child_process";
import {createHash} from "node:crypto";
import {existsSync, readFileSync} from "node:fs";
import {chromium, firefox, webkit} from "@playwright/test";

import {stableJSONStringify} from "../../scripts/stable-json.mjs";

// Observes the reference-environment tuple without launching any browser.
// Every field the host cannot observe is null, which differs from the
// recorded reference environment and makes the comparison unverified.
// fontConfig is the SHA-256 of the fontconfig file named by FONTCONFIG_FILE,
// which the caller sets to its run directory's copy of tests/visual/fonts.conf
// before observing, so that fc-match and every browser resolve fonts through
// the hashed bytes. fontMatches records the fc-match result for each named
// family queried by its whole name: fc-match reads the text after an
// unescaped hyphen as a point size, so every hyphen is escaped.

export const comparedEnvironmentFields = Object.freeze(["architecture", "dockerImage", "emulation", "engines", "fontConfig", "fontMatches", "os", "packages"]);
const fontFamilies = ["monospace", "sans-serif", "serif", "system-ui", "ui-monospace"];
const commandOptions = {encoding: "utf8", stdio: ["ignore", "pipe", "ignore"], timeout: 10_000, maxBuffer: 1 << 20};

export function observeEnvironment({platform = process.platform, run = runCommand, read = readText, environment = process.env} = {}) {
  const architecture = run("uname", ["-m"]);
  const cpuinfo = platform === "linux" ? read("/proc/cpuinfo") : null;
  return {
    architecture,
    cpu: observeCPU(platform, cpuinfo, run),
    dockerImage: observeDockerImage(read),
    emulation: observeEmulation(platform, architecture, cpuinfo, run, read),
    engines: observeEngines(),
    fontConfig: observeFontConfig(environment.FONTCONFIG_FILE),
    fontMatches: observeFontMatches(run),
    os: platform === "linux" ? observeOS(read) : null,
    packages: platform === "linux" ? observePackages(run) : null,
  };
}

// environmentDivergence returns the compared fields whose observed value
// differs from the reference value, in the fixed field order.
export function environmentDivergence(reference, observed) {
  return comparedEnvironmentFields.filter((field) => stableJSONStringify(reference[field] ?? null) !== stableJSONStringify(observed[field] ?? null));
}

function runCommand(command, args) {
  try {
    const output = execFileSync(command, args, commandOptions).trim();
    return output === "" ? null : output;
  } catch {
    return null;
  }
}

function readText(path) {
  try {
    return readFileSync(path, "utf8");
  } catch {
    return null;
  }
}

function observeOS(read) {
  const text = read("/etc/os-release");
  if (text === null) return null;
  const fields = Object.fromEntries(text.split("\n").map((line) => line.match(/^([A-Z_]+)=(.*)$/)).filter(Boolean)
    .map(([, key, value]) => [key, value.replace(/^"(.*)"$/, "$1")]));
  if (!fields.ID || !fields.VERSION_ID) return null;
  return {id: fields.ID, versionId: fields.VERSION_ID};
}

function observeDockerImage(read) {
  const text = read("/ms-playwright/.docker-info");
  if (text === null) return null;
  try {
    const value = JSON.parse(text);
    if (!value || typeof value !== "object" || Array.isArray(value)) return null;
    const result = {};
    for (const key of Object.keys(value).sort()) {
      if (typeof value[key] !== "string" || value[key] === "") return null;
      result[key] = value[key];
    }
    return Object.keys(result).length === 0 ? null : result;
  } catch {
    return null;
  }
}

function observePackages(run) {
  const output = run("dpkg-query", ["-W", "-f", "${db:Status-Abbrev}\t${Package}\t${Version}\n", "fontconfig", "libfreetype6", "libharfbuzz0b", "fonts-*"]);
  if (output === null) return null;
  const packages = {};
  for (const line of output.split("\n")) {
    const [status, name, version] = line.split("\t");
    if (status?.trim() === "ii" && name && version) packages[name] = version;
  }
  for (const required of ["fontconfig", "libfreetype6", "libharfbuzz0b"]) {
    if (!(required in packages)) return null;
  }
  return Object.fromEntries(Object.keys(packages).sort().map((name) => [name, packages[name]]));
}

function observeFontMatches(run) {
  const matches = {};
  for (const family of fontFamilies) {
    const match = run("fc-match", [family.replaceAll("-", "\\-")]);
    if (match === null) return null;
    matches[family] = match;
  }
  return matches;
}

function observeFontConfig(path) {
  if (typeof path !== "string" || path === "") return null;
  try {
    return `sha256:${createHash("sha256").update(readFileSync(path)).digest("hex")}`;
  } catch {
    return null;
  }
}

// Installed engine revisions: the revision directory of each executable that
// Playwright reports for the engine. Chromium's headless shell is installed
// at the same revision; a missing executable is unobserved.
function observeEngines() {
  const engines = {};
  for (const [name, type] of [["chromium", chromium], ["firefox", firefox], ["webkit", webkit]]) {
    let revision = null;
    try {
      const executable = type.executablePath();
      const match = executable.match(/(?:^|[\\/])(?:chromium|firefox|webkit)-(\d+)[\\/]/);
      if (match && existsSync(executable)) revision = match[1];
    } catch {
      revision = null;
    }
    engines[name] = revision;
  }
  return engines;
}

function observeEmulation(platform, architecture, cpuinfo, run, read) {
  if (platform === "darwin") {
    return run("sysctl", ["-in", "sysctl.proc_translated"]) === "1" ? "rosetta" : "none";
  }
  if (platform !== "linux" || cpuinfo === null || architecture === null) return null;
  const maps = read("/proc/self/maps") ?? "";
  if (/\/rosetta\b|qemu-/.test(maps)) return "translator-mapped";
  const x86CPU = /^vendor_id\s*:/m.test(cpuinfo);
  const armCPU = /^CPU implementer\s*:/m.test(cpuinfo);
  if (/VirtualApple/.test(cpuinfo)) return "rosetta";
  if (architecture === "aarch64" && !armCPU) return "foreign-cpu";
  if (architecture === "x86_64" && !x86CPU) return "foreign-cpu";
  return "none";
}

// The CPU is recorded in every run but not compared. A value the host cannot
// observe is null: x86 instruction-set and hypervisor flags do not exist on
// arm64, where the cpuinfo Features line is recorded instead.
function observeCPU(platform, cpuinfo, run) {
  if (platform === "darwin") {
    const hypervisor = run("sysctl", ["-in", "kern.hv_vmm_present"]);
    return {avx2: null, avx512f: null, features: null, hypervisor: hypervisor === null ? null : hypervisor === "1", model: run("sysctl", ["-n", "machdep.cpu.brand_string"]), vendor: "apple"};
  }
  if (cpuinfo === null) return {avx2: null, avx512f: null, features: null, hypervisor: null, model: null, vendor: null};
  const first = (pattern) => cpuinfo.match(pattern)?.[1]?.trim() || null;
  const implementer = first(/^CPU implementer\s*:(.*)$/m);
  const part = first(/^CPU part\s*:(.*)$/m);
  const vendor = first(/^vendor_id\s*:(.*)$/m);
  if (vendor === null && implementer !== null) {
    return {avx2: null, avx512f: null, features: first(/^Features\s*:(.*)$/m), hypervisor: null, model: part === null ? null : `part ${part}`, vendor: `implementer ${implementer}`};
  }
  const flagsLine = first(/^flags\s*:(.*)$/m);
  const flags = flagsLine === null ? null : new Set(flagsLine.split(/\s+/).filter(Boolean));
  return {
    avx2: flags === null ? null : flags.has("avx2"),
    avx512f: flags === null ? null : flags.has("avx512f"),
    features: flagsLine,
    hypervisor: flags === null ? null : flags.has("hypervisor"),
    model: first(/^model name\s*:(.*)$/m),
    vendor,
  };
}
