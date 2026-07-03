#!/usr/bin/env node
import { execFileSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";

const textExtensions = new Set([
  ".go",
  ".js",
  ".json",
  ".md",
  ".mjs",
  ".ts",
  ".yml",
  ".yaml",
]);

const bannedTokens = [
  ["@", "a", "fc"].join(""),
  ["a", "fc"].join(""),
  ["agentic", "platform"].join("-"),
  ["auto", "fleet"].join(""),
];

function trackedFiles() {
  return execFileSync("git", ["ls-files", "-z"], { encoding: "utf8" })
    .split("\0")
    .filter(Boolean);
}

function trackedIndexEntries() {
  return execFileSync("git", ["ls-files", "-s", "-z"], { encoding: "utf8" })
    .split("\0")
    .filter(Boolean)
    .map((entry) => {
      const tabIndex = entry.indexOf("\t");
      const metadata = entry.slice(0, tabIndex).split(" ");
      return { file: entry.slice(tabIndex + 1), object: metadata[1], stage: metadata[2] };
    })
    .filter((entry) => entry.stage === "0");
}

function isTextFile(file) {
  const extensionStart = file.lastIndexOf(".");
  const extension = extensionStart >= 0 ? file.slice(extensionStart) : "";
  return textExtensions.has(extension);
}

const organizationSpecific = new Set();

for (const entry of trackedIndexEntries()) {
  if (!isTextFile(entry.file)) {
    continue;
  }

  const lowerText = execFileSync("git", ["cat-file", "-p", entry.object], {
    encoding: "utf8",
  }).toLowerCase();
  if (bannedTokens.some((token) => lowerText.includes(token))) {
    organizationSpecific.add(entry.file);
  }
}

for (const file of trackedFiles()) {
  if (!isTextFile(file) || !existsSync(file)) {
    continue;
  }

  const lowerText = readFileSync(file, "utf8").toLowerCase();
  if (bannedTokens.some((token) => lowerText.includes(token))) {
    organizationSpecific.add(file);
  }
}

if (organizationSpecific.size > 0) {
  throw new Error(
    `organization-specific text leaked into Proofkit: ${[...organizationSpecific].sort().join(", ")}`,
  );
}
