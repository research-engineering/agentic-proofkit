#!/usr/bin/env node
import { execFileSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";

import {runDiagnosticEntrypoint} from "./diagnostic.mjs";
import {decodeUTF8Strict} from "./stable-json.mjs";

const textExtensions = new Set([
  ".css",
  ".go",
  ".js",
  ".json",
  ".md",
  ".mjs",
  ".py",
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

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function tokenPattern(token) {
  const leftBoundary = /^[a-z0-9]/.test(token) ? "(^|[^a-z0-9])" : "";
  const rightBoundary = /[a-z0-9]$/.test(token) ? "([^a-z0-9]|$)" : "";
  return new RegExp(`${leftBoundary}${escapeRegExp(token)}${rightBoundary}`, "i");
}

const bannedTokenPatterns = bannedTokens.map(tokenPattern);

function containsOrganizationSpecificToken(text) {
  return bannedTokenPatterns.some((pattern) => pattern.test(text));
}

function trackedFiles() {
  return decodeUTF8Strict(execFileSync("git", ["ls-files", "-z"]), "Git file inventory")
    .split("\0")
    .filter(Boolean);
}

function trackedIndexEntries() {
  return decodeUTF8Strict(execFileSync("git", ["ls-files", "-s", "-z"]), "Git index inventory")
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

await runDiagnosticEntrypoint(() => {
  const organizationSpecific = new Set();

  for (const entry of trackedIndexEntries()) {
    if (!isTextFile(entry.file)) {
      continue;
    }

    const lowerText = decodeUTF8Strict(
      execFileSync("git", ["cat-file", "-p", entry.object]),
      "tracked text object",
    ).toLowerCase();
    if (containsOrganizationSpecificToken(lowerText)) {
      organizationSpecific.add(entry.file);
    }
  }

  for (const file of trackedFiles()) {
    if (!isTextFile(file) || !existsSync(file)) {
      continue;
    }

    const lowerText = decodeUTF8Strict(readFileSync(file), "worktree text file").toLowerCase();
    if (containsOrganizationSpecificToken(lowerText)) {
      organizationSpecific.add(file);
    }
  }

  if (organizationSpecific.size > 0) {
    throw new Error(
      `organization-specific text leaked into Proofkit: ${[...organizationSpecific].sort().join(", ")}`,
    );
  }
});
