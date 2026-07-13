import {execFileSync} from "node:child_process";
import {createHash} from "node:crypto";
import {lstatSync, mkdirSync, readFileSync, writeFileSync} from "node:fs";
import {dirname, isAbsolute, join} from "node:path";

export const browserProofInputManifestPath = "scripts/browser-runtime-proof-inputs.v1.json";

export function loadBrowserProofInputResolution() {
  const encoded = process.env.PROOFKIT_BROWSER_INPUT_RESOLUTION ?? execFileSync(
    "go",
    ["run", "./internal/tools/browserproofverify", "--resolve-inputs"],
    {encoding: "utf8"},
  );
  const resolution = JSON.parse(encoded);
  if (!resolution || typeof resolution !== "object" || Array.isArray(resolution)) throw new Error("browser proof input resolution must be an object");
  const keys = Object.keys(resolution).sort();
  if (JSON.stringify(keys) !== JSON.stringify(["inputPaths", "schemaVersion", "serverTarget", "writerPath"])) throw new Error("browser proof input resolution keys are invalid");
  if (resolution.schemaVersion !== 1) throw new Error("browser proof input resolution schemaVersion is invalid");
  assertSortedUniqueStrings(resolution.inputPaths, "browser proof input resolution inputPaths");
  for (const path of resolution.inputPaths) {
    if (!isSafeRepoPath(path)) throw new Error("browser proof input resolution contains an unsafe path");
  }
  if (typeof resolution.serverTarget !== "string" || !resolution.serverTarget.startsWith("./") || !isSafeRepoPath(resolution.serverTarget.slice(2))) throw new Error("browser proof input resolution serverTarget is invalid");
  if (typeof resolution.writerPath !== "string" || !isSafeRepoPath(resolution.writerPath)) throw new Error("browser proof input resolution writerPath is invalid");
  return resolution;
}

export function snapshotInputAssets(inputPaths, root = ".") {
  return inputPaths.map((path) => inputAsset(path, root));
}

export function materializeInputSnapshot(inputPaths, sourceRoot, destinationRoot) {
  return inputPaths.map((path) => {
    if (!isSafeRepoPath(path)) throw new Error("browser proof snapshot input path must be repository-relative");
    const source = filePath(sourceRoot, path);
    const metadata = lstatSync(source);
    if (metadata.isSymbolicLink() || !metadata.isFile()) throw new Error("browser proof inputs must be regular non-symlink files");
    const content = readFileSync(source);
    const destination = filePath(destinationRoot, path);
    mkdirSync(dirname(destination), {recursive: true});
    writeFileSync(destination, content, {flag: "wx", mode: metadata.mode & 0o777});
    return {path, sha256: createHash("sha256").update(content).digest("hex")};
  });
}

export function assertInputSnapshotUnchanged(before, after) {
  if (JSON.stringify(after) !== JSON.stringify(before)) {
    throw new Error("browser proof inputs changed during execution");
  }
}

function inputAsset(path, root) {
  const source = filePath(root, path);
  const metadata = lstatSync(source);
  if (metadata.isSymbolicLink() || !metadata.isFile()) throw new Error("browser proof inputs must be regular non-symlink files");
  return {path, sha256: createHash("sha256").update(readFileSync(source)).digest("hex")};
}

function filePath(root, path) {
  return isAbsolute(path) ? path : join(root, path);
}

function assertSortedUniqueStrings(value, context) {
  if (!Array.isArray(value) || value.length === 0 || value.some((item) => typeof item !== "string" || item.length === 0)) throw new Error(`${context} must be a non-empty string array`);
  const sorted = [...new Set(value)].sort();
  if (JSON.stringify(value) !== JSON.stringify(sorted)) throw new Error(`${context} must be sorted and unique`);
}

export function isSafeRepoPath(path) {
  return path !== "." && !path.startsWith("/") && !path.includes("\\") && !path.includes(":") && path.split("/").every((part) => part !== "" && part !== "." && part !== "..");
}
